"""The Guard's gRPC server (architecture §4.4).

The Guard detects; it never enforces. It returns findings and threat scores,
holds no state, and never logs the text it inspects. Offsets in its answers are
UTF-8 byte offsets, end exclusive.

It has two levels: recognizers from a file, and the
model packs installed in its model directory. It loads every pack, and reports
which level covers each data type.

    kygate-guard [--listen 127.0.0.1:4002] [--recognizers FILE] [--models DIR] [--workers 4]
    kygate-guard models list | pull NAME | add MANIFEST | remove NAME
"""

from __future__ import annotations

import argparse
import os
import hashlib
import logging
import signal
import sys
import threading
from concurrent import futures
from pathlib import Path

import grpc

from . import __version__, packs
from .detectors.base import MODEL, ByteOffsets, Detector
from .detectors.personal_data import ConfiguredRecognizers
from .pb import guard_pb2, guard_pb2_grpc

log = logging.getLogger("kygate.guard")

# The Guard's own limit on one segment, independent of the gateway's deadline.
MAX_SEGMENT_BYTES = 1 << 20


class GuardService(guard_pb2_grpc.GuardServicer):
    def __init__(self, detectors: list[Detector], languages: list[str] | None = None):
        self._detectors = detectors
        self._languages = sorted(set(languages or []) | {l for d in detectors for l in d.languages})
        self._ready = threading.Event()
        digest = hashlib.sha256()
        for d in detectors:
            digest.update(d.name.encode())
            digest.update(",".join(d.entity_types).encode())
        self.version = f"{__version__}+{digest.hexdigest()[:12]}"

    def mark_ready(self) -> None:
        self._ready.set()

    def coverage(self) -> list[guard_pb2.Coverage]:
        """Which level covers each data type and threat: "model" if any model finds it."""
        by_type: dict[str, list[Detector]] = {}
        for d in self._detectors:
            for t in (*d.entity_types, *d.threat_types):
                by_type.setdefault(t, []).append(d)
        return [guard_pb2.Coverage(entity_type=t, level=MODEL if any(d.level == MODEL for d in ds) else "list",
                                   detectors=[d.name for d in ds])
                for t, ds in sorted(by_type.items())]

    def Inspect(self, request, context):
        if not self._ready.is_set():
            context.abort(grpc.StatusCode.UNAVAILABLE, "the Guard is still loading its models")
        wanted = set(request.entity_types)
        threats = set(request.threat_types)
        resp = guard_pb2.InspectResponse()
        for seg in request.segments:
            if len(seg.text.encode("utf-8", "surrogatepass")) > MAX_SEGMENT_BYTES:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"segment {seg.id} is larger than {MAX_SEGMENT_BYTES} bytes")
            # Threats: untrusted segments only (user turns, tool results), any
            # kind of content, because an injection hides in documents and tool
            # output too. Several detectors of one threat: the highest score counts.
            if threats and seg.untrusted:
                best: dict[str, tuple[float, str]] = {}
                for d in self._detectors:
                    if not threats.intersection(d.threat_types):
                        continue
                    for t, score in d.detect_threats(seg.text, threats):
                        if t not in best or score > best[t][0]:
                            best[t] = (score, d.name)
                for t, (score, name) in sorted(best.items()):
                    resp.threats.append(guard_pb2.Threat(segment_id=seg.id, type=t, score=score, detector=name))
            if not wanted and threats:
                continue  # a request for threats alone (no data types asked for)
            if seg.kind not in (guard_pb2.CONTENT_KIND_PROSE, guard_pb2.CONTENT_KIND_UNSPECIFIED):
                continue  # code and structured content get the gateway's fast detectors only
            to_bytes = None
            for d in self._detectors:
                if wanted and not wanted.intersection(d.entity_types):
                    continue
                for det in d.detect(seg.text, wanted):
                    if to_bytes is None:
                        to_bytes = ByteOffsets(seg.text)
                    resp.findings.append(guard_pb2.Finding(
                        segment_id=seg.id, entity_type=det.entity_type,
                        start=to_bytes(det.start), end=to_bytes(det.end),
                        score=det.score, detector=det.detector, language=det.language))
        return resp

    def Embed(self, request, context):
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "embeddings are not implemented yet")

    def Rerank(self, request, context):
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "reranking is not implemented yet")

    def Info(self, request, context):
        types = sorted({t for d in self._detectors for t in d.entity_types})
        threat_types = sorted({t for d in self._detectors for t in d.threat_types})
        return guard_pb2.InfoResponse(
            version=self.version, ready=self._ready.is_set(), entity_types=types, threat_types=threat_types,
            languages=self._languages, coverage=self.coverage(),
            models=[guard_pb2.Model(task=getattr(getattr(d, "pack", None), "task", "personal_data"), name=d.name, version=getattr(getattr(d, "pack", None), "version", self.version),
                                    license=d.license) for d in self._detectors])


def tls_credentials(cert: str, key: str, client_ca: str | None) -> grpc.ServerCredentials:
    """TLS for the Guard's port. With client_ca, every caller must present a
    certificate that CA signed: mutual TLS, as a separate Guard pool needs
    (architecture section 4.4)."""
    with open(cert, "rb") as f:
        chain = f.read()
    with open(key, "rb") as f:
        private = f.read()
    ca = None
    if client_ca:
        with open(client_ca, "rb") as f:
            ca = f.read()
    return grpc.ssl_server_credentials([(private, chain)], root_certificates=ca, require_client_auth=ca is not None)


def build_server(listen: str, service: GuardService, workers: int = 4, creds: grpc.ServerCredentials | None = None) -> tuple[grpc.Server, int]:
    # Connections live a minute at most: gateways then reconnect and resolve
    # the Guard's address again, so new Guard instances receive calls as soon
    # as they are added (per-call balancing, architecture section 4.4).
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=workers),
                         options=[("grpc.max_connection_age_ms", 60_000), ("grpc.max_connection_age_grace_ms", 15_000)])
    guard_pb2_grpc.add_GuardServicer_to_server(service, server)
    port = server.add_secure_port(listen, creds) if creds is not None else server.add_insecure_port(listen)
    if port == 0:
        raise OSError(f"cannot listen on {listen}")
    return server, port


def load_packs(models_dir: Path) -> list[Detector]:
    """Every installed pack whose files match their SHA-256. A pack that
    cannot be used is reported and left out; the gateway sees the level that
    remains, and a policy that requires a model fails closed."""
    found, errors = packs.installed(models_dir)
    for e in errors:
        log.error("model pack not used: %s", e)
    detectors: list[Detector] = []
    for pack in found:
        if pack.runtime == "onnx-token-classifier":
            try:
                from .runtime.onnx_token import OnnxTokenClassifier
            except ImportError as e:
                log.error("model pack %s not used: the ML software is not installed (pip install \"kygate-guard[ml]\"): %s", pack.name, e)
                continue
            detectors.append(OnnxTokenClassifier(pack))
            log.info("model pack %s loaded: %s, %s, version %s", pack.name, pack.title, pack.license, pack.version[:12])
        elif pack.runtime == "onnx-sequence-classifier":
            try:
                from .runtime.onnx_seq import OnnxSequenceClassifier
            except ImportError as e:
                log.error("model pack %s not used: the ML software is not installed (pip install \"kygate-guard[ml]\"): %s", pack.name, e)
                continue
            try:
                detectors.append(OnnxSequenceClassifier(pack))
            except ValueError as e:
                log.error("model pack %s not used: %s", pack.name, e)
                continue
            log.info("model pack %s loaded: %s, %s, version %s", pack.name, pack.title, pack.license, pack.version[:12])
    return detectors


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["models"]:
        return packs.cli(argv[1:])
    p = argparse.ArgumentParser(prog="kygate-guard", description="KyGate Guard: detects personal data and threats for the KyGate gateway. "
                                "'kygate-guard models ...' manages model packs.")
    p.add_argument("--listen", default="127.0.0.1:4002", help="address to listen on (default 127.0.0.1:4002)")
    p.add_argument("--recognizers", help="a JSON file of pattern and dictionary recognizers")
    p.add_argument("--models", default=str(packs.default_dir()), help="model directory (default: KYGATE_GUARD_MODELS, or ~/.kygate/models)")
    p.add_argument("--no-models", action="store_true", help="do not load model packs, even if some are installed")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--tls-cert", default=os.environ.get("KYGATE_GUARD_TLS_CERT"), help="serve TLS with this certificate (PEM; also KYGATE_GUARD_TLS_CERT)")
    p.add_argument("--tls-key", default=os.environ.get("KYGATE_GUARD_TLS_KEY"), help="its private key (PEM; also KYGATE_GUARD_TLS_KEY)")
    p.add_argument("--tls-client-ca", default=os.environ.get("KYGATE_GUARD_TLS_CLIENT_CA"),
                   help="require callers to present a certificate this CA signed: mutual TLS (also KYGATE_GUARD_TLS_CLIENT_CA)")
    args = p.parse_args(argv)
    if bool(args.tls_cert) != bool(args.tls_key):
        p.error("--tls-cert and --tls-key go together")
    if args.tls_client_ca and not args.tls_cert:
        p.error("--tls-client-ca needs --tls-cert and --tls-key")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s guard: %(message)s", datefmt="%Y/%m/%d %H:%M:%S")

    detectors: list[Detector] = []
    if args.recognizers:
        detectors.append(ConfiguredRecognizers.from_file(args.recognizers))
    if not args.no_models:
        detectors += load_packs(Path(args.models))
    service = GuardService(detectors)
    creds = tls_credentials(args.tls_cert, args.tls_key, args.tls_client_ca) if args.tls_cert else None
    server, _ = build_server(args.listen, service, args.workers, creds)
    server.start()  # answers Info (not ready) while the models warm up
    for d in detectors:
        d.warm_up()
    service.mark_ready()
    levels = ", ".join(f"{c.entity_type} ({c.level})" for c in service.coverage()) or "nothing yet: no recognizers and no model pack"
    tls = "mutual TLS" if args.tls_client_ca else ("TLS" if args.tls_cert else "plain gRPC: keep it on a private network, or use --tls-cert")
    log.info("KyGate Guard %s listening on %s (%s); finds: %s", service.version, args.listen, tls, levels)

    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    while not stop.wait(0.5):
        pass
    log.info("stopping: open calls have 5 seconds to finish")
    server.stop(5).wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
