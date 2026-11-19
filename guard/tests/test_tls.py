"""The Guard's port over TLS and mutual TLS. Certificates are
made for the test with the openssl command; without it the test is skipped."""
import shutil
import subprocess

import grpc
import pytest

from kygate_guard.pb import guard_pb2, guard_pb2_grpc
from kygate_guard.server import GuardService, build_server, tls_credentials

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl is not installed")


def openssl(*args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture()
def pki(tmp_path):
    d = str(tmp_path)
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
            "-days", "1", "-subj", "/CN=test CA", cwd=d)
    for name, usage in (("server", "serverAuth"), ("client", "clientAuth")):
        openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.csr",
                "-subj", f"/CN={name}", cwd=d)
        (tmp_path / f"{name}.ext").write_text(f"subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage={usage}\n")
        openssl("x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", f"{name}.pem",
                "-days", "1", "-extfile", f"{name}.ext", cwd=d)
    return tmp_path


def serve(pki, mutual):
    creds = tls_credentials(str(pki / "server.pem"), str(pki / "server.key"), str(pki / "ca.pem") if mutual else None)
    service = GuardService([], languages=[])
    server, port = build_server("127.0.0.1:0", service, creds=creds)
    server.start()
    service.mark_ready()
    return server, port


def info(pki, port, with_client_cert):
    ca = (pki / "ca.pem").read_bytes()
    key = (pki / "client.key").read_bytes() if with_client_cert else None
    cert = (pki / "client.pem").read_bytes() if with_client_cert else None
    channel = grpc.secure_channel(f"localhost:{port}", grpc.ssl_channel_credentials(ca, key, cert))
    try:
        return guard_pb2_grpc.GuardStub(channel).Info(guard_pb2.InfoRequest(), timeout=5)
    finally:
        channel.close()


def test_tls(pki):
    server, port = serve(pki, mutual=False)
    try:
        assert info(pki, port, with_client_cert=False).ready
    finally:
        server.stop(0)


def test_mutual_tls_refuses_a_caller_without_a_certificate(pki):
    server, port = serve(pki, mutual=True)
    try:
        with pytest.raises(grpc.RpcError):
            info(pki, port, with_client_cert=False)
        assert info(pki, port, with_client_cert=True).ready
    finally:
        server.stop(0)
