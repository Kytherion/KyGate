"""Model packs: manifests, verification, install, coverage. Every value is synthetic.

The last tests use the real default pack when it is installed
(kygate-guard models pull personal-data), and are skipped otherwise.
"""

import hashlib
import json
from pathlib import Path

import grpc
import pytest

from kygate_guard import packs
from kygate_guard.detectors.base import MODEL, Detection, Detector
from kygate_guard.detectors.personal_data import ConfiguredRecognizers
from kygate_guard.pb import guard_pb2, guard_pb2_grpc
from kygate_guard.server import GuardService, build_server


def manifest(content, **over):
    m = {"format": 1, "name": "test-pack", "title": "Test pack", "task": "personal_data", "runtime": "onnx-token-classifier",
         "version": "abc123", "license": "MIT", "labels": "config.json", "label_map": {"PERSON_NAME": "PERSON"},
         "files": [{"path": p, "url": "", "size": len(b), "sha256": hashlib.sha256(b).hexdigest()} for p, b in content.items()]}
    m.update(over)
    return m


@pytest.mark.parametrize("change, message", [
    ({"format": 2}, "format"),
    ({"runtime": "pytorch"}, "runtime"),
    ({"name": "../evil"}, "name"),
    ({"files": [{"path": "../x", "sha256": "0" * 64}]}, "inside the pack"),
    ({"files": [{"path": "m.onnx", "sha256": "abc"}]}, "SHA-256"),
    ({"files": [{"path": "m.onnx", "sha256": "0" * 64, "url": "http://example.com/m.onnx"}]}, "https"),
])
def test_bad_manifests_are_refused(change, message):
    with pytest.raises(packs.PackError, match=message):
        packs.parse(manifest({"m.onnx": b"x"}, **change))


def test_install_verifies_and_writes_the_manifest_last(tmp_path):
    files = {"model.onnx": b"weights", "config.json": b"{}"}
    m = manifest(files)
    partial = tmp_path / ".test-pack.partial"
    partial.mkdir()
    for p, b in files.items():  # as if downloaded; url is empty so nothing is fetched
        (partial / p).write_bytes(b)
    out = []
    pack = packs.install(m, tmp_path, assume_yes=True, out=type("W", (), {"write": lambda s, x: out.append(x), "flush": lambda s: None})())
    assert pack.dir == tmp_path / "test-pack" and (pack.dir / "pack.json").is_file()
    assert [p.name for p in packs.installed(tmp_path)[0]] == ["test-pack"]


def test_install_asks_first(tmp_path):
    with pytest.raises(packs.PackError, match="nothing was downloaded"):
        packs.install(manifest({"m.onnx": b"x"}), tmp_path, ask=lambda _: "n", out=__import__("io").StringIO())
    assert not (tmp_path / "test-pack").exists()


def test_a_changed_file_is_never_used(tmp_path):
    d = tmp_path / "test-pack"
    d.mkdir()
    (d / "model.onnx").write_bytes(b"weights")
    (d / "pack.json").write_text(json.dumps(manifest({"model.onnx": b"weights"})))
    assert packs.load(d).name == "test-pack"
    (d / "model.onnx").write_bytes(b"tampered")
    packs_ok, errors = packs.installed(tmp_path)
    assert packs_ok == [] and "does not match its SHA-256" in errors[0]


def test_an_interrupted_install_is_not_loaded(tmp_path):
    (tmp_path / ".test-pack.partial").mkdir()
    (tmp_path / ".test-pack.partial" / "model.onnx").write_bytes(b"half")
    assert packs.installed(tmp_path) == ([], [])


def test_the_catalog_pack_is_pinned():
    p = packs.parse(packs.catalog()["personal-data"])
    assert all(len(f.sha256) == 64 and f.url.startswith("https://") and p.version in f.url for f in p.files)
    assert p.license == "Apache-2.0" and "en" in p.languages and "fr" in p.languages
    assert p.label_map["PERSON_NAME"] == "PERSON" and len(p.label_map) == 37


def test_one_default_pack_and_the_others_are_add_ons():
    known = packs.catalog()
    assert packs.default_pack(known) == "prompt-injection"
    assert [n for n, d in known.items() if d.get("default") is True] == ["prompt-injection"]
    with pytest.raises(packs.PackError, match="exactly one"):
        packs.default_pack({"a": {"default": True}, "b": {"default": True}})


def test_pull_without_a_name_installs_the_default(tmp_path, monkeypatch):
    got = []
    monkeypatch.setattr(packs, "install", lambda data, models_dir, yes: got.append(data["name"]))
    assert packs.cli(["--models", str(tmp_path), "pull", "--yes"]) == 0
    assert got == ["prompt-injection"]


def test_list_names_the_default_and_the_add_ons(tmp_path, capsys):
    assert packs.cli(["--models", str(tmp_path), "list"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert "prompt-injection" in lines[1] and "default" in lines[1] and "(kygate-guard models pull)" in lines[1]
    assert any("personal-data" in l and "add-on" in l and "models pull personal-data" in l for l in lines)


class FakeModel(Detector):
    name = "fake-model/1"
    level = MODEL
    entity_types = ("PERSON", "PHONE")

    def detect(self, text, entity_types):
        return []


def test_coverage_says_which_level_finds_each_type():
    rec = ConfiguredRecognizers.from_config({"recognizers": [{"type": "PERSON", "terms": ["Alice"]}, {"type": "EMPLOYEE_ID", "pattern": "EMP-[0-9]+"}]})
    cov = {c.entity_type: (c.level, list(c.detectors)) for c in GuardService([rec, FakeModel()]).coverage()}
    assert cov == {"EMPLOYEE_ID": ("list", ["recognizers/1"]), "PERSON": ("model", ["recognizers/1", "fake-model/1"]), "PHONE": ("model", ["fake-model/1"])}


# ---- the real default pack, when installed ----

REAL = packs.default_dir() / "personal-data"
needs_real = pytest.mark.skipif(not (REAL / "pack.json").is_file(), reason="the personal-data pack is not installed")


@pytest.fixture(scope="module")
def real_stub():
    from kygate_guard.server import load_packs
    service = GuardService(load_packs(packs.default_dir()))
    server, port = build_server("127.0.0.1:0", service)
    server.start()
    service.mark_ready()
    ch = grpc.insecure_channel(f"127.0.0.1:{port}")
    yield guard_pb2_grpc.GuardStub(ch)
    ch.close()
    server.stop(0)


@needs_real
def test_real_pack_reports_model_coverage(real_stub):
    cov = {c.entity_type: c.level for c in real_stub.Info(guard_pb2.InfoRequest()).coverage}
    assert cov["PERSON"] == "model" and cov["ADDRESS"] == "model" and cov["PHONE"] == "model"


@needs_real
def test_real_pack_byte_offsets(real_stub):
    text = "Écris à Hélène Dubois, 12 rue de la Paix, 75002 Paris."
    resp = real_stub.Inspect(guard_pb2.InspectRequest(segments=[guard_pb2.Segment(id="s", kind=guard_pb2.CONTENT_KIND_PROSE, text=text)],
                                                      entity_types=["PERSON", "ADDRESS"]))
    got = {(f.entity_type, text.encode()[f.start:f.end].decode()) for f in resp.findings}
    assert ("PERSON", "Hélène Dubois") in got and ("ADDRESS", "12 rue de la Paix, 75002 Paris") in got
