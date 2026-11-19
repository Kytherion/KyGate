"""The Guard against its contract, over a real gRPC connection.

Every value here is synthetic.
"""

import grpc
import pytest

from kygate_guard.detectors.base import ByteOffsets
from kygate_guard.detectors.personal_data import ConfiguredRecognizers
from kygate_guard.pb import guard_pb2, guard_pb2_grpc
from kygate_guard.server import GuardService, build_server

CONFIG = {"recognizers": [
    {"type": "PERSON", "terms": ["Hélène Dubois", "Alice", "Zoë"]},
    {"type": "EMPLOYEE_ID", "pattern": r"\bEMP-[0-9]{6}\b"},
]}


@pytest.fixture()
def stub():
    service = GuardService([ConfiguredRecognizers.from_config(CONFIG)], languages=[])
    server, port = build_server("127.0.0.1:0", service)
    server.start()
    service.mark_ready()
    channel = grpc.insecure_channel(f"127.0.0.1:{port}")
    yield guard_pb2_grpc.GuardStub(channel)
    channel.close()
    server.stop(0)


def seg(text, id="s0", kind=guard_pb2.CONTENT_KIND_PROSE):
    return guard_pb2.Segment(id=id, role=guard_pb2.ROLE_USER, kind=kind, untrusted=True, text=text)


def cut(text, f):
    return text.encode("utf-8")[f.start:f.end].decode("utf-8")


def test_offsets_are_utf8_bytes(stub):
    text = "Écris à Hélène Dubois, à Zoë 🙂 et à Alice."
    resp = stub.Inspect(guard_pb2.InspectRequest(segments=[seg(text)]))
    assert sorted(cut(text, f) for f in resp.findings) == ["Alice", "Hélène Dubois", "Zoë"]
    assert all(f.entity_type == "PERSON" and f.segment_id == "s0" for f in resp.findings)


def test_only_the_types_asked_for(stub):
    text = "Alice has badge EMP-123456."
    resp = stub.Inspect(guard_pb2.InspectRequest(segments=[seg(text)], entity_types=["EMPLOYEE_ID"]))
    assert [(f.entity_type, cut(text, f)) for f in resp.findings] == [("EMPLOYEE_ID", "EMP-123456")]


def test_whole_words_only(stub):
    resp = stub.Inspect(guard_pb2.InspectRequest(segments=[seg("Alicedale and Malice")]))
    assert list(resp.findings) == []


def test_structured_content_is_left_to_the_gateway(stub):
    resp = stub.Inspect(guard_pb2.InspectRequest(segments=[seg('{"name":"Alice"}', kind=guard_pb2.CONTENT_KIND_STRUCTURED)]))
    assert list(resp.findings) == []


def test_info(stub):
    info = stub.Info(guard_pb2.InfoRequest())
    assert info.ready and list(info.entity_types) == ["EMPLOYEE_ID", "PERSON"] and info.version


def test_not_ready_is_unavailable():
    service = GuardService([], languages=[])
    server, port = build_server("127.0.0.1:0", service)
    server.start()
    try:
        with grpc.insecure_channel(f"127.0.0.1:{port}") as ch:
            with pytest.raises(grpc.RpcError) as e:
                guard_pb2_grpc.GuardStub(ch).Inspect(guard_pb2.InspectRequest(segments=[seg("Alice")]))
            assert e.value.code() == grpc.StatusCode.UNAVAILABLE
    finally:
        server.stop(0)


def test_byte_offsets_table():
    b = ByteOffsets("aé🙂b")
    assert [b(i) for i in range(5)] == [0, 1, 3, 7, 8]


def test_bad_config_is_refused():
    with pytest.raises(ValueError):
        ConfiguredRecognizers.from_config({"recognizers": [{"terms": ["x"]}]})
    with pytest.raises(ValueError):
        ConfiguredRecognizers.from_config({"recognizers": [{"type": "PERSON"}]})
