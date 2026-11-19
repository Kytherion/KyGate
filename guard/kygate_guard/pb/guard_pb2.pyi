from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Role(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ROLE_UNSPECIFIED: _ClassVar[Role]
    ROLE_SYSTEM: _ClassVar[Role]
    ROLE_USER: _ClassVar[Role]
    ROLE_ASSISTANT: _ClassVar[Role]
    ROLE_TOOL_RESULT: _ClassVar[Role]
    ROLE_INPUT: _ClassVar[Role]

class ContentKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CONTENT_KIND_UNSPECIFIED: _ClassVar[ContentKind]
    CONTENT_KIND_PROSE: _ClassVar[ContentKind]
    CONTENT_KIND_CODE: _ClassVar[ContentKind]
    CONTENT_KIND_STRUCTURED: _ClassVar[ContentKind]
ROLE_UNSPECIFIED: Role
ROLE_SYSTEM: Role
ROLE_USER: Role
ROLE_ASSISTANT: Role
ROLE_TOOL_RESULT: Role
ROLE_INPUT: Role
CONTENT_KIND_UNSPECIFIED: ContentKind
CONTENT_KIND_PROSE: ContentKind
CONTENT_KIND_CODE: ContentKind
CONTENT_KIND_STRUCTURED: ContentKind

class Segment(_message.Message):
    __slots__ = ("id", "role", "kind", "untrusted", "text")
    ID_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    UNTRUSTED_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    id: str
    role: Role
    kind: ContentKind
    untrusted: bool
    text: str
    def __init__(self, id: _Optional[str] = ..., role: _Optional[_Union[Role, str]] = ..., kind: _Optional[_Union[ContentKind, str]] = ..., untrusted: _Optional[bool] = ..., text: _Optional[str] = ...) -> None: ...

class InspectRequest(_message.Message):
    __slots__ = ("segments", "entity_types", "threat_types", "policy_version")
    SEGMENTS_FIELD_NUMBER: _ClassVar[int]
    ENTITY_TYPES_FIELD_NUMBER: _ClassVar[int]
    THREAT_TYPES_FIELD_NUMBER: _ClassVar[int]
    POLICY_VERSION_FIELD_NUMBER: _ClassVar[int]
    segments: _containers.RepeatedCompositeFieldContainer[Segment]
    entity_types: _containers.RepeatedScalarFieldContainer[str]
    threat_types: _containers.RepeatedScalarFieldContainer[str]
    policy_version: str
    def __init__(self, segments: _Optional[_Iterable[_Union[Segment, _Mapping]]] = ..., entity_types: _Optional[_Iterable[str]] = ..., threat_types: _Optional[_Iterable[str]] = ..., policy_version: _Optional[str] = ...) -> None: ...

class Finding(_message.Message):
    __slots__ = ("segment_id", "entity_type", "start", "end", "score", "detector", "language")
    SEGMENT_ID_FIELD_NUMBER: _ClassVar[int]
    ENTITY_TYPE_FIELD_NUMBER: _ClassVar[int]
    START_FIELD_NUMBER: _ClassVar[int]
    END_FIELD_NUMBER: _ClassVar[int]
    SCORE_FIELD_NUMBER: _ClassVar[int]
    DETECTOR_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_FIELD_NUMBER: _ClassVar[int]
    segment_id: str
    entity_type: str
    start: int
    end: int
    score: float
    detector: str
    language: str
    def __init__(self, segment_id: _Optional[str] = ..., entity_type: _Optional[str] = ..., start: _Optional[int] = ..., end: _Optional[int] = ..., score: _Optional[float] = ..., detector: _Optional[str] = ..., language: _Optional[str] = ...) -> None: ...

class Threat(_message.Message):
    __slots__ = ("segment_id", "type", "score", "detector")
    SEGMENT_ID_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    SCORE_FIELD_NUMBER: _ClassVar[int]
    DETECTOR_FIELD_NUMBER: _ClassVar[int]
    segment_id: str
    type: str
    score: float
    detector: str
    def __init__(self, segment_id: _Optional[str] = ..., type: _Optional[str] = ..., score: _Optional[float] = ..., detector: _Optional[str] = ...) -> None: ...

class InspectResponse(_message.Message):
    __slots__ = ("findings", "threats")
    FINDINGS_FIELD_NUMBER: _ClassVar[int]
    THREATS_FIELD_NUMBER: _ClassVar[int]
    findings: _containers.RepeatedCompositeFieldContainer[Finding]
    threats: _containers.RepeatedCompositeFieldContainer[Threat]
    def __init__(self, findings: _Optional[_Iterable[_Union[Finding, _Mapping]]] = ..., threats: _Optional[_Iterable[_Union[Threat, _Mapping]]] = ...) -> None: ...

class EmbedRequest(_message.Message):
    __slots__ = ("texts",)
    TEXTS_FIELD_NUMBER: _ClassVar[int]
    texts: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, texts: _Optional[_Iterable[str]] = ...) -> None: ...

class Vector(_message.Message):
    __slots__ = ("values",)
    VALUES_FIELD_NUMBER: _ClassVar[int]
    values: _containers.RepeatedScalarFieldContainer[float]
    def __init__(self, values: _Optional[_Iterable[float]] = ...) -> None: ...

class EmbedResponse(_message.Message):
    __slots__ = ("vectors", "model")
    VECTORS_FIELD_NUMBER: _ClassVar[int]
    MODEL_FIELD_NUMBER: _ClassVar[int]
    vectors: _containers.RepeatedCompositeFieldContainer[Vector]
    model: str
    def __init__(self, vectors: _Optional[_Iterable[_Union[Vector, _Mapping]]] = ..., model: _Optional[str] = ...) -> None: ...

class RerankRequest(_message.Message):
    __slots__ = ("query", "candidates")
    QUERY_FIELD_NUMBER: _ClassVar[int]
    CANDIDATES_FIELD_NUMBER: _ClassVar[int]
    query: str
    candidates: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, query: _Optional[str] = ..., candidates: _Optional[_Iterable[str]] = ...) -> None: ...

class RerankResponse(_message.Message):
    __slots__ = ("scores", "model")
    SCORES_FIELD_NUMBER: _ClassVar[int]
    MODEL_FIELD_NUMBER: _ClassVar[int]
    scores: _containers.RepeatedScalarFieldContainer[float]
    model: str
    def __init__(self, scores: _Optional[_Iterable[float]] = ..., model: _Optional[str] = ...) -> None: ...

class InfoRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class Model(_message.Message):
    __slots__ = ("task", "name", "version", "license")
    TASK_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    LICENSE_FIELD_NUMBER: _ClassVar[int]
    task: str
    name: str
    version: str
    license: str
    def __init__(self, task: _Optional[str] = ..., name: _Optional[str] = ..., version: _Optional[str] = ..., license: _Optional[str] = ...) -> None: ...

class InfoResponse(_message.Message):
    __slots__ = ("version", "ready", "entity_types", "threat_types", "languages", "models", "coverage")
    VERSION_FIELD_NUMBER: _ClassVar[int]
    READY_FIELD_NUMBER: _ClassVar[int]
    ENTITY_TYPES_FIELD_NUMBER: _ClassVar[int]
    THREAT_TYPES_FIELD_NUMBER: _ClassVar[int]
    LANGUAGES_FIELD_NUMBER: _ClassVar[int]
    MODELS_FIELD_NUMBER: _ClassVar[int]
    COVERAGE_FIELD_NUMBER: _ClassVar[int]
    version: str
    ready: bool
    entity_types: _containers.RepeatedScalarFieldContainer[str]
    threat_types: _containers.RepeatedScalarFieldContainer[str]
    languages: _containers.RepeatedScalarFieldContainer[str]
    models: _containers.RepeatedCompositeFieldContainer[Model]
    coverage: _containers.RepeatedCompositeFieldContainer[Coverage]
    def __init__(self, version: _Optional[str] = ..., ready: _Optional[bool] = ..., entity_types: _Optional[_Iterable[str]] = ..., threat_types: _Optional[_Iterable[str]] = ..., languages: _Optional[_Iterable[str]] = ..., models: _Optional[_Iterable[_Union[Model, _Mapping]]] = ..., coverage: _Optional[_Iterable[_Union[Coverage, _Mapping]]] = ...) -> None: ...

class Coverage(_message.Message):
    __slots__ = ("entity_type", "level", "detectors")
    ENTITY_TYPE_FIELD_NUMBER: _ClassVar[int]
    LEVEL_FIELD_NUMBER: _ClassVar[int]
    DETECTORS_FIELD_NUMBER: _ClassVar[int]
    entity_type: str
    level: str
    detectors: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, entity_type: _Optional[str] = ..., level: _Optional[str] = ..., detectors: _Optional[_Iterable[str]] = ...) -> None: ...
