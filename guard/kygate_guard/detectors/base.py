"""What every detector returns, and the conversion to the contract's offsets.

Detectors work on Python strings and count characters. The contract counts
UTF-8 bytes, end exclusive (architecture §4.3), so every finding passes
through `to_bytes` before it leaves the Guard. Getting this wrong would mask
the wrong part of a name in any text with an accent.
"""

from __future__ import annotations

from dataclasses import dataclass

LIST = "list"    # finds what a recognizers file lists, and nothing else
MODEL = "model"  # an ML model: finds values it has never seen


@dataclass(frozen=True)
class Detection:
    entity_type: str
    start: int  # character offset, inclusive
    end: int    # character offset, exclusive
    score: float
    detector: str
    language: str = ""


class ByteOffsets:
    """Maps character offsets of one text to UTF-8 byte offsets."""

    def __init__(self, text: str):
        self._offsets = [0] * (len(text) + 1)
        n = 0
        for i, ch in enumerate(text):
            self._offsets[i] = n
            n += len(ch.encode("utf-8", "surrogatepass"))
        self._offsets[len(text)] = n

    def __call__(self, char_offset: int) -> int:
        return self._offsets[char_offset]


class Detector:
    """A detector finds some data types in prose. It never changes the text.

    `level` says what kind of detector it is, so that KyGate can show, for
    each data type, whether a list or a model covers it.
    """

    name = "detector"
    level = LIST
    license = ""
    entity_types: tuple[str, ...] = ()
    threat_types: tuple[str, ...] = ()
    languages: tuple[str, ...] = ()

    def detect(self, text: str, entity_types: set[str]) -> list[Detection]:
        return []

    def detect_threats(self, text: str, threat_types: set[str]) -> list[tuple[str, float]]:
        """The threat types this detector scores in the text, each with its
        score from 0 to 1. Run on untrusted segments only."""
        return []

    def warm_up(self) -> None:
        """Run once before the Guard reports ready, so the first request is not slow."""
