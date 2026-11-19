"""Detectors of personal data.

The configurable recognizers: patterns and dictionaries, added by
configuration (architecture §4.4, "Extension"). The ML detectors for names,
addresses, and other data that can only be recognized in context come from a
model pack (packs.py, runtime/onnx_token.py).

A configuration file is JSON:

    {
      "recognizers": [
        {"type": "PERSON", "terms": ["Alice Martin", "Hélène Dubois"], "case_sensitive": false},
        {"type": "EMPLOYEE_ID", "pattern": "\\\\bEMP-[0-9]{6}\\\\b", "score": 0.99}
      ]
    }
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from .base import LIST, Detection, Detector


@dataclass
class _Recognizer:
    entity_type: str
    regex: re.Pattern
    score: float


class ConfiguredRecognizers(Detector):
    """Pattern and dictionary recognizers from a configuration file. They are
    the Guard's base level: they find what is listed, and nothing else."""

    name = "recognizers/1"
    level = LIST
    license = "Apache-2.0"

    def __init__(self, recognizers: list[_Recognizer]):
        self._recognizers = recognizers
        self.entity_types = tuple(sorted({r.entity_type for r in recognizers}))

    @classmethod
    def from_file(cls, path: str) -> "ConfiguredRecognizers":
        with open(path, encoding="utf-8") as f:
            return cls.from_config(json.load(f))

    @classmethod
    def from_config(cls, config: dict) -> "ConfiguredRecognizers":
        out = []
        for i, r in enumerate(config.get("recognizers", [])):
            entity = str(r.get("type", "")).strip().upper()
            if not entity:
                raise ValueError(f"recognizer {i}: a type is required, such as PERSON")
            flags = 0 if r.get("case_sensitive", False) else re.IGNORECASE
            if "pattern" in r:
                regex = re.compile(r["pattern"], flags)
            elif r.get("terms"):
                terms = sorted({t.strip() for t in r["terms"] if t.strip()}, key=len, reverse=True)
                # Whole words only, so "Al" is not found inside "Alice".
                regex = re.compile(r"(?<!\w)(?:" + "|".join(re.escape(t) for t in terms) + r")(?!\w)", flags)
            else:
                raise ValueError(f"recognizer {i} ({entity}): give a pattern or a list of terms")
            out.append(_Recognizer(entity, regex, float(r.get("score", 1.0))))
        return cls(out)

    def detect(self, text: str, entity_types: set[str]) -> list[Detection]:
        found = []
        for r in self._recognizers:
            if entity_types and r.entity_type not in entity_types:
                continue
            for m in r.regex.finditer(text):
                if m.end() > m.start():
                    found.append(Detection(r.entity_type, m.start(), m.end(), r.score, self.name))
        return found
