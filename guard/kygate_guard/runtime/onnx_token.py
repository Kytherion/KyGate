"""The ONNX token-classifier runtime: one model pack, run with ONNX Runtime
and the `tokenizers` library, without PyTorch.

Any pack whose model is a token classifier with BIO labels (B-X, I-X, O) can
use this runtime with no code: its manifest names the files and maps the
model's labels to KyGate's data types.

Decoding follows the reference decoder its authors publish for the default
pack (bardsai/eu-pii-anonimization-multilang-v3, pii_detector.py), so the
Guard reproduces their reported scores:

  1. Sliding windows over the text (512 tokens, stride 128); softmax per token.
  2. One label per word: the mean of its sub-token probabilities, with B-/I-
     mass pooled per type. Words split on whitespace and , ; | " < > ( ) [ ] { } * ^,
     with edge punctuation trimmed.
  3. Adjacent words of the same type are merged, unless the next word looks
     like the start of a new value.
  4. Format checks: a link must look like a URL; a phone number needs 5 digits
     or more; an identifier needs 2 digits or more.
  5. Every email address that a pattern matches is an email address.
"""

from __future__ import annotations

import json
import re

import numpy as np

from ..detectors.base import MODEL, Detection, Detector
from ..packs import Pack

_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}(?![\w-])")
_URLISH = re.compile(r"(https?://|www\.|\w\.[a-z]{2,}\b|/\w)", re.I)
_WORD = re.compile(r"[^\s,;|\"<>()\[\]{}*^]+")
_ID_TYPES = ("PERSON_IDENTIFIER", "BANK_ACCOUNT_IDENTIFIER", "PAYMENT_CARD", "ACCOUNT_IDENTIFIER",
             "DOCUMENT_IDENTIFIER", "VEHICLE_IDENTIFIER")
_OPEN = "([{<\"'«“‘„"
_CLOSE = ")]}>\"'»”’.,;:!?"


def _valid(text: str, s: int, e: int, label: str) -> bool:
    v = text[s:e]
    digits = sum(c.isdigit() for c in v)
    if label == "IDENTIFYING_LINK":
        return bool(_URLISH.search(v))
    if label == "PHONE_NUMBER":
        return digits >= 5
    if label in _ID_TYPES:
        return digits >= 2
    return True


class OnnxTokenClassifier(Detector):
    level = MODEL

    def __init__(self, pack: Pack, threads: int = 0):
        import onnxruntime as ort
        from tokenizers import Tokenizer

        self.pack = pack
        self.name = f"{pack.name}/{pack.version[:12]}"
        self.license = pack.license
        self.languages = tuple(pack.languages)
        settings = pack.settings
        self._window = int(settings.get("window_tokens", 512))
        self._stride = int(settings.get("stride_tokens", 128))

        model_file = next(f.path for f in pack.files if f.path.endswith(".onnx"))
        opts = ort.SessionOptions()
        if threads:
            opts.intra_op_num_threads = threads
        self._session = ort.InferenceSession(str(pack.file(model_file)), sess_options=opts, providers=["CPUExecutionProvider"])
        self._inputs = {i.name for i in self._session.get_inputs()}

        self._tok = Tokenizer.from_file(str(pack.file("tokenizer.json")))
        self._tok.no_padding()
        self._tok.enable_truncation(max_length=self._window, stride=self._stride)

        id2label = {int(k): v for k, v in json.loads(pack.file(pack.labels).read_text(encoding="utf-8"))["id2label"].items()}
        n = len(id2label)
        self._labels = sorted({v.split("-", 1)[1] for v in id2label.values() if v != "O"})
        index = {t: i for i, t in enumerate(self._labels)}
        o = len(self._labels)
        # label -> model type (last column: O), and the mass of B- labels per token
        self._to_type = np.zeros((n, o + 1), dtype=np.float32)
        self._is_b = np.zeros(n, dtype=np.float32)
        for i in range(n):
            lab = id2label[i]
            self._to_type[i, o if lab == "O" else index[lab.split("-", 1)[1]]] = 1
            self._is_b[i] = 1.0 if lab.startswith(("B-", "S-")) else 0.0
        self._map = {k: v for k, v in pack.label_map.items() if v}
        self.entity_types = tuple(sorted(set(self._map.values())))

    def warm_up(self) -> None:
        self._spans("Warm-up: Alice Martin, 12 rue de la Paix, Paris, alice@example.com.")

    def _char_probs(self, text: str):
        o = len(self._labels)
        acc = np.zeros((len(text), o + 1), dtype=np.float32)
        cnt = np.zeros(len(text), dtype=np.float32)
        bmass = np.zeros(len(text), dtype=np.float32)
        first = self._tok.encode(text)
        for enc in [first, *first.overflowing]:
            ids = np.asarray([enc.ids], dtype=np.int64)
            feed = {"input_ids": ids}
            if "attention_mask" in self._inputs:
                feed["attention_mask"] = np.asarray([enc.attention_mask], dtype=np.int64)
            logits = self._session.run(None, feed)[0][0]
            logits = logits - logits.max(-1, keepdims=True)
            probs = np.exp(logits)
            probs /= probs.sum(-1, keepdims=True)
            per_type = probs @ self._to_type
            per_b = probs @ self._is_b
            for j, (s, e) in enumerate(enc.offsets):
                if e <= s or enc.special_tokens_mask[j]:
                    continue
                while s < e - 1 and text[s].isspace():  # the offsets include the leading space
                    s += 1
                acc[s] += per_type[j]
                cnt[s] += 1
                bmass[s] += per_b[j]
        return acc, cnt, bmass

    def _spans(self, text: str) -> list[tuple[int, int, str, float]]:
        if not text.strip():
            return []
        acc, cnt, bmass = self._char_probs(text)
        o = len(self._labels)
        spans: list[list] = []
        for m in _WORD.finditer(text):
            ws, we = m.start(), m.end()
            while ws < we and text[ws] in _OPEN:
                ws += 1
            while we > ws and text[we - 1] in _CLOSE:
                we -= 1
            if we <= ws:
                continue
            sel = cnt[ws:we] > 0
            if not sel.any():
                continue
            v = acc[ws:we][sel].sum(0) / cnt[ws:we][sel].sum()
            k = int(v.argmax())
            if k == o:
                continue
            f = int(np.flatnonzero(sel)[0])
            start_b = bmass[ws + f] / max(cnt[ws + f], 1)
            label = self._labels[k]
            gap = text[spans[-1][1]:ws] if spans else ""
            if spans and spans[-1][2] == label and gap.strip(" ,-/.()") == "" and "\n\n" not in gap and start_b < 0.5:
                spans[-1][1] = we
                spans[-1][3] = min(spans[-1][3], float(v[k]))
            else:
                spans.append([ws, we, label, float(v[k])])
        out = [tuple(s) for s in spans if _valid(text, s[0], s[1], s[2])]
        emails = [(m.start(), m.end()) for m in _EMAIL.finditer(text)]
        if emails:
            out = [s for s in out if not any(s[0] < b and a < s[1] for a, b in emails)]
            out += [(a, b, "EMAIL_ADDRESS", 1.0) for a, b in emails]
        return sorted(out)

    def detect(self, text: str, entity_types: set[str]) -> list[Detection]:
        found = []
        for s, e, label, score in self._spans(text):
            kind = self._map.get(label)
            if kind and (not entity_types or kind in entity_types):
                found.append(Detection(kind, s, e, score, self.name))
        return found
