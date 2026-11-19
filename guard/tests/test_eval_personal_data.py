"""Quality gate of the personal-data model pack:
precision and recall per data type and per language, on the synthetic English
and French corpus in eval/detection/corpus. Skipped when the pack is not
installed (kygate-guard models pull personal-data).

A finding matches an expected value when it has the same type and covers at
least half of the value's characters; another piece of the same value is not
counted as a false alarm. Findings of other types are not scored.
A missed value is a leak; a false alarm is a broken prompt: both have floors.
"""

import json
from collections import defaultdict
from pathlib import Path

import pytest

from kygate_guard import packs

CORPUS = Path(__file__).resolve().parents[2] / "eval" / "detection" / "corpus" / "personal_data_en_fr.jsonl"
TYPES = ("PERSON", "ADDRESS", "PHONE", "EMAIL", "DATE_OF_BIRTH", "BANK_ACCOUNT", "ORGANIZATION")
REAL = packs.default_dir() / "personal-data"

# Floors per language, from the first measurement (2026-11-17). They are a
# regression gate on a small corpus (55 texts), not a certificate: raise them as
# the pack improves, never lower them silently. Known weakness: a date of birth
# written as "14 July 1979" or "22/03/1985" is often taken for a plain date.
FLOORS = {
    "recall": {"PERSON": 0.90, "ADDRESS": 0.95, "PHONE": 1.0, "EMAIL": 1.0, "DATE_OF_BIRTH": 0.5, "BANK_ACCOUNT": 1.0},
    "precision_all_types": 0.90,
}


def overlap(a, b):
    return max(0, min(a[1], b[1]) - max(a[0], b[0]))


def measure(detector):
    rows = [json.loads(line) for line in CORPUS.read_text(encoding="utf-8").splitlines() if line.strip()]
    stats = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0})
    misses, alarms = [], []
    for r in rows:
        text, lang = r["text"], r["lang"]
        expected = []
        for t, v in r["spans"]:
            i = text.find(v)
            assert i >= 0, f"corpus: {v!r} not in {text!r}"
            expected.append((t, i, i + len(v)))
        found = [(d.entity_type, d.start, d.end) for d in detector.detect(text, set(TYPES))]
        used = set()
        for t, s, e in expected:
            hit = next((j for j, f in enumerate(found) if j not in used and f[0] == t and overlap((s, e), f[1:]) * 2 >= e - s), None)
            if hit is None:
                stats[(lang, t)]["fn"] += 1
                misses.append(f"[{lang}] missed {t} {text[s:e]!r} in {text!r}")
            else:
                used.add(hit)
                stats[(lang, t)]["tp"] += 1
        for j, f in enumerate(found):
            # A piece of a value already found (a ZIP code split from its
            # street) is not a false alarm.
            if j not in used and not any(f[0] == t and overlap((s, e), f[1:]) for t, s, e in expected):
                stats[(lang, f[0])]["fp"] += 1
                alarms.append(f"[{lang}] false {f[0]} {text[f[1]:f[2]]!r} in {text!r}")
    return stats, misses, alarms


def ratio(a, b):
    return a / b if b else 1.0


@pytest.mark.skipif(not (REAL / "pack.json").is_file(), reason="the personal-data pack is not installed")
def test_personal_data_quality():
    from kygate_guard.runtime.onnx_token import OnnxTokenClassifier

    stats, misses, alarms = measure(OnnxTokenClassifier(packs.load(REAL)))
    lines = ["", f"{'lang':5}{'type':15}{'recall':>8}{'precision':>11}   tp fn fp"]
    failures = []
    for lang in ("en", "fr"):
        tp_all = fp_all = 0
        for t in TYPES:
            s = stats[(lang, t)]
            tp_all, fp_all = tp_all + s["tp"], fp_all + s["fp"]
            if s["tp"] + s["fn"] + s["fp"] == 0:
                continue
            rec, prec = ratio(s["tp"], s["tp"] + s["fn"]), ratio(s["tp"], s["tp"] + s["fp"])
            lines.append(f"{lang:5}{t:15}{rec:8.2f}{prec:11.2f}   {s['tp']:2} {s['fn']:2} {s['fp']:2}")
            if t in FLOORS["recall"] and s["tp"] + s["fn"] and rec < FLOORS["recall"][t]:
                failures.append(f"{lang} {t} recall {rec:.2f} < floor {FLOORS['recall'][t]}")
        prec_all = ratio(tp_all, tp_all + fp_all)
        lines.append(f"{lang:5}{'all types':15}{'':8}{prec_all:11.2f}")
        if prec_all < FLOORS["precision_all_types"]:
            failures.append(f"{lang} precision {prec_all:.2f} < floor {FLOORS['precision_all_types']}")
    report = "\n".join(lines + [""] + misses + alarms)
    print(report)
    assert not failures, "; ".join(failures) + "\n" + report
