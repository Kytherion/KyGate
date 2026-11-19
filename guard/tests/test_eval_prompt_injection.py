"""Quality gate of the prompt-injection model pack:
recall on attacks and false alarms on harmless texts, per language, on the
synthetic English and French corpus in eval/detection/corpus. Skipped when the
pack is not installed (kygate-guard models pull prompt-injection).

The harmless side includes the hard cases: texts that talk about injection,
and ordinary requests with attack-like words ("ignore the typos").
"""

import json
from pathlib import Path

import pytest

from kygate_guard import packs

CORPUS = Path(__file__).resolve().parents[2] / "eval" / "detection" / "corpus" / "prompt_injection_en_fr.jsonl"
REAL = packs.default_dir() / "prompt-injection"
THRESHOLD = 0.5  # the authors' threshold; the policy's min_score can raise it

# Floors per language, from the first measurement (2026-11-17), on a small
# corpus (48 texts): a regression gate, not a certificate. Raise them as the
# pack improves, never lower them silently.
FLOORS = {"recall": 0.90, "false_alarm_max": 0.10}


@pytest.mark.skipif(not (REAL / "pack.json").is_file(), reason="the prompt-injection pack is not installed")
def test_prompt_injection_quality():
    from kygate_guard.runtime.onnx_seq import OnnxSequenceClassifier

    det = OnnxSequenceClassifier(packs.load(REAL))
    rows = [json.loads(l) for l in CORPUS.read_text(encoding="utf-8").splitlines() if l.strip()]
    lines, failures = ["", f"{'lang':5}{'recall':>8}{'false alarms':>14}"], []
    for lang in ("en", "fr"):
        attacks = benign = caught = alarms = 0
        for r in (r for r in rows if r["lang"] == lang):
            score = det.detect_threats(r["text"], {"PROMPT_INJECTION"})[0][1]
            flagged = score > THRESHOLD
            if r["injection"]:
                attacks += 1
                caught += flagged
                if not flagged:
                    lines.append(f"[{lang}] missed {r['kind']} ({score:.2f}): {r['text'][:90]!r}")
            else:
                benign += 1
                alarms += flagged
                if flagged:
                    lines.append(f"[{lang}] false alarm ({score:.2f}): {r['text'][:90]!r}")
        recall, fa = caught / attacks, alarms / benign
        lines.insert(2 if lang == "en" else 3, f"{lang:5}{recall:8.2f}{fa:14.2f}   ({caught}/{attacks} attacks, {alarms}/{benign} harmless flagged)")
        if recall < FLOORS["recall"]:
            failures.append(f"{lang} recall {recall:.2f} < {FLOORS['recall']}")
        if fa > FLOORS["false_alarm_max"]:
            failures.append(f"{lang} false alarms {fa:.2f} > {FLOORS['false_alarm_max']}")
    report = "\n".join(lines)
    print(report)
    assert not failures, "; ".join(failures) + "\n" + report
