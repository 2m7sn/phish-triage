"""Compare verdicts with corpus/labels.csv (file,label)."""

from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path

from .triage import Result, triage

CLASSES = ("malicious", "suspicious", "clean")


def load_labels(corpus: Path) -> dict[str, str]:
    with (corpus / "labels.csv").open(encoding="utf-8") as f:
        return {row["file"]: row["label"] for row in csv.DictReader(f)}


def _prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"precision": p, "recall": r, "f1": 2 * p * r / (p + r) if p + r else 0.0, "support": tp + fn}


def metrics(results: list[Result], labels: dict[str, str]) -> dict:
    pairs = [(labels[r.file], r.verdict, r) for r in results if r.file in labels]
    cm = {t: {p: 0 for p in CLASSES} for t in CLASSES}
    for t, p, _ in pairs:
        cm[t][p] += 1
    per = {}
    for c in CLASSES:
        tp = cm[c][c]
        fp = sum(cm[t][c] for t in CLASSES if t != c)
        fn = sum(cm[c][p] for p in CLASSES if p != c)
        per[c] = _prf(tp, fp, fn)
    phish = lambda v: v != "clean"  # noqa: E731
    b_tp = sum(1 for t, p, _ in pairs if phish(t) and phish(p))
    b_fp = sum(1 for t, p, _ in pairs if not phish(t) and phish(p))
    b_fn = sum(1 for t, p, _ in pairs if phish(t) and not phish(p))
    fp_reasons = Counter(f.code for t, p, r in pairs if t == "clean" and p != "clean" for f in r.findings if f.weight > 0)
    return {
        "n": len(pairs),
        "accuracy": sum(1 for t, p, _ in pairs if t == p) / len(pairs) if pairs else 0.0,
        "macro_f1": sum(per[c]["f1"] for c in CLASSES) / len(CLASSES),
        "classes": per,
        "binary": _prf(b_tp, b_fp, b_fn),
        "confusion": cm,
        "fp_reasons": fp_reasons.most_common(),
        "misclassified": [(r.file, t, p, r.score) for t, p, r in pairs if t != p],
    }


def evaluate(corpus: Path) -> tuple[list[Result], dict[str, str], dict]:
    labels = load_labels(corpus)
    results = [triage(corpus / f) for f in sorted(labels)]
    return results, labels, metrics(results, labels)
