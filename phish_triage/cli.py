"""phish-triage scan <eml|dir>... [--out DIR] [--json] [--enrich]
phish-triage eval <corpus_dir> [--out DIR]"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .evaluate import evaluate
from .report import write_all
from .rules import Finding
from .triage import Result, triage


def _emls(paths: list[str]) -> list[Path]:
    out: list[Path] = []
    for p in map(Path, paths):
        out += sorted(p.glob("*.eml")) if p.is_dir() else [p]
    return out


def _print(results: list[Result]) -> None:
    for r in results:
        top = ", ".join(f.code for f in r.findings[:3] if f.weight > 0) or "-"
        print(f"{r.verdict:<10} {r.score:>3}  {r.file:<40} {top}")


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(prog="phish-triage", description="L1 triage of reported .eml files")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="analyse .eml files or folders")
    s.add_argument("paths", nargs="+")
    s.add_argument("--out", help="write HTML reports, IOC CSV, STIX bundle here")
    s.add_argument("--json", action="store_true", help="print results as JSON instead of a table")
    s.add_argument("--enrich", action="store_true", help="query VirusTotal/URLhaus if VT_API_KEY / URLHAUS_AUTH_KEY are set")
    ev = sub.add_parser("eval", help="scan a corpus folder with labels.csv and report precision/recall/F1")
    ev.add_argument("corpus")
    ev.add_argument("--out", default="out")
    a = ap.parse_args(argv)

    if a.cmd == "scan":
        results = [triage(p) for p in _emls(a.paths)]
        if a.enrich:
            from .enrich import enrich
            for r in results:
                for k, v in enrich(r).items():
                    r.findings.append(Finding("ENRICH", 0, f"{k}: {v}"))
        if a.json:
            print(json.dumps([r.to_dict() for r in results], indent=1, ensure_ascii=False))
        else:
            _print(results)
        if a.out:
            write_all(results, Path(a.out), ", ".join(a.paths))
            print(f"\nreports: {Path(a.out) / 'summary.html'}")
        return 0

    results, labels, m = evaluate(Path(a.corpus))
    _print(results)
    print(f"\nn={m['n']}  accuracy={m['accuracy']:.3f}  macro-F1={m['macro_f1']:.3f}")
    for c, v in m["classes"].items():
        print(f"{c:<11} P={v['precision']:.2f} R={v['recall']:.2f} F1={v['f1']:.2f} n={v['support']}")
    b = m["binary"]
    print(f"{'binary':<11} P={b['precision']:.2f} R={b['recall']:.2f} F1={b['f1']:.2f} n={b['support']}")
    print("confusion (truth -> predicted):", json.dumps(m["confusion"]))
    print("FP rules:", m["fp_reasons"][:5])
    print("misclassified:", m["misclassified"])
    write_all(results, Path(a.out), a.corpus, labels, m)
    print(f"\nreports: {Path(a.out) / 'summary.html'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
