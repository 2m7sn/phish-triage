import json
import re
from pathlib import Path

from phish_triage.cli import main
from phish_triage.evaluate import evaluate
from phish_triage.triage import triage

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus"


def test_single_verdicts():
    bad = triage(CORPUS / "m03_spl_parcel_fee.eml")
    assert bad.verdict == "malicious"
    assert {"DOMAIN_BRAND_SUBDOMAIN", "REPLYTO_MISMATCH", "URL_TEXT_MISMATCH", "LURE_PAYMENT"} <= {f.code for f in bad.findings}
    assert any("Block sender" in s for s in bad.actions)
    assert bad.iocs["domain"] == ["spl.com.sa.track-parcel.example"]
    ok = triage(CORPUS / "c03_alrajhi_otp_real.eml")
    assert ok.verdict == "clean" and ok.actions[0].startswith("Close")


def test_eval_on_corpus_floor():
    results, labels, m = evaluate(CORPUS)
    assert m["n"] == len(labels) >= 40
    assert m["binary"]["recall"] >= 0.9  # phish (malicious|suspicious) found
    assert m["binary"]["precision"] >= 0.9
    assert m["macro_f1"] >= 0.75


def test_cli_writes_reports_without_control_chars(tmp_path):
    assert main(["eval", str(CORPUS), "--out", str(tmp_path)]) == 0
    for name in ("summary.html", "iocs.csv", "iocs.stix.json", "results.json", "eval.json"):
        assert (tmp_path / name).exists(), name
    cases = list((tmp_path / "cases").glob("*.html"))
    assert len(cases) == len(list(CORPUS.glob("*.eml")))
    ctrl = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
    for p in cases + [tmp_path / "summary.html"]:
        assert not ctrl.search(p.read_text(encoding="utf-8")), p.name
    stix = json.loads((tmp_path / "iocs.stix.json").read_text(encoding="utf-8"))
    assert stix["type"] == "bundle" and stix["objects"]
    assert all(o["spec_version"] == "2.1" and o["pattern_type"] == "stix" for o in stix["objects"])
