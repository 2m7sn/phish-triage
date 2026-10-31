from pathlib import Path

from phish_triage.parse import parse
from phish_triage.rules import check_auth

CORPUS = Path(__file__).resolve().parents[1] / "corpus"


def _write(tmp_path: Path, headers: str) -> Path:
    p = tmp_path / "t.eml"
    p.write_bytes((headers + "\r\nFrom: A <a@x.example>\r\nTo: b@corp.example\r\nSubject: t\r\n\r\nbody\r\n").encode())
    return p


def test_authentication_results_parsed(tmp_path):
    m = parse(_write(tmp_path, "Authentication-Results: mx; spf=fail smtp.mailfrom=x.example; dkim=pass header.d=x.example; dmarc=fail header.from=x.example"))
    assert m.auth == {"spf": "fail", "dkim": "pass", "dmarc": "fail"}
    codes = {f.code: f.weight for f in check_auth(m)}
    assert codes == {"SPF_FAIL": 15, "DMARC_FAIL": 20}


def test_received_spf_fallback_and_missing(tmp_path):
    m = parse(_write(tmp_path, "Received-SPF: Softfail (mx: domain of a@x.example does not designate 203.0.113.9 as permitted sender) client-ip=203.0.113.9;"))
    assert m.auth["spf"] == "softfail"
    none = parse(_write(tmp_path, "X-Nothing: 1"))
    assert [f.code for f in check_auth(none)] == ["AUTH_MISSING"]


def test_received_chain_public_ips_origin_first():
    m = parse(CORPUS / "m01_absher_fine_ip_url.eml")
    assert m.received_ips == ["203.0.113.44"]  # RFC 5737 kept; our own mx1.corp.example hop (192.0.2.10) dropped
    assert m.auth["spf"] == "fail" and m.auth["dmarc"] == "fail"
