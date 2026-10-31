"""Regression tests for the fixes requested in review round 1 (R1-R4)."""
import base64
from pathlib import Path

from phish_triage.parse import from_bytes
from phish_triage.rules import check_domain, run_all
from phish_triage.triage import triage

FRESH = Path(__file__).resolve().parents[1] / "corpus-fresh"


def test_r1_unknown_charset_does_not_crash():
    raw = (b"From: a@x.example\r\nTo: b@corp.example\r\nSubject: t\r\n"
           b"Content-Type: text/plain; charset=\"x-made-up-charset\"\r\n\r\nhello \xff world\r\n")
    m = from_bytes(raw)
    assert "hello" in m.text and "world" in m.text


def test_r2_rfc822_attachment_triages_inner_message():
    inner = (b"From: Absher <no-reply@absher-notify.example>\r\nTo: user@corp.example\r\n"
             b"Subject: fine\r\nAuthentication-Results: mx; spf=fail; dmarc=fail header.from=absher-notify.example\r\n"
             b"Content-Type: text/plain\r\n\r\nPay the fine http://203.0.113.10/x\r\n")
    wrapper = (b"From: Reporter <m.alharbi@corp.example>\r\nTo: soc@corp.example\r\nSubject: FW: suspicious\r\n"
               b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n"
               b"--B\r\nContent-Type: text/plain\r\n\r\nplease check\r\n"
               b"--B\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment; filename=\"orig.eml\"\r\n\r\n" + inner + b"\r\n--B--\r\n")
    m = from_bytes(wrapper)
    assert m.from_addr == "no-reply@absher-notify.example" and m.wrapper_from == "m.alharbi@corp.example"
    codes = {f.code for f in run_all(m)}
    assert {"DISPLAYNAME_SPOOF", "URL_IP", "REPORTED_AS_ATTACHMENT"} <= codes


def test_r3_html_attachment_script_and_redirect_url():
    html = b'<html><script>window.location="https://198.51.100.211/o365/login.php?u=' + base64.b64encode(b"x") + b'";</script></html>'
    raw = (b"From: v@pbx.example\r\nTo: b@corp.example\r\nSubject: voicemail\r\nMIME-Version: 1.0\r\n"
           b"Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nlisten\r\n"
           b"--B\r\nContent-Type: text/html\r\nContent-Disposition: attachment; filename=\"vm.html\"\r\n"
           b"Content-Transfer-Encoding: base64\r\n\r\n" + base64.b64encode(html) + b"\r\n--B--\r\n")
    m = from_bytes(raw)
    codes = {f.code for f in run_all(m)}
    assert {"ATT_HTML", "ATT_HTML_SCRIPT", "URL_IP"} <= codes
    assert any(l.host == "198.51.100.211" for l in m.links)


def test_r4_brand_subdomain_only_in_prefix():
    assert "DOMAIN_BRAND_SUBDOMAIN" not in {f.code for f in check_domain("sadad.com.sa")}
    assert "DOMAIN_BRAND_SUBDOMAIN" not in {f.code for f in check_domain("aramex.com.sa")}
    assert "DOMAIN_BRAND_SUBDOMAIN" in {f.code for f in check_domain("spl.com.sa.track-parcel.example")}
    assert check_domain("stcpay.com.sa") == []  # related-domain allow-list


def test_fresh_set_files_parse_and_mailing_list_is_not_malicious():
    r = triage(FRESH / "f3_mailing_list_dmarc_fail.eml")
    assert r.verdict != "malicious"
    r7 = triage(FRESH / "f7_html_att_js_redirect.eml")
    assert r7.verdict == "malicious"
