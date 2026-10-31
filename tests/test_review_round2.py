"""Regression tests for review round 2 (F1-F4) plus IPv6 and STIX escaping."""
import base64
import json

from phish_triage.parse import Attachment, Link, from_bytes
from phish_triage.report import stix_bundle
from phish_triage.rules import check_attachments, check_context, check_language, check_links, run_all
from phish_triage.triage import Result

SPOOF = (b"Return-Path: <bounce@mailer-x.example>\r\n"
         b"Authentication-Results: mx; spf=fail smtp.mailfrom=mailer-x.example; dkim=none; dmarc=fail header.from=absher.sa\r\n"
         b"From: Absher <noreply@absher.sa>\r\nTo: u@corp.example\r\nSubject: fine\r\n%s"
         b"Content-Type: text/plain\r\n\r\nPay http://198.51.100.23/absher\r\n")


def _score(raw: bytes) -> int:
    return sum(f.weight for f in run_all(from_bytes(raw)))


def test_f1_forged_list_headers_do_not_soften():
    plain = _score(SPOOF % b"")
    forged = _score(SPOOF % b"List-Id: <news.mailer-x.example>\r\nReply-To: help@mailer-x.example\r\n")
    assert forged >= plain  # extra Reply-To may add, never subtract


def test_f1_genuine_list_is_softened():
    raw = (b"Return-Path: <list-bounces@lists.example>\r\nList-Id: <dev.lists.example>\r\n"
           b"Authentication-Results: mx; spf=pass smtp.mailfrom=lists.example; dkim=fail; dmarc=fail (p=none) header.from=uni.example\r\n"
           b"From: A <a@uni.example>\r\nTo: dev@lists.example\r\nReply-To: dev@lists.example\r\nSubject: [dev] hi\r\n"
           b"Content-Type: text/plain\r\n\r\nslides\r\n")
    codes = {f.code: f.weight for f in run_all(from_bytes(raw))}
    assert codes["DMARC_FAIL"] == 10 and codes["DKIM_FAIL"] == 5
    assert "REPLYTO_MISMATCH" not in codes and "RETURNPATH_MISMATCH" not in codes


def test_f2_double_extension_html_is_still_content_scanned():
    html = b'<html><script>var p=atob("aHR0cHM6Ly9ldmlsLXZpZXdlci5leGFtcGxlL3g=");window.location.replace(p);</script></html>'
    codes = {f.code for f in check_attachments([Attachment("invoice.pdf.html", html, "text/html")], "")}
    assert {"ATT_DOUBLE_EXT", "ATT_HTML_SCRIPT"} <= codes
    raw = (b"From: b@x.example\r\nTo: u@corp.example\r\nSubject: inv\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n"
           b"--B\r\nContent-Type: text/plain\r\n\r\nopen\r\n--B\r\nContent-Type: text/html\r\nContent-Disposition: attachment; filename=\"invoice.pdf.html\"\r\n"
           b"Content-Transfer-Encoding: base64\r\n\r\n" + base64.b64encode(html) + b"\r\n--B--\r\n")
    assert any(l.host == "evil-viewer.example" for l in from_bytes(raw).links)  # atob() literal decoded


def test_f3_qr_heuristic_needs_qr_or_both_lures():
    raw = (b"From: Absher <no-reply@absher.sa>\r\nTo: u@corp.example\r\nSubject: otp\r\nMIME-Version: 1.0\r\nContent-Type: multipart/related; boundary=\"B\"\r\n\r\n"
           b"--B\r\nContent-Type: text/html\r\n\r\n<img src=\"cid:logo\"><p>%s</p>\r\n--B\r\nContent-Type: image/png\r\nContent-ID: <logo>\r\n\r\nPNG\r\n--B--\r\n")
    otp_only = from_bytes(raw % b"your verification code is 1234")
    assert "QR_LURE_HEURISTIC" not in {f.code for f in run_all(otp_only)}
    both = from_bytes(raw % b"urgent: verify your account within 24 hours")
    assert "QR_LURE_HEURISTIC" in {f.code for f in run_all(both)}


def test_f4_shared_brand_name_across_two_domains_is_not_a_spoof():
    m = from_bytes(b"From: Fahad via DocuSign <dse@docusign.net>\r\nTo: u@corp.example\r\nSubject: sign\r\nContent-Type: text/plain\r\n\r\nx\r\n")
    assert "DISPLAYNAME_SPOOF" not in {f.code for f in run_all(m)}
    fake = from_bytes(b"From: DocuSign <dse@docusign-secure.example>\r\nTo: u@corp.example\r\nSubject: sign\r\nContent-Type: text/plain\r\n\r\nx\r\n")
    assert {"DISPLAYNAME_SPOOF", "DOMAIN_BRAND_TERM"} <= {f.code for f in run_all(fake)}


def test_f4_oauth_consent_and_iban_change():
    url = ("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=x&response_type=code"
           "&redirect_uri=https%3A%2F%2Fviewer-app.example%2Fcb&scope=openid%20offline_access%20Mail.ReadWrite")
    f = {x.code: x for x in check_links([Link(url, "Open")])}
    assert f["URL_OAUTH_CONSENT"].weight == 40 and "viewer-app.example" in f["URL_OAUTH_CONSENT"].evidence
    legit = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=x&redirect_uri=https%3A%2F%2Fcorp.sharepoint.com%2F"
    assert "URL_OAUTH_CONSENT" not in {x.code for x in check_links([Link(legit)])}
    m = from_bytes(b"From: v@x.example\r\nTo: ap@corp.example\r\nSubject: RE: payment\r\nContent-Type: text/plain\r\n\r\n"
                   b"We have moved our business account. New IBAN: SA44 2000 0001 2345 6789 0123\r\n")
    assert "LURE_BANK_CHANGE" in {x.code for x in check_language(m)}
    ar = from_bytes("From: v@x.example\r\nTo: ap@corp.example\r\nSubject: s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
                    "يرجى التحويل إلى حسابنا الجديد، رقم الآيبان SA03 8000 0000 6080 1016 7519\r\n".encode())
    assert "LURE_BANK_CHANGE" in {x.code for x in check_language(ar)}
    no_change = from_bytes(b"From: v@x.example\r\nTo: ap@corp.example\r\nSubject: s\r\nContent-Type: text/plain\r\n\r\nIBAN unchanged: SA44 2000 0001 2345 6789 0123\r\n")
    assert "LURE_BANK_CHANGE" not in {x.code for x in check_language(no_change)}


def test_ipv6_received_and_stix_escaping():
    raw = (b"Received: from mail.x.example (mail.x.example [IPv6:2001:db8::25]) by mx1.corp.example; Thu, 29 Oct 2026 10:00:00 +0300\r\n"
           b"Received: from [fe80::1] by mail.x.example; Thu, 29 Oct 2026 09:59:00 +0300\r\n"
           b"From: a@x.example\r\nTo: u@corp.example\r\nSubject: s\r\nContent-Type: text/plain\r\n\r\nhi\r\n")
    m = from_bytes(raw)
    assert m.received_ips == ["2001:db8::25"]  # link-local dropped
    r = Result("t.eml", "s", "malicious", 50, [], [], {"email": [], "ip": ["2001:db8::25"], "url": ["https://x.example/a'b\\c"], "domain": [], "file": []}, m)
    pats = [o["pattern"] for o in stix_bundle([r])["objects"]]
    assert "[ipv6-addr:value = '2001:db8::25']" in pats
    assert "[url:value = 'https://x.example/a\\'b\\\\c']" in pats
    json.dumps(stix_bundle([r]))
