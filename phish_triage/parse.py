"""Turn an .eml file into a flat, inspectable structure. Stdlib only."""

from __future__ import annotations

import base64
import binascii
import email
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from email import policy
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

ORG_DOMAIN = "corp.example"  # our own mail domain; Received hops from here are not IOCs
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6 = re.compile(r"(?<![\w:])(?:IPv6:)?((?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{1,4})(?![\w:])", re.I)
URL_RE = re.compile(r"(?:https?://|data:|javascript:)[^\s<>\"')\]]+", re.I)
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)
DMARC_POLICY_RE = re.compile(r"dmarc\s*=\s*\w+\s*\([^)]*\bp=(\w+)", re.I)
CC_SLD = {"com", "gov", "edu", "org", "net", "med", "sch", "co", "ac"}
HTML_ATT_EXT = (".html", ".htm", ".shtml", ".xhtml", ".mht", ".mhtml", ".svg")
# Explicit non-routable list instead of ip.is_global: Python treats RFC 5737 documentation
# ranges (used by the synthetic corpus) as non-global, which would hide every test IP.
_NON_PUBLIC = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "::ffff:0:0/96")]


def is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(a in n for n in _NON_PUBLIC if n.version == a.version)


@dataclass
class Link:
    href: str
    text: str = ""

    @property
    def host(self) -> str:
        return (urlsplit(self.href).hostname or "").lower()


@dataclass
class Attachment:
    name: str
    data: bytes
    content_type: str = ""

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    @property
    def md5(self) -> str:
        return hashlib.md5(self.data).hexdigest()


@dataclass
class Mail:
    path: str
    subject: str = ""
    from_name: str = ""
    from_addr: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: list[str] = field(default_factory=list)
    date: str = ""
    message_id: str = ""
    in_reply_to: str = ""
    list_mail: bool = False  # List-Id / List-Unsubscribe / List-Post present
    list_domain: str = ""  # registrable domain of the list (from List-Id or List-Unsubscribe)
    wrapper_from: str = ""  # set when the .eml was a "report as attachment" wrapper
    auth: dict[str, str] = field(default_factory=dict)  # spf/dkim/dmarc -> result, dmarc_policy
    received_ips: list[str] = field(default_factory=list)  # origin first, public, not our own hops
    text: str = ""
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    inline_images: int = 0

    @property
    def from_domain(self) -> str:
        return domain_of(self.from_addr)


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(" >") if "@" in addr else ""


def registrable(host: str) -> str:
    """Naive eTLD+1: keeps three labels for ccTLD second levels like .com.sa / .gov.sa."""
    labels = host.lower().rstrip(".").split(".")
    if len(labels) >= 3 and labels[-2] in CC_SLD and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


class _Anchors(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[Link] = []
        self.text: list[str] = []
        self._href: str | None = None
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._buf = []
        elif tag in ("br", "p", "div", "tr", "li"):
            self.text.append("\n")

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append(Link(self._href.strip(), " ".join("".join(self._buf).split())))
            self._href = None

    def handle_data(self, data):
        if self._href is not None:
            self._buf.append(data)
        self.text.append(data)


def _auth_results(msg) -> dict[str, str]:
    out: dict[str, str] = {}
    for hdr in msg.get_all("Authentication-Results", []):
        for k, v in AUTH_RE.findall(hdr):
            out.setdefault(k.lower(), v.lower())
        if (pol := DMARC_POLICY_RE.search(hdr)) and "dmarc_policy" not in out:
            out["dmarc_policy"] = pol.group(1).lower()
    spf = msg.get("Received-SPF")
    if spf and "spf" not in out:
        out["spf"] = spf.split()[0].lower().rstrip(";")
    return out


def _received_ips(msg) -> list[str]:
    ips: list[str] = []
    for hdr in reversed(msg.get_all("Received", [])):  # bottom header = first hop
        hdr = " ".join(str(hdr).split())
        sender = re.match(r"from\s+([^\s(\[;]+)", hdr, re.I)
        if sender and (sender.group(1).lower() == ORG_DOMAIN or sender.group(1).lower().endswith("." + ORG_DOMAIN)):
            continue  # our own relay hop
        for ip in IPV4.findall(hdr) + IPV6.findall(hdr):
            if is_public(ip) and ip not in ips:
                ips.append(ip)
    return ips


def _text(part) -> str:
    try:
        return part.get_content()
    except (LookupError, UnicodeDecodeError):  # unknown charset: do not kill the run
        return (part.get_payload(decode=True) or b"").decode("utf-8", "replace")


def _inner_message(msg):
    """'Report as attachment': the mail of interest is the message/rfc822 part, not the wrapper."""
    for part in msg.walk():
        if part.get_content_type() == "message/rfc822":
            inner = part.get_payload()
            return inner[0] if isinstance(inner, list) else inner
    return None


def parse(path: str | Path) -> Mail:
    return from_bytes(Path(path).read_bytes(), str(path))


def from_bytes(raw: bytes, path: str = "") -> Mail:
    msg = email.message_from_bytes(raw, policy=policy.default)
    wrapper = ""
    if inner := _inner_message(msg):
        wrapper = parseaddr(str(msg.get("From", "")))[1].lower()
        msg = inner
    m = Mail(path=path, wrapper_from=wrapper)
    m.subject = str(msg.get("Subject", "")).strip()
    m.from_name, m.from_addr = parseaddr(str(msg.get("From", "")))
    m.from_addr = m.from_addr.lower()
    m.reply_to = parseaddr(str(msg.get("Reply-To", "")))[1].lower()
    m.return_path = parseaddr(str(msg.get("Return-Path", "")))[1].lower()
    m.to = [a.lower() for _, a in getaddresses([str(msg.get("To", ""))]) if a]
    m.date = str(msg.get("Date", ""))
    m.message_id = str(msg.get("Message-ID", "")).strip()
    m.in_reply_to = str(msg.get("In-Reply-To", "") or msg.get("References", "")).strip()
    m.list_mail = any(msg.get(h) for h in ("List-Id", "List-Unsubscribe", "List-Post"))
    if lid := re.search(r"<([^>]+)>", str(msg.get("List-Id", ""))):
        m.list_domain = registrable(lid.group(1).split("@")[-1])
    elif lu := re.search(r"https?://([^/>\s]+)", str(msg.get("List-Unsubscribe", ""))):
        m.list_domain = registrable(lu.group(1))
    m.auth = _auth_results(msg)
    m.received_ips = _received_ips(msg)

    texts, htmls, att_html = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        fname = part.get_filename()
        ctype = part.get_content_type()
        if ctype.startswith("image/") and (part.get("Content-ID") or part.get_content_disposition() == "inline"):
            m.inline_images += 1
        if fname or part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True) or b""
            m.attachments.append(Attachment(fname or "unnamed", payload, ctype))
            if (fname or "").lower().endswith(HTML_ATT_EXT) or ctype == "text/html":
                att_html.append((fname or "unnamed", payload[:200_000].decode("utf-8", "replace")))
        elif ctype == "text/plain":
            texts.append(_text(part))
        elif ctype == "text/html":
            htmls.append(_text(part))

    seen: set[str] = set()
    for h in htmls:
        p = _Anchors()
        p.feed(h)
        for link in p.links:
            if link.href and link.href not in seen:
                seen.add(link.href)
                m.links.append(link)
        if not texts:
            texts.append("".join(p.text))
    m.text = "\n".join(texts).strip()
    for url in URL_RE.findall(m.text + "\n" + "\n".join(htmls)):
        url = url.rstrip(".,;")
        if url not in seen:
            seen.add(url)
            m.links.append(Link(url))
    for name, content in att_html:  # URLs inside HTML attachments are links too, incl. atob("...") literals
        decoded = []
        for b64 in re.findall(r"atob\s*\(\s*[\"']([A-Za-z0-9+/=]{8,})[\"']", content):
            try:
                decoded.append(base64.b64decode(b64 + "=" * (-len(b64) % 4)).decode("utf-8", "replace"))
            except (ValueError, binascii.Error):
                pass
        for url in URL_RE.findall(content + "\n" + "\n".join(decoded)):
            url = url.rstrip(".,;\"'")
            if url not in seen:
                seen.add(url)
                m.links.append(Link(url, f"[inside attachment {name}]"))
    return m
