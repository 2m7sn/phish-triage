"""Detection rules. Each check returns Finding(code, weight, evidence)."""

from __future__ import annotations

import codecs
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlsplit

from .parse import ORG_DOMAIN, Attachment, Link, Mail, domain_of, is_public, registrable

# brand domain -> (display name, terms that identify the brand in a label or display name)
BRANDS: dict[str, tuple[str, list[str]]] = {
    "absher.sa": ("Absher", ["absher", "أبشر"]),
    "my.gov.sa": ("National Unified Portal", ["mygov", "my.gov", "mygovsa"]),
    "alrajhibank.com.sa": ("Al Rajhi Bank", ["alrajhi", "alrajhibank", "الراجحي"]),
    "stc.com.sa": ("stc", ["stc", "mystc"]),
    "aramco.com": ("Saudi Aramco", ["aramco", "أرامكو"]),
    "sadad.com": ("SADAD", ["sadad", "سداد"]),
    "spl.com.sa": ("Saudi Post SPL", ["spl", "saudipost", "البريد السعودي"]),
    "aramex.com": ("Aramex", ["aramex", "أرامكس"]),
    "smsaexpress.com": ("SMSA Express", ["smsa", "smsaexpress"]),
    "docusign.com": ("DocuSign", ["docusign"]),
    "docusign.net": ("DocuSign", ["docusign"]),
    "microsoft.com": ("Microsoft", ["microsoft", "office365", "onedrive", "sharepoint"]),
    "google.com": ("Google", ["google"]),
    ORG_DOMAIN: ("Corp (our organisation)", ["corp"]),
}
# Domains that legitimately carry a brand term. Seed only; verify and extend per tenant.
RELATED_DOMAINS = {"stcpay.com.sa", "microsoftonline.com", "office.com", "live.com", "sharepoint.com", "onedrive.com", "googleapis.com", "gstatic.com"}
FREEMAIL = {"gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "icloud.com", "live.com", "protonmail.com", "proton.me"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "shorturl.at", "goo.gl", "ow.ly", "tiny.cc", "rebrand.ly"}
RISKY_TLDS = {"zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "link", "icu", "cam", "quest", "rest", "buzz", "cfd", "sbs"}
KNOWN_SHARE_HOSTS = {"dropbox.com", "wetransfer.com", "sharepoint.com", "onedrive.live.com", "1drv.ms", "drive.google.com", "docs.google.com", "box.com",
                     "zoom.us", "teams.microsoft.com", "calendly.com", "meet.google.com", "calendar.google.com", "docusign.net", "docusign.com"}
OAUTH_IDP_HOSTS = {"login.microsoftonline.com", "login.live.com", "login.microsoft.com", "accounts.google.com"}
OAUTH_IDP_DOMAINS = {"microsoftonline.com", "microsoft.com", "live.com", "office.com", "sharepoint.com", "google.com"}
OAUTH_RISKY_SCOPES = ("mail.readwrite", "mail.send", "files.readwrite", "mailboxsettings", "offline_access", "https://mail.google.com/", "gmail.")
IBAN_SA_RE = re.compile(r"\bSA\d{2}(?:\s?\d{4}){5}\b|\biban\b|آيبان|ايبان", re.I)
BANK_CHANGE_RE = re.compile(
    r"new (?:bank )?account|moved our (?:business |bank )?account|chang(?:e|ed|ing) (?:of |our |the )?bank|new bank details|bank details (?:have )?changed|"
    r"update (?:our|your|the) (?:vendor |bank |payment )?(?:record|details|information)|remit(?:tance)? to|"
    r"حساب(?:نا)? (?:بنكي )?(?:ال)?جديد|تغيير (?:ال)?حساب|تحديث (?:ال)?حساب|تم تغيير|تم تحديث (?:بيانات|الحساب)", re.I)
ORG_WORDS_RE = re.compile(r"\b(?:est\.?|trading|ltd\.?|llc|inc\.?|co\.?|company|corp\.?|group|holding|bank)\b|مؤسسة|شركة|مجموعة|بنك", re.I)

DANGEROUS_EXT = {"exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "ps1", "msi", "lnk", "iso", "img", "vhd", "vhdx", "one", "chm", "jar", "cpl", "msc", "reg"}
HTML_EXT = {"html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xltm", "ppam", "xlam"}
LEGACY_OFFICE = {"doc", "xls", "ppt", "dot", "xlt", "pps"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tgz", "arj", "cab"}
DECOY_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "csv", "ppt", "pptx"}
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
HTML_SCRIPT_RE = re.compile(r"<script|\blocation(?:\.href|\.replace|\.assign)?\s*[=(]|\batob\s*\(|http-equiv\s*=\s*[\"']?refresh|\bunescape\s*\(|document\.write\s*\(", re.I)

LURES = {
    "urgency": [
        "immediately", "24 hours", "48 hours", "urgent", "suspended", "final notice", "last warning",
        "act now", "expires today", "will be closed", "will be blocked",
        "عاجل", "فوراً", "فورا", "24 ساعة", "٢٤ ساعة", "48 ساعة", "سيتم إيقاف", "سيتم تعليق", "الإشعار الأخير", "آخر تحذير", "ينتهي اليوم",
    ],
    "credential": [
        "verify your account", "confirm your identity", "update your password", "reset your password", "login to confirm",
        "sign in to verify", "verification code", "one-time password", "confirm your account", "validate your account",
        "mfa", "authenticator", "two-factor", "2fa", "re-enrol", "re-enroll",
        "تحقق من حسابك", "تأكيد هويتك", "تحديث كلمة المرور", "رمز التحقق", "تسجيل الدخول للتحقق", "تحديث بياناتك", "تأكيد حسابك",
    ],
    "payment": [
        "unpaid fee", "outstanding fee", "customs fee", "pay the fine", "traffic fine", "outstanding bill", "pending payment",
        "gift card", "wire transfer", "update payment", "delivery fee", "release your parcel",
        "رسوم جمركية", "غرامة", "مخالفة مرورية", "رسوم غير مدفوعة", "فاتورة مستحقة", "بطاقات هدايا", "تحويل عاجل", "رسوم التوصيل", "سداد المبلغ",
    ],
    "share": [
        "shared folder", "shared document", "shared with you", "shared file", "view document", "open shared", "check and confirm",
        "review and sign", "access the document", "مجلد مشترك", "ملف مشترك", "مستند مشترك", "تمت مشاركة",
    ],
}
QR_RE = re.compile(r"\bqr\b|qr code|رمز الاستجابة|رمز qr|امسح الرمز|scan the (?:qr )?code", re.I)
PASSWORD_RE = re.compile(r"password|كلمة المرور|كلمة السر", re.I)
URLISH_RE = re.compile(r"^(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?:[/?#].*)?$", re.I)
REPLY_RE = re.compile(r"^\s*((re|fw|fwd|aw|wg|رد|إعادة توجيه)\s*:\s*)+", re.I)

# Confusables -> ASCII. Cyrillic, Greek, Arabic letters/digits, accented Latin, digit-for-letter.
HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "һ": "h", "ԁ": "d",
    "ɡ": "g", "ѕ": "s", "ԛ": "q", "ԝ": "w", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h", "ё": "e",
    "ο": "o", "α": "a", "ν": "v", "ι": "i", "κ": "k", "ρ": "p", "τ": "t", "υ": "u", "ε": "e",
    "ا": "l", "أ": "l", "إ": "l", "آ": "l", "١": "1", "٠": "0", "٥": "o", "۱": "1", "۰": "0", "۵": "o",
    "ı": "i", "ł": "l", "ſ": "s", "ç": "c", "ğ": "g", "ş": "s",
    "0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s",
})


@dataclass
class Finding:
    code: str
    weight: int
    evidence: str


def fold(s: str) -> str:
    """Lowercase, strip accents, map confusables to ASCII."""
    s = unicodedata.normalize("NFKD", s.lower())
    s = "".join(c for c in s if unicodedata.category(c) != "Mn")
    return s.translate(HOMOGLYPHS)


def edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def decode_label(label: str) -> tuple[str, bool]:
    """Decode an xn-- label. Uses raw punycode so bidi-invalid (mixed-script) labels still decode."""
    if not label.startswith("xn--"):
        return label, False
    try:
        return codecs.decode(label[4:].encode("ascii"), "punycode"), True
    except Exception:
        return label, True


def check_domain(host: str) -> list[Finding]:
    """Lookalike / brand-abuse checks for one hostname."""
    host = host.lower().rstrip(".")
    if not host or host.replace(".", "").isdigit() or ":" in host:
        return []
    reg = registrable(host)
    if reg in BRANDS or reg in RELATED_DOMAINS:
        return []
    labels = host.split(".")
    decoded = [decode_label(l) for l in labels]
    out: list[Finding] = []
    if any(idn for _, idn in decoded):
        out.append(Finding("URL_IDN", 10, f"punycode hostname {host}"))
    prefix = host[: len(host) - len(reg)]  # "spl.com.sa." in "spl.com.sa.track-parcel.example"
    best: Finding | None = None
    for brand, (name, terms) in BRANDS.items():
        if f".{brand}." in f".{prefix}":
            best = Finding("DOMAIN_BRAND_SUBDOMAIN", 30, f"{brand} appears as subdomain of {reg}")
            break
        for label, idn in decoded[:-1]:
            parts = re.split(r"[-_]", label)
            if len(parts) > 1:
                parts.append("".join(parts))  # my-gov-sa -> mygovsa
            for term in terms:
                if not term.isascii():  # Arabic brand name
                    if term in label:
                        best = _max(best, Finding("DOMAIN_HOMOGLYPH", 35, f"{name} written in Arabic inside {host}"))
                    continue
                for part in parts:
                    folded = fold(part)
                    if part == term:
                        best = _max(best, Finding("DOMAIN_BRAND_TERM", 25, f"'{term}' ({name}) in {host}, which is not {brand}"))
                    elif folded == term:
                        best = _max(best, Finding("DOMAIN_HOMOGLYPH", 35, f"'{part}' looks like '{term}' ({name}) after confusable mapping"))
                    elif len(term) >= 5 and edit_distance(folded, term) <= (1 if len(term) < 8 else 2):
                        best = _max(best, Finding("DOMAIN_LOOKALIKE", 30, f"'{part}' is {edit_distance(folded, term)} edit(s) from '{term}' ({name})"))
    if best:
        out.append(best)
    return out


def _max(a: Finding | None, b: Finding) -> Finding:
    return b if a is None or b.weight > a.weight else a


def trusted_list(m: Mail) -> bool:
    """List headers are free to forge. Trust them only when SPF passed for a Return-Path on the list's own domain."""
    return bool(m.list_mail and m.list_domain and m.auth.get("spf") == "pass"
                and "@" in m.return_path and registrable(domain_of(m.return_path)) == m.list_domain)


def _relaxed(m: Mail) -> bool:
    """Verified mailing-list traffic or a DMARC p=none domain: alignment failures are expected noise."""
    return trusted_list(m) or m.auth.get("dmarc_policy") == "none"


def check_auth(m: Mail) -> list[Finding]:
    out = []
    if not m.auth:
        return [Finding("AUTH_MISSING", 5, "no Authentication-Results / Received-SPF header")]
    relaxed = _relaxed(m)
    for k, bad, w in (("spf", {"fail", "softfail", "permerror"}, 15), ("dkim", {"fail", "permerror"}, 10), ("dmarc", {"fail"}, 20)):
        v = m.auth.get(k, "none")
        if v in bad:
            if relaxed:
                w = w // 2 if k != "dmarc" else 10
            out.append(Finding(f"{k.upper()}_FAIL", w, f"{k}={v}" + (" (list / p=none, reduced)" if relaxed else "")))
        elif v == "none" and k == "dmarc":
            out.append(Finding("DMARC_NONE", 5, "no DMARC result"))
    # DMARC pass proves the sending domain, which says nothing when that domain is gmail/outlook/...
    if m.auth.get("dmarc") == "pass" and registrable(m.from_domain) not in FREEMAIL:
        out.append(Finding("DMARC_PASS", -10, f"dmarc=pass for {m.from_domain}"))
    return out


def check_headers(m: Mail) -> list[Finding]:
    out = []
    fd = registrable(m.from_domain) if m.from_domain else ""
    relaxed = _relaxed(m)
    rt, rp = domain_of(m.reply_to), domain_of(m.return_path)
    on_list = lambda d: trusted_list(m) and registrable(d) == m.list_domain  # noqa: E731
    if rt and registrable(rt) != fd and not on_list(rt):
        out.append(Finding("REPLYTO_MISMATCH", 7 if relaxed else 15, f"Reply-To {m.reply_to} vs From {m.from_addr}"))
    if rp and registrable(rp) != fd and not on_list(rp):
        out.append(Finding("RETURNPATH_MISMATCH", 5 if relaxed else 10, f"Return-Path {m.return_path} vs From {m.from_addr}"))
    name = m.from_name or ""
    if fd in FREEMAIL:
        out.append(Finding("FREEMAIL_SENDER", 5, f"sender uses consumer mailbox {fd}"))
        if ORG_WORDS_RE.search(name):
            out.append(Finding("DISPLAYNAME_ORG_FREEMAIL", 10, f"display name '{name}' names a company but the mailbox is {fd}"))
    if (em := re.search(r"[\w.+-]+@[\w.-]+", name)) and em.group(0).lower() != m.from_addr:
        out.append(Finding("DISPLAYNAME_EMAIL", 20, f"display name carries another address: {em.group(0)}"))
    lname = fold(name)
    compact = re.sub(r"[\s.\-_|]", "", lname)  # "Al Rajhi Bank" -> "alrajhibank"
    own_brand = BRANDS[fd][0] if fd in BRANDS else None  # docusign.net and docusign.com share one brand name
    for brand, (bname, terms) in BRANDS.items():
        if fd == brand or bname == own_brand or fd in RELATED_DOMAINS:
            continue
        for term in terms:
            if not term.isascii():
                hit = term in name
            elif len(term) >= 5:
                hit = term in compact
            else:  # short terms (stc, spl, corp) only count against consumer mailboxes
                hit = fd in FREEMAIL and re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", lname)
            if hit:
                out.append(Finding("DISPLAYNAME_SPOOF", 25, f"display name '{name}' claims {bname} but sender is {m.from_domain}"))
                return out + check_domain(m.from_domain)
    return out + check_domain(m.from_domain)


def check_links(links: list[Link]) -> list[Finding]:
    out = []
    for link in links:
        href = link.href
        scheme = urlsplit(href).scheme.lower()
        if scheme in ("data", "javascript"):
            out.append(Finding("URL_DATA_URI", 20, f"{scheme}: link: {href[:60]}"))
            continue
        parts = urlsplit(href)
        host = (parts.hostname or "").lower()
        if parts.username is not None:
            out.append(Finding("URL_USERINFO", 20, f"'@' in URL hides real host {host}: {href}"))
        if (host.replace(".", "").isdigit() or ":" in host) and is_public(host):
            out.append(Finding("URL_IP", 20, f"link to bare IP {href}"))
        if host in SHORTENERS:
            out.append(Finding("URL_SHORTENER", 10, f"URL shortener {host}"))
        if host.rsplit(".", 1)[-1] in RISKY_TLDS:
            out.append(Finding("URL_RISKY_TLD", 10, f"abuse-heavy TLD .{host.rsplit('.', 1)[-1]} in {href}"))
        if (mt := URLISH_RE.match(link.text.strip())) and host and registrable(mt.group(1)) != registrable(host):
            out.append(Finding("URL_TEXT_MISMATCH", 15, f"text says {mt.group(1)} but link goes to {host}"))
        if host in OAUTH_IDP_HOSTS and "oauth2" in parts.path.lower() and "authorize" in parts.path.lower():
            q = parse_qs(parts.query)
            redirect = unquote(q.get("redirect_uri", [""])[0])
            rhost = (urlsplit(redirect).hostname or "").lower()
            if rhost and registrable(rhost) not in OAUTH_IDP_DOMAINS:
                scope = unquote(q.get("scope", [""])[0]).lower()
                risky = [s for s in OAUTH_RISKY_SCOPES if s in scope]
                w = 40 if risky else 30
                out.append(Finding("URL_OAUTH_CONSENT", w, f"OAuth consent at {host} redirects to third-party app {rhost}"
                                   + (f"; scopes: {', '.join(risky)}" if risky else "")))
        out += check_domain(host)
    return out


def check_attachments(atts: list[Attachment], body: str) -> list[Finding]:
    out = []
    for a in atts:
        name = a.name.lower()
        parts = name.split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        if len(parts) >= 3 and ext in DANGEROUS_EXT | HTML_EXT and parts[-2] in DECOY_EXT:
            out.append(Finding("ATT_DOUBLE_EXT", 30, f"{a.name}: '{parts[-2]}' decoy before real .{ext}"))
        elif ext in DANGEROUS_EXT:
            out.append(Finding("ATT_DANGEROUS_TYPE", 30, f"{a.name}: .{ext} is executable/container type"))
        elif ext in HTML_EXT or a.content_type == "text/html":
            out.append(Finding("ATT_HTML", 25, f"{a.name}: HTML attachment (smuggling / local phishing page)"))
        elif ext in MACRO_EXT:
            out.append(Finding("ATT_MACRO", 25, f"{a.name}: macro-enabled Office format"))
        elif ext in LEGACY_OFFICE and a.data.startswith(OLE_MAGIC):
            out.append(Finding("ATT_OLE_LEGACY", 20, f"{a.name}: legacy OLE Office file (can carry VBA)"))
        elif ext in ARCHIVE_EXT:
            if PASSWORD_RE.search(body):
                out.append(Finding("ATT_ARCHIVE_PASSWORD", 20, f"{a.name}: archive and body mentions a password"))
            else:
                out.append(Finding("ATT_ARCHIVE", 10, f"{a.name}: archive attachment"))
        # content scan runs for every HTML-ish attachment, including invoice.pdf.html caught above as a double extension
        if (ext in HTML_EXT or a.content_type == "text/html") and (hit := HTML_SCRIPT_RE.search(a.data[:200_000].decode("utf-8", "replace"))):
            out.append(Finding("ATT_HTML_SCRIPT", 20, f"{a.name}: contains '{hit.group(0).strip()}' (script / redirect / decoder)"))
    return out


def check_language(m: Mail) -> list[Finding]:
    text = f"{m.subject}\n{m.text}".lower()
    out = []
    for cat, words in LURES.items():
        hits = [w for w in words if w in text]
        if hits:
            out.append(Finding(f"LURE_{cat.upper()}", 8, ", ".join(hits[:4])))
    if QR_RE.search(text):
        out.append(Finding("LURE_QR", 10, "asks the reader to scan a QR code"))
    if (iban := IBAN_SA_RE.search(text)) and (chg := BANK_CHANGE_RE.search(text)):
        out.append(Finding("LURE_BANK_CHANGE", 25, f"bank account change request: '{chg.group(0)}' with {iban.group(0)[:12]}"))
    return out


def check_context(m: Mail, findings: list[Finding]) -> list[Finding]:
    """Heuristics that combine signals. Both are approximations and say so in their evidence."""
    out = []
    codes = {f.code for f in findings}
    http_links = [l for l in m.links if l.host]
    # QR lure: an inline image, no clickable links, and the text pushes for credentials or urgency.
    # The image itself is not decoded, so this is a shape match, not proof of a QR code.
    if m.inline_images and not http_links and ("LURE_QR" in codes or {"LURE_CREDENTIAL", "LURE_URGENCY"} <= codes):
        out.append(Finding("QR_LURE_HEURISTIC", 20, f"{m.inline_images} inline image(s), zero links, lure text present (image not decoded)"))
    # Thread hijack from a compromised account: a reply from an external sender whose only link
    # goes to a third-party host that is neither the sender's domain nor a known share service.
    fd = registrable(m.from_domain) if m.from_domain else ""
    is_reply = bool(m.in_reply_to) or bool(REPLY_RE.match(m.subject))
    if is_reply and fd and fd != ORG_DOMAIN and fd not in FREEMAIL:
        foreign = [l for l in http_links if registrable(l.host) not in (fd, ORG_DOMAIN) and registrable(l.host) not in KNOWN_SHARE_HOSTS]
        if foreign and len(foreign) == len(http_links):
            out.append(Finding("THREAD_FOREIGN_LINK", 20, f"reply thread from {fd} links only to {foreign[0].host}"))
    return out


def run_all(m: Mail) -> list[Finding]:
    found = check_auth(m) + check_headers(m) + check_links(m.links) + check_attachments(m.attachments, m.text) + check_language(m)
    found += check_context(m, found)
    if m.wrapper_from:
        found.append(Finding("REPORTED_AS_ATTACHMENT", 0, f"analysed the inner message; wrapper sent by {m.wrapper_from}"))
    merged: dict[str, Finding] = {}
    for f in found:  # one line per rule; keep the heaviest and join evidence
        if f.code in merged:
            if f.evidence not in merged[f.code].evidence:
                merged[f.code].evidence += "; " + f.evidence
        else:
            merged[f.code] = Finding(f.code, f.weight, f.evidence)
    return sorted(merged.values(), key=lambda f: -f.weight)
