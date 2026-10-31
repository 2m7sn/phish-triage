"""Score, verdict, L1 action and IOC extraction for one mail."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path

from .parse import Mail, domain_of, parse, registrable
from .rules import Finding, run_all

MALICIOUS_AT = 45
SUSPICIOUS_AT = 20


@dataclass
class Result:
    file: str
    subject: str
    verdict: str
    score: int
    findings: list[Finding]
    actions: list[str]
    iocs: dict[str, list]  # kind -> values
    mail: Mail = field(repr=False)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("mail")
        return d


def verdict_for(score: int) -> str:
    return "malicious" if score >= MALICIOUS_AT else "suspicious" if score >= SUSPICIOUS_AT else "clean"


def actions_for(verdict: str, findings: list[Finding], m: Mail) -> list[str]:
    codes = {f.code for f in findings}
    has_link = any(f.code.startswith(("URL_", "DOMAIN_")) for f in findings) or bool(m.links)
    cred = "LURE_CREDENTIAL" in codes or any(c.startswith("DOMAIN_") for c in codes)
    att = any(c.startswith("ATT_") for c in codes)
    if verdict == "malicious":
        steps = [
            f"Block sender {m.from_addr} and its domain at the mail gateway",
            f"Purge the message from every recipient mailbox (search Message-ID {m.message_id or 'n/a'} and the subject)",
        ]
        if has_link:
            steps.append("Block the listed URLs and domains on proxy and DNS; add them to the IOC list")
        if cred:
            steps.append("If anyone clicked or typed a password: reset the password, revoke sessions and MFA tokens, review sign-in logs")
        if att:
            steps.append("If the attachment was opened: isolate the host, pull the EDR timeline, escalate to L2")
        steps.append("Close with verdict 'malicious' and notify the reporter")
        return steps
    if verdict == "suspicious":
        return [
            "Hold the message; do not release to the user",
            "Confirm with the sender through a known channel (phone book, ticket, not the email itself)",
            "Search the gateway for the same sender / subject across other mailboxes",
            "Escalate to L2 if any recipient interacted with it",
        ]
    return ["Close the ticket as benign", "Thank the reporter; no further action"]


def iocs_for(m: Mail, findings: list[Finding]) -> dict[str, list]:
    hosts = sorted({l.host for l in m.links if l.host and not l.host.replace(".", "").isdigit() and ":" not in l.host})
    codes = {f.code for f in findings}
    emails = {a for a in (m.from_addr, m.reply_to, m.return_path) if "@" in a}
    # a plain gmail/outlook address is not an indicator unless it was used to spoof someone
    from .rules import FREEMAIL
    if not codes & {"DISPLAYNAME_SPOOF", "DISPLAYNAME_EMAIL"}:
        emails = {a for a in emails if registrable(domain_of(a)) not in FREEMAIL}
    return {
        "email": sorted(emails),
        "ip": list(m.received_ips),
        "url": [l.href for l in m.links],
        "domain": hosts,
        "file": [{"name": a.name, "size": len(a.data), "sha256": a.sha256, "md5": a.md5} for a in m.attachments],
    }


def triage(path: str | Path) -> Result:
    m = parse(path)
    findings = run_all(m)
    score = max(0, min(100, sum(f.weight for f in findings)))
    v = verdict_for(score)
    return Result(Path(path).name, m.subject, v, score, findings, actions_for(v, findings, m), iocs_for(m, findings), m)
