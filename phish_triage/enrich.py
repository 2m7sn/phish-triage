"""Optional online enrichment. Off unless --enrich is passed AND an API key is in the environment.
Never required: the verdict does not depend on it. Results are attached as extra evidence only."""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request

from .triage import Result

TIMEOUT = 10


def _get(url: str, headers: dict, data: bytes | None = None) -> dict | None:
    try:
        req = urllib.request.Request(url, data=data, headers=headers)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310 - fixed vendor hosts
            return json.load(resp)
    except Exception:
        return None


def virustotal(r: Result) -> dict[str, str]:
    key = os.environ.get("VT_API_KEY")
    if not key:
        return {}
    out = {}
    h = {"x-apikey": key}
    for d in r.iocs["domain"]:
        if j := _get(f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(d)}", h):
            s = j.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            out[d] = f"VT: {s.get('malicious', 0)} malicious / {s.get('suspicious', 0)} suspicious vendors"
    for f in r.iocs["file"]:
        if j := _get(f"https://www.virustotal.com/api/v3/files/{f['sha256']}", h):
            s = j.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            out[f["sha256"]] = f"VT: {s.get('malicious', 0)} malicious vendors"
    return out


def urlhaus(r: Result) -> dict[str, str]:
    key = os.environ.get("URLHAUS_AUTH_KEY")
    if not key:
        return {}
    out = {}
    for d in r.iocs["domain"]:
        j = _get("https://urlhaus-api.abuse.ch/v1/host/", {"Auth-Key": key}, urllib.parse.urlencode({"host": d}).encode())
        if j and j.get("query_status") == "ok":
            out[d] = f"URLhaus: {j.get('url_count', 0)} known URLs, blacklist {j.get('blacklists', {}).get('spamhaus_dbl', 'n/a')}"
    return out


def enrich(r: Result) -> dict[str, str]:
    return {**virustotal(r), **urlhaus(r)}
