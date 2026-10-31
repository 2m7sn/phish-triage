"""HTML case reports, run summary, IOC CSV and STIX 2.1 bundle. No templates engine, no deps."""

from __future__ import annotations

import csv
import json
import uuid
from datetime import datetime, timezone
from html import escape as e
from pathlib import Path

from . import __version__
from .triage import Result

CSS = """
:root{--bg:#262626;--fg:#e4e4e4;--mute:#9a9a9a;--line:#3d3d3d;--acc:#a68af9;--bad:#f0716f;--warn:#e8b04a;--ok:#7cc47f}
html{background:var(--bg)}
body{margin:0 auto;padding:24px 16px 48px;max-width:920px;color:var(--fg);font:14px/1.5 -apple-system,"Segoe UI",Roboto,Arial,sans-serif}
h1{font-size:20px;line-height:1.3;margin:0 0 4px;font-weight:600}
h2{font-size:15px;margin:28px 0 8px;font-weight:600;border-bottom:1px solid var(--line);padding-bottom:4px}
p{margin:6px 0} a{color:var(--acc)}
.wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;margin:6px 0}
th,td{border:1px solid var(--line);padding:4px 8px;text-align:left;vertical-align:top}
th{color:var(--mute);font-weight:500;white-space:nowrap}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.mono{font-family:ui-monospace,Consolas,"Cascadia Mono",monospace;font-size:13px;overflow-wrap:anywhere}
.nw{white-space:nowrap;word-break:normal}
.v-malicious{color:var(--bad);font-weight:600}.v-suspicious{color:var(--warn);font-weight:600}.v-clean{color:var(--ok);font-weight:600}
.neg{color:var(--ok)}
.body{white-space:pre-wrap;border:1px solid var(--line);padding:8px 10px;max-height:320px;overflow:auto;word-break:break-word}
.meta{color:var(--mute);font-size:12px}
ol,ul{padding-inline-start:20px;margin:6px 0}
"""


def _page(title: str, body: str) -> str:
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>{e(title)}</title><style>{CSS}</style></head><body>{body}"
            f'<p class="meta">phish-triage {__version__} · generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC · synthetic corpus, no live indicators</p></body></html>')


def _table(headers: list[str], rows: list[list[str]], numeric: set[int] = frozenset()) -> str:
    if not rows:
        return "<p class=meta>none</p>"
    th = "".join(f'<th{" class=n" if i in numeric else ""}>{e(h)}</th>' for i, h in enumerate(headers))
    trs = "".join("<tr>" + "".join(f'<td{" class=n" if i in numeric else ""}>{c}</td>' for i, c in enumerate(r)) + "</tr>" for r in rows)
    return f'<div class=wrap><table><thead><tr>{th}</tr></thead><tbody>{trs}</tbody></table></div>'


def _v(verdict: str) -> str:
    return f'<span class="v-{verdict}">{verdict}</span>'


def case_html(r: Result) -> str:
    m = r.mail
    auth = ", ".join(f"{k}={v}" for k, v in m.auth.items()) or "no Authentication-Results header"
    why = [[f'<span{" class=neg" if f.weight < 0 else ""}>{f.weight:+d}</span>', f'<span class="mono nw">{e(f.code)}</span>', f'<span dir=auto>{e(f.evidence)}</span>'] for f in r.findings]
    headers = [
        ["From", f'<bdi dir=auto>{e(m.from_name)}</bdi> <span class=mono>&lt;{e(m.from_addr)}&gt;</span>'],
        ["Reply-To", f'<span class=mono>{e(m.reply_to) or "—"}</span>'],
        ["Return-Path", f'<span class=mono>{e(m.return_path) or "—"}</span>'],
        ["To", f'<span class=mono>{e(", ".join(m.to))}</span>'],
        ["Date", e(m.date)],
        ["Message-ID", f'<span class=mono>{e(m.message_id)}</span>'],
        ["Authentication", f'<span class=mono>{e(auth)}</span>'],
        ["Received path (public IPs, origin first)", f'<span class=mono>{e(" → ".join(m.received_ips) or "—")}</span>'],
    ]
    links = [[f'<bdi dir=auto>{e(l.text) or "—"}</bdi>', f'<span class=mono>{e(l.href)}</span>', f'<span class=mono>{e(l.host) or "—"}</span>'] for l in m.links]
    atts = [[f'<bdi dir=auto>{e(a.name)}</bdi>', f"{len(a.data):,}", f'<span class=mono>{a.sha256}</span>'] for a in m.attachments]
    body = f"""
<p class=meta><a href="../summary.html">← summary</a> · {e(r.file)}</p>
<h1 dir=auto>{e(r.subject) or "(no subject)"}</h1>
<p>Verdict: {_v(r.verdict)}, score {r.score}/100 from {len(r.findings)} rule{"s" if len(r.findings) != 1 else ""}.
Sender <span class=mono>{e(m.from_addr)}</span>, {len(m.links)} link{"s" if len(m.links) != 1 else ""}, {len(m.attachments)} attachment{"s" if len(m.attachments) != 1 else ""}.</p>
<h2>L1 action</h2><ol>{"".join(f"<li>{e(s)}</li>" for s in r.actions)}</ol>
<h2>Why</h2>{_table(["Points", "Rule", "Evidence"], why, {0})}
<h2>Headers</h2>{_table(["Header", "Value"], [[e(k), v] for k, v in headers])}
<h2>Links</h2>{_table(["Visible text", "Destination", "Host"], links)}
<h2>Attachments</h2>{_table(["Name", "Bytes", "SHA-256"], atts, {1})}
<h2>Body as received</h2><div class=body dir=auto>{e(m.text[:4000]) or "(empty)"}</div>
"""
    return _page(f"{r.verdict}: {r.subject}", body)


def summary_html(results: list[Result], labels: dict[str, str] | None, metrics: dict | None, source: str) -> str:
    counts = {v: sum(r.verdict == v for r in results) for v in ("malicious", "suspicious", "clean")}
    rows = []
    for r in sorted(results, key=lambda r: (-r.score, r.file)):
        top = r.findings[0].code if r.findings else "—"
        row = [_v(r.verdict), str(r.score), f'<a href="cases/{e(Path(r.file).stem)}.html" class="mono nw">{e(r.file)}</a>', f'<bdi dir=auto>{e(r.subject)}</bdi>', f'<span class="mono nw">{e(top)}</span>']
        if labels:
            t = labels.get(r.file, "?")
            row.append(_v(t) if t == r.verdict else f'<span class=mono>{e(t)}</span> ≠')
        rows.append(row)
    hdr = ["Verdict", "Score", "File", "Subject", "Top rule"] + (["Truth"] if labels else [])
    body = f"""
<h1>Phish Triage — run summary</h1>
<p class=meta>{len(results)} .eml files from <span class=mono>{e(source)}</span>. Rules are explained in each case report; thresholds: suspicious ≥ 20, malicious ≥ 45.</p>
<p>{counts["malicious"]} malicious, {counts["suspicious"]} suspicious, {counts["clean"]} clean. IOCs exported to <a href="iocs.csv">iocs.csv</a> and <a href="iocs.stix.json">iocs.stix.json</a>.</p>
<h2>All messages</h2>{_table(hdr, rows, {1})}
"""
    if metrics:
        cls = metrics["classes"]
        per = [[e(c), f"{cls[c]['precision']:.2f}", f"{cls[c]['recall']:.2f}", f"{cls[c]['f1']:.2f}", str(cls[c]["support"])] for c in cls]
        b = metrics["binary"]
        per.append(["phish vs clean (binary)", f"{b['precision']:.2f}", f"{b['recall']:.2f}", f"{b['f1']:.2f}", str(b["support"])])
        order = ["malicious", "suspicious", "clean"]
        cm = [[f"truth {t}"] + [str(metrics["confusion"][t][p]) for p in order] for t in order]
        fp = [[f'<span class=mono>{e(c)}</span>', str(n)] for c, n in metrics["fp_reasons"]]
        mis = [[f'<a href="cases/{e(Path(f).stem)}.html" class="mono nw">{e(f)}</a>', _v(t), _v(p), str(s)] for f, t, p, s in metrics["misclassified"]]
        body += f"""
<h2>Evaluation against ground truth (synthetic corpus)</h2>
<p>Accuracy {metrics["accuracy"]:.2f}, macro-F1 {metrics["macro_f1"]:.2f} over {metrics["n"]} labelled messages. Binary row treats malicious and suspicious as one "phish" class.</p>
{_table(["Class", "Precision", "Recall", "F1", "Support"], per, {1, 2, 3, 4})}
<h2>Confusion matrix (rows = truth, columns = predicted)</h2>
{_table(["", "malicious", "suspicious", "clean"], cm, {1, 2, 3})}
<h2>Rules that drove false positives</h2>
<p class=meta>Counted over messages labelled clean but scored suspicious or malicious.</p>
{_table(["Rule", "Hits"], fp, {1})}
<h2>Misclassified</h2>{_table(["File", "Truth", "Predicted", "Score"], mis, {3})}
"""
    return _page("Phish Triage summary", body)


def iocs_csv(results: list[Result], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["type", "value", "context", "file", "verdict", "score"])
        for r in results:
            if r.verdict == "clean":
                continue
            for kind, vals in r.iocs.items():
                for v in vals:
                    if kind == "file":
                        w.writerow(["sha256", v["sha256"], v["name"], r.file, r.verdict, r.score])
                    else:
                        w.writerow([kind, v, "", r.file, r.verdict, r.score])


def stix_bundle(results: list[Result]) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    pat = {"email": "email-addr:value", "ip": "ipv4-addr:value", "url": "url:value", "domain": "domain-name:value"}
    esc = lambda s: s.replace("\\", "\\\\").replace("'", "\\'")  # noqa: E731 - STIX pattern string literal
    objs, seen = [], set()
    for r in results:
        if r.verdict == "clean":
            continue
        for kind, vals in r.iocs.items():
            for v in vals:
                if kind == "file":
                    pattern = f"[file:hashes.'SHA-256' = '{v['sha256']}']"
                else:
                    obj = "ipv6-addr:value" if kind == "ip" and ":" in v else pat[kind]
                    pattern = f"[{obj} = '{esc(v)}']"
                if pattern in seen:
                    continue
                seen.add(pattern)
                objs.append({
                    "type": "indicator", "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, pattern)}",
                    "created": now, "modified": now, "valid_from": now,
                    "name": f"{kind} from {r.file} ({r.verdict})",
                    "indicator_types": ["malicious-activity"] if r.verdict == "malicious" else ["anomalous-activity"],
                    "pattern": pattern, "pattern_type": "stix",
                    "confidence": min(100, r.score),
                    "labels": [f.code.lower() for f in r.findings if f.weight > 0][:5],
                })
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}


def write_all(results: list[Result], out: Path, source: str, labels: dict[str, str] | None = None, metrics: dict | None = None) -> None:
    (out / "cases").mkdir(parents=True, exist_ok=True)
    for r in results:
        (out / "cases" / f"{Path(r.file).stem}.html").write_text(case_html(r), encoding="utf-8")
    (out / "summary.html").write_text(summary_html(results, labels, metrics, source), encoding="utf-8")
    iocs_csv(results, out / "iocs.csv")
    (out / "iocs.stix.json").write_text(json.dumps(stix_bundle(results), indent=1, ensure_ascii=False), encoding="utf-8")
    (out / "results.json").write_text(json.dumps([r.to_dict() for r in results], indent=1, ensure_ascii=False), encoding="utf-8")
    if metrics:
        (out / "eval.json").write_text(json.dumps(metrics, indent=1), encoding="utf-8")
