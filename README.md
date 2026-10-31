# Phish Triage

L1 SOC triage for reported emails. Feed it `.eml` files, get a verdict (malicious / suspicious / clean), a score with the rules that produced it, extracted IOCs, and the action an L1 analyst takes next.

Stdlib only (Python 3.11+). No model, no API calls unless you opt in. Every point in the score is a named rule with evidence, so the verdict can be checked by a human in a minute.

## Problem

"User reported a phishing email" is the most common ticket in a SOC queue. The work is repetitive: read headers, check SPF/DKIM/DMARC, compare From / Reply-To / Return-Path, look at where the links really go, look at the attachment type, decide, act. Most of that is mechanical. This tool does the mechanical part and leaves the decision visible and explainable.

It is tuned for Saudi lures: Absher fines, SPL / Aramex / SMSA parcel fees, bank OTP alerts, Aramco HR bonuses, SADAD bills, in Arabic and English, with a protected-brand list (`absher.sa`, `my.gov.sa`, `alrajhibank.com.sa`, `stc.com.sa`, `aramco.com`, `sadad.com`, `spl.com.sa`, `aramex.com`, `smsaexpress.com`, plus your own domain).

## Quickstart

```
git clone https://github.com/2m7sn/phish-triage.git && cd phish-triage
pip install -e .[dev]

phish-triage scan corpus/m03_spl_parcel_fee.eml          # one file, table on stdout
phish-triage scan corpus --out out                        # a folder: HTML reports + IOC CSV + STIX
phish-triage eval corpus --out out                        # same, plus metrics against corpus/labels.csv
pytest -q
```

`python -m phish_triage ...` works without installing. Open `out/summary.html` after a run; every row links to a case report.

Optional enrichment: `scan --enrich` queries VirusTotal (`VT_API_KEY`) and URLhaus (`URLHAUS_AUTH_KEY`) for the domains and hashes it found. Off by default, never required, and it does not change the score; results are appended as evidence lines.

## What it checks

| Area | Rules |
|---|---|
| Authentication | `Authentication-Results` and `Received-SPF` parsing: SPF fail/softfail, DKIM fail, DMARC fail/none, header missing. DMARC pass on a non-freemail domain subtracts points. |
| Header alignment | From vs Reply-To, From vs Return-Path (compared on registrable domain), freemail sender, an email address hidden in the display name. |
| Display-name spoofing | "Al Rajhi Bank" or "Saudi Aramco HR" from a domain the brand does not own (incl. gmail/outlook). Arabic names (أبشر, الراجحي, سداد ...) count too. |
| Lookalike domains | Brand name as a label on another domain (`alrajhi-secure.example`), brand domain as a subdomain (`spl.com.sa.track-parcel.example`), edit distance ≤ 1–2 (`alrajhlbank`), punycode/IDN, and confusable mapping across Cyrillic, Greek, Arabic and digit-for-letter (`c0rp`, `aاrajhibank`, `аbsher`). |
| URL tricks | visible text says one domain, href goes to another; bare public IP; `user@host` trick; `data:` / `javascript:` URIs; known shorteners; abuse-heavy TLDs. |
| Attachments | double extension (`invoice.pdf.exe`), HTML/HTM smuggling, `.iso .lnk .one .js .vbs .hta ...`, macro formats (`.docm .xlsm`), legacy OLE Office by magic bytes, archives (more if the body mentions a password). |
| Language | urgency, credential, payment and file-share lures in Arabic and English; QR-code instructions. Each category is one flat 8-point rule so wording alone never makes a verdict. |
| HTML attachments | the first 200 KB of any HTML attachment is read: `<script>`, `location=`, `atob(`, meta refresh, `document.write` add `ATT_HTML_SCRIPT`; URLs inside the file are extracted and go through the URL rules and into the IOCs. |
| Context heuristics | `QR_LURE_HEURISTIC`: inline image + zero clickable links + (QR wording, or credential **and** urgency lures together); the image is not decoded, so this is a shape match. `THREAD_FOREIGN_LINK`: a reply from an external sender whose only link goes to a host that is neither the sender's domain nor a known share/meeting service. |
| OAuth and BEC | `URL_OAUTH_CONSENT` (30, 40 with mail/files scopes): an authorize URL on `login.microsoftonline.com` / `accounts.google.com` whose `redirect_uri` is not the identity provider. `LURE_BANK_CHANGE` (25): a Saudi IBAN or the word IBAN/آيبان together with new-account / changed-bank phrasing, Arabic or English. `DISPLAYNAME_ORG_FREEMAIL` (10): a company name in the display name on a gmail/outlook mailbox. |
| Input handling | `message/rfc822` attachments ("report as attachment") are unwrapped and the inner message is triaged. Unknown charsets fall back to UTF-8 with replacement instead of crashing. Mailing-list traffic softens alignment penalties (SPF/DKIM halved, `DMARC_FAIL` capped at 10, list-domain Reply-To/Return-Path not a mismatch) **only when** SPF passed for a Return-Path on the list's own domain — `List-Id` alone is free to forge and buys nothing. `dmarc=fail (p=none)` gets the same softening. |

Thresholds: score ≥ 45 malicious, ≥ 20 suspicious, else clean. Each rule counts once per message, however many links or attachments trigger it.

IOC hygiene: Received hops from our own domain (`parse.ORG_DOMAIN`) are dropped; clean verdicts export nothing; a gmail/outlook sender address is only exported when it was used to spoof a display name.

## Results (synthetic corpus, 51 emails)

The corpus in `corpus/` is written by `corpus/build_corpus.py`: 23 malicious, 6 suspicious, 22 clean, with ground truth in `corpus/labels.csv`. Links point at `.example` domains and RFC 5737 addresses; attachments are dummy bytes with the right magic numbers. These numbers come from `phish-triage eval corpus` on that corpus and nothing else. They say the rules do what they claim on cases I wrote; they are not a detection rate on real mail.

| Class | Precision | Recall | F1 | n |
|---|---|---|---|---|
| malicious | 0.95 | 0.87 | 0.91 | 23 |
| suspicious | 0.67 | 1.00 | 0.80 | 6 |
| clean | 1.00 | 0.95 | 0.98 | 22 |
| phish vs clean (binary) | 0.97 | 1.00 | 0.98 | 29 |

Accuracy 0.92, macro-F1 0.90 (after review round 2; the first version scored 0.90 / 0.86 on the same files).

Confusion matrix (rows = truth, columns = predicted):

| | malicious | suspicious | clean |
|---|---|---|---|
| malicious | 20 | 3 | 0 |
| suspicious | 0 | 6 | 0 |
| clean | 1 | 0 | 21 |

The one false positive is `c22_forwarded_by_user_auth_broken`: a clean internal notice a user forwarded from gmail, so Return-Path, SPF and DMARC all break (`DMARC_FAIL`, `SPF_FAIL`, `RETURNPATH_MISMATCH`, exactly 45 points). That is a real-world limitation, not a corpus artefact: forwarded mail looks like spoofed mail at the header level.

Misses: a compromised-partner email with clean auth and one lookalike link, a CEO gift-card BEC from gmail, and a generic tax-refund lure all land in **suspicious** rather than malicious (the L1 action is still "hold and verify").

### Review round 1 (`corpus-fresh/`, 8 emails)

A reviewer who had not seen the rules wrote 8 new emails (4 clean, 4 malicious). **Before any fix the tool got 4/8**: a mailing-list post with `dkim=fail`/`dmarc=fail (p=none)` was called malicious, and a QR lure with no links, an HTML attachment with a JavaScript redirect, and a thread hijack from a compromised account were all scored clean.

After the fixes above the same 8 score **7/8** (binary precision 1.00, recall 0.75). This set is no longer held out — the fixes were written with these files in view — so treat 7/8 as a regression check, not a measurement. The remaining miss is `f5_thread_hijack_compromised`: clean SPF/DKIM/DMARC, a real `In-Reply-To`, and one link to an unknown file-share host. It scores 18 (`THREAD_FOREIGN_LINK` 20 + `LURE_SHARE` 8 − `DMARC_PASS` 10), two points under the suspicious threshold. The threshold was deliberately not lowered to catch it; see Limits.

### Review round 2 (`corpus-heldout-r2/`, 10 emails)

A second reviewer wrote 10 new emails (5 clean, 5 malicious) that nobody tuning the rules had seen. **Before any change the tool got 6/10** (binary precision 1.00, recall 0.40, no false positives): a fake DocuSign, an OAuth consent-grant phish and an IBAN-change BEC all scored clean, and `invoice.pdf.html` only reached suspicious because the double-extension branch skipped the content scan. The same reviewer also showed that the round-1 list softening was forgeable: adding `List-Id` plus an attacker Reply-To dropped two corpus phish from 96→73 and 36→21.

After the fixes (list softening gated on SPF + Return-Path alignment, content scan for every HTML attachment, DocuSign/Microsoft/Google in the brand list, `URL_OAUTH_CONSENT`, `LURE_BANK_CHANGE`, `DISPLAYNAME_ORG_FREEMAIL`, stricter QR heuristic) the same 10 score **8/10 exact, 10/10 binary** (precision 1.00, recall 1.00, accuracy 0.80). No longer held out. The two remaining class misses are the OAuth consent phish (38, suspicious) and the IBAN-change BEC (40, suspicious): both come from senders with clean DMARC and no lookalike domain, so the content rules alone stop just short of 45. The L1 action for both is still "hold and verify out of band".

All three corpora run in CI. A fresh held-out set is needed for the next honest number; everything in this repo has now been seen by the person tuning it.

## How to read a verdict

```
malicious  100  m03_spl_parcel_fee.eml   DOMAIN_BRAND_SUBDOMAIN, DISPLAYNAME_SPOOF, DOMAIN_BRAND_TERM
```

Open the case report. The **Why** table lists every rule that fired, its points and the exact evidence (`spl.com.sa appears as subdomain of track-parcel.example`). Negative lines are things in the sender's favour. Below it: headers as parsed, links with visible text vs real destination, attachments with SHA-256, the body as received, and the **L1 action** list:

- malicious: block sender, purge from mailboxes by Message-ID, block URLs, reset credentials if anyone clicked, isolate the host if an attachment was opened, close.
- suspicious: hold, confirm with the sender out of band, search for the same sender/subject, escalate if anyone interacted.
- clean: close, thank the reporter.

IOCs go to `out/iocs.csv` (sender, reply-to, return-path, public IPs from the Received chain, URLs, domains, attachment hashes) and `out/iocs.stix.json`, a hand-built STIX 2.1 bundle of `indicator` objects for anything not scored clean.

## Limits

- Rule-based with hand-set weights. The weights were set once and checked against the synthetic corpus; real mail will move them.
- Forwarded mail breaks SPF/DMARC and is scored as if spoofed (see the FP above). Reporting by attachment preserves the original headers and avoids this.
- Lookalike detection only covers the brands in `rules.BRANDS`. Add your own domain there; `corp.example` is a placeholder.
- No URL fetching, no attachment detonation, no reputation data unless `--enrich` is used. A clean-looking message from a compromised legitimate account scores low: the thread-hijack case in review round 1 is missed (18/20) and will stay missed until sender history or link reputation is available. The OAuth-consent and IBAN-change cases in round 2 reach suspicious, not malicious, for the same reason.
- The bank-change rule needs both an IBAN (or the word) and change wording; a BEC that only says "use the account below" without an IBAN is not caught by it.
- The QR heuristic does not decode the image. It matches the shape of the attack (inline image, no links, lure text), so a newsletter with one hero image and urgent wording could trip it.
- Brand terms on unlisted domains (`sadad.com.sa`, `aramex.com.sa`) are flagged unless added to `rules.RELATED_DOMAINS`; the seed list (`stcpay.com.sa`) is unverified and should be checked per tenant.
- Registrable-domain logic is a short list (`.com.sa`, `.gov.sa`, ...), not the Public Suffix List.
- Language rules are keyword lists, so unusual phrasing is missed and a security-awareness email about phishing collects a few points.
- Synthetic corpus only. There is no real-mail evaluation yet.

## Roadmap

- Ingest from Microsoft 365 (Graph `reportedMessages` / user-reported quarantine) and Gmail API instead of `.eml` on disk.
- Sandbox detonation of attachments and URL follow-through (cuckoo/any.run-style) with the result feeding the score.
- Public Suffix List for registrable domains; a brand list per tenant.
- Real-mail evaluation with analyst labels, then re-weight rules.

## Layout

```
phish_triage/parse.py      .eml -> headers, auth results, Received IPs, links, attachments
phish_triage/rules.py      detection rules, brand list, confusable mapping
phish_triage/triage.py     score, verdict, L1 action, IOC extraction
phish_triage/report.py     HTML case/summary, IOC CSV, STIX 2.1 bundle
phish_triage/evaluate.py   precision / recall / F1, confusion matrix, FP reasons
phish_triage/enrich.py     optional VirusTotal / URLhaus lookups
corpus/build_corpus.py     writes the 51 synthetic .eml files + labels.csv
corpus-fresh/              review round 1 set: 8 reviewer-written emails + labels.csv (4/8 before fixes, 7/8 after)
corpus-heldout-r2/         review round 2 set: 10 reviewer-written emails + labels.csv (6/10 before fixes, 8/10 after)
tests/                     auth parsing, lookalikes (incl. Arabic homoglyph), attachments, end to end, review-round regressions
```

MIT, Abdulmohsen Alharbi.
