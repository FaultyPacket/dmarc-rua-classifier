# FaultyPacket™ dmarc-rua-classifier

**Who reads your DMARC reports, and are they allowed to?** A small Python 3
tool that answers both from public DNS.

DMARC aggregate (`rua`) reports list the IP addresses that sent mail as your
domain, with volumes and pass/fail results. They go to whoever is named in your
`_dmarc` TXT record. This tool lists those destinations and puts each into a
generic tier, so you can see where your reports go.

## Install

```bash
pip install -r requirements.txt   # dnspython, publicsuffixlist (pinned)
```

## Usage

```bash
# classify where rua reports go (1.0 behaviour)
python3 dmarc_rua_classifier.py domains.txt --out results.csv
python3 dmarc_rua_classifier.py domains.txt --providers providers.csv --delay 1.5

# check your own domain(s)
python3 dmarc_rua_classifier.py --check example.com
python3 dmarc_rua_classifier.py --check -f domains.txt --json out.json --out out.csv
cat list.txt | python3 dmarc_rua_classifier.py --check -q --doh
```

Inputs can be domains, URLs or email addresses, as arguments, from
`-f/--file` (repeatable, `-` = stdin), or piped in. Lines starting `#` are
ignored; duplicates are removed. A positional argument that is an existing
file is read as a list. Exit status is 1 if any domain fails or any input is
invalid, so it can gate CI.

DNS goes to your system resolver on port 53 by default. `--resolver IP` picks
one; `--doh` uses a DNS-over-HTTPS JSON API (`--doh-url` to choose the endpoint).

## Check mode (`--check`)

DMARC is now RFC 9989 (May 2026), which obsoletes RFC 7489 and RFC 9091.
Aggregate reports are RFC 9990, failure reports RFC 9991. Section numbers
below were checked against the RFC Editor text, including verified erratum
9150 (RFC 9989 points to RFC 9990 section 4, not 3, for external
verification).

| Check | Reference |
|---|---|
| `v=DMARC1` first, value case-sensitive; near-miss records (`v=dmarc1`) reported | RFC 9989 4.7 |
| More than one record at a name: all discarded | RFC 9989 4.10 step 2 |
| `p`, `sp`, `np`, `adkim`, `aspf`, `psd` (y/n/u), `t` (y/n) values; missing `p` treated as `p=none` | RFC 9989 4.7, 4.10.1 |
| `fo` grammar: `0` and `1` mutually exclusive, `d`/`s` at most once | RFC 9989 4.8 |
| `pct`, `rf`, `ri` flagged as historic (receivers ignore them); `pct` below 100 is a warning because the full policy now applies | RFC 9989 9.3, A.6 |
| `!size` on report URIs flagged as obsolete | RFC 9989 4.8 |
| Policy discovery: own record, else Organizational Domain, else PSD record | RFC 9989 4.10.1 |
| Organizational Domain by **DNS Tree Walk** (at most 8 queries); legacy PSL answer kept for comparison and differences reported | RFC 9989 4.10, 4.10.2 |
| Parent public suffix publishing a record without `psd=y` (suggests `psd=n`) | RFC 9989 5.2, 11.8 |
| **External destination verification** for every `rua` and `ruf` address | RFC 9990 4; RFC 9991 5 |

External destination verification: when a report address's Organizational
Domain differs from the policy domain's, the destination must publish a TXT
record starting `v=DMARC1` at

```
<your-domain>._report._dmarc.<destination-host>
```

If it does not, compliant receivers ignore that URI. Nothing errors anywhere;
the reports just never arrive. The tool shows the exact name it queried.
Wildcards (`*._report._dmarc.<host>`) are resolved by DNS and count.

Why Tree Walk vs PSL matters: RFC 9989 drops the Public Suffix List. A
receiver walks up `_dmarc` names and picks the record with the fewest labels
unless a record says `psd=y` or `psd=n`. If a public suffix above you publishes
a DMARC record without `psd=y`, RFC 9989 receivers treat that suffix as your
Organizational Domain, which changes relaxed alignment and which report
addresses count as external. Legacy RFC 7489 receivers still use the PSL, so
both answers are shown when they differ.

Classify by the company, not by the TLD. A hostname is never evidence of
headquarters either way: an EU-region hostname of a recognised provider is
counted by its parent company, and an EU-headquartered provider must **never** be counted
as US (T4). Give EU-headquartered providers an EU hq_country so they land in T3.
If you can't establish a provider's headquarters, leave it out of
`providers.csv` so it stays T5 (unclassified) rather than guessing.

## What it does and doesn't do

- Classify mode makes one `_dmarc` TXT query per domain, with a 1 s default
  delay. Check mode adds up to 8 Tree Walk queries per name (cached) and one
  per external destination.
- It reads public DNS only. It doesn't connect to mail servers or websites.
- Output is a snapshot with a UTC timestamp. DNS changes all the time.

## Limitations

- No DNSSEC validation; it trusts the resolver.
- A subdomain with no record is reported with the record that applies
  (Organizational Domain or PSD); that record's tags are not re-validated.
  Run `--check` on that domain.
- Verification checks that a `v=DMARC1` record exists at the
  `_report._dmarc` name. It does not apply `rua` overrides a destination may
  publish there (RFC 9990 4 step 9).
- The legacy comparison depends on the bundled Public Suffix List snapshot
  (pinned in `requirements.txt`).
- Receivers still on RFC 7489 behave differently (PSL, `pct`). The tool
  reports RFC 9989 behaviour and shows the PSL answer where it differs.
- It cannot see whether reports are actually delivered or read.

## Tests

`pip install -r requirements-dev.txt && python -m pytest -q tests` runs the
offline suite (fake DNS; no network). CI runs it on Python 3.10, 3.12, 3.13.

Live check, 29 Oct 2026 10:42 UTC, 54 public UK and global domains, DoH,
RFC 9989 rules: 39 had at least one external report destination (73
destinations), all authorised. 28 of 54 records still carry historic tags
(`pct` in 26, `ri` in 6, `rf` in 3); 25 of the 26 are `pct=100`, which changes nothing, and 1 is a partial value whose meaning is now gone. For 12 domains, all under one public
suffix whose record lacks `psd=y`, the Tree Walk and the PSL disagree on the
Organizational Domain. (The same set under the PSL rules gave 43 domains and 81
external destinations, also all authorised; the difference is that Tree Walk.)

## Data

`aggregate_uk_councils_2026-10-29.csv` holds the aggregate results of a scan of
366 UK local council email domains, observed 29 Oct 2026. It contains no council
names. The tiers come from FaultyPacket's own dated classification of each
provider's headquarters. They are indicative only.

Headline (29 Oct 2026): 94 of 366 domains (25.7%; 26.6% of the 353 with rua)
send rua to at least one US-HQ or US/global-parent provider. Of the 94, 69
use at least one provider with a US head office; the other 25 use only
providers with a US/global parent. EU-region hosts of recognised providers
(15 domains) are counted by parent company; excluding them would give 81.
Hostnames not yet attributed stay unclassified (T5).

Write-up: https://faultypacket.co.uk/research/dmarc-reports

Made by FaultyPacket™: https://faultypacket.co.uk

---

## Licence

AGPL-3.0-or-later. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Copyright (c) 2026 FaultyPacket. FaultyPacket™ — https://faultypacket.co.uk
