# dmarc-rua-classifier

**Who reads your DMARC reports?** A small, dependency-free Python 3 script that
answers that from public DNS.

DMARC aggregate (`rua`) reports list the IP addresses that sent mail as your
domain, with volumes and pass/fail results. They go to whoever is named in your
`_dmarc` TXT record. This tool lists those destinations and puts each into a
generic tier, so you can see where your reports go.

## Usage

```bash
python3 dmarc_rua_classifier.py domains.txt --out results.csv
python3 dmarc_rua_classifier.py domains.txt --providers providers.csv --delay 1.5
```

`domains.txt` has one domain per line. Lines starting with `#` are ignored.

## Tiers

| Tier | Meaning | How it is decided |
|---|---|---|
| T0 | Self-hosted | rua domain equals, or is a subdomain or parent of, the queried domain |
| T1 | Government | rua domain ends in a government suffix (`.gov.uk`, `.gov`, ...) |
| T2 | Bundled infrastructure | your `providers.csv` marks it `bundled_infrastructure` |
| T3 | UK/EU-headquartered provider | your `providers.csv` gives hq_country GB or an EU state |
| T4 | Other-country-headquartered provider (e.g. US) | your `providers.csv` gives another country |
| T5 | Unclassified | third party not in your `providers.csv` (TLD hint shown) |

**No provider list ships with this tool, on purpose.** Where a company has its
headquarters is a judgement call, and it changes with acquisitions. Write your
own `providers.csv`, date it, and publish it with your results:

```csv
suffix,type,hq_country
reports.example-provider.com,dmarc_saas,US
mail.example-gateway.net,bundled_infrastructure,US
```

A vendor-neutral template is included as `providers.example.csv` (placeholder
hostnames only). To use it:

1. `cp providers.example.csv providers-YYYY-MM-DD.csv` and put the date you
   researched each provider in the filename.
2. Replace the placeholder rows with real rua hostname suffixes. `type` is
   `dmarc_saas` or `bundled_infrastructure`; `hq_country` is the ISO code of the
   company's headquarters (or ultimate parent, if that is your rule) on that date.
3. Run with `--providers providers-YYYY-MM-DD.csv` and publish that file, the
   run's UTC timestamp and the resolver alongside your totals so others can
   reproduce or challenge them.

Self-hosted (T0) means the rua host is the scanned domain itself or one of its
subdomains. A report address on a different organisation's domain is not T0.

Classify by the company, not by the TLD. A hostname is never evidence of
headquarters either way: an EU-region hostname of a recognised provider is
counted by its parent company, and an EU-headquartered provider must **never** be counted
as US (T4). Give EU-headquartered providers an EU hq_country so they land in T3.
If you can't establish a provider's headquarters, leave it out of
`providers.csv` so it stays T5 (unclassified) rather than guessing.

## What it does and doesn't do

- It makes one `_dmarc` TXT query per domain, over DNS-over-HTTPS to a public
  resolver (edit `DOH` to change which one). The default delay between domains is 1 s.
- It reads public DNS only. It doesn't connect to mail servers or websites.
- It doesn't check whether the external rua destination has authorised your
  domain (the `_report._dmarc` record).
- Its output is a snapshot with a UTC timestamp. DNS changes all the time.

## Tested

We ran it on 10 public UK and global domains on 29 Oct 2026 (08:32 UTC). It
handled several rua destinations per record, records with no rua, and the
self-hosted and government tiers.

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

MIT licensed. Made by FaultyPacket. Free 20-check domain scan at faultypacket.co.uk.
