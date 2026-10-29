#!/usr/bin/env python3
"""dmarc_rua_classifier - where do a domain's DMARC aggregate (rua) reports go?

Reads a list of domains, fetches the public _dmarc TXT record over
DNS-over-HTTPS, extracts every rua destination domain and classifies it
generically:

  T0 self-hosted       rua domain is the domain itself or a subdomain/parent
  T1 government        rua domain sits under a government suffix (.gov.uk, .gov ...)
  T2-T4 third party    classified via an OPTIONAL providers.csv you supply
                       (suffix,type,hq_country) e.g. "example-dmarc.com,dmarc_saas,US"
  T5 unclassified      third party not in providers.csv (ccTLD shown as a hint)

No provider list ships with this tool on purpose: you decide and document
your own classification of headquarters. Only public DNS is queried.

Usage: python3 dmarc_rua_classifier.py domains.txt [--providers providers.csv] [--out results.csv]
MIT licensed.
"""
import argparse, csv, json, re, sys, time, urllib.parse, urllib.request

GOV_SUFFIXES = (".gov.uk", ".gov", ".gov.scot", ".gov.wales", ".nhs.uk", ".mod.uk",
                ".police.uk", ".gouv.fr", ".bund.de", ".gov.ie", ".europa.eu")
DOH = "https://cloudflare-dns.com/dns-query?"

def doh_txt(name):
    q = DOH + urllib.parse.urlencode({"name": name, "type": "TXT"})
    req = urllib.request.Request(q, headers={"accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        data = json.load(r)
    out = []
    for a in data.get("Answer", []) or []:
        if a.get("type") == 16:
            out.append("".join(re.findall(r'"([^"]*)"', a["data"])) or a["data"].strip('"'))
    return out

def rua_domains(record):
    m = re.search(r"(?:^|;)\s*rua\s*=\s*([^;]+)", record, re.I)
    if not m:
        return []
    doms = []
    for uri in m.group(1).split(","):
        uri = uri.strip()
        if "@" in uri:
            d = uri.split("@", 1)[1].split("!")[0].strip().lower().rstrip(".")
            if d and d not in doms:
                doms.append(d)
    return doms

def load_providers(path):
    prov = []
    if path:
        with open(path) as f:
            for row in csv.DictReader(f):
                prov.append((row["suffix"].lower().lstrip("."), row["type"], row["hq_country"].upper()))
    return prov

def classify(domain, rua, prov):
    d = domain.lower()
    if rua == d or rua.endswith("." + d) or d.endswith("." + rua):
        return "T0", "self-hosted", ""
    if any(rua.endswith(s) for s in GOV_SUFFIXES):
        return "T1", "government", ""
    for suf, typ, cc in prov:
        if rua == suf or rua.endswith("." + suf):
            if typ == "bundled_infrastructure":
                return "T2", typ, cc
            if cc in ("GB", "UK") or cc in EU:
                return "T3", typ, cc
            return "T4", typ, cc
    return "T5", "unclassified", "tld:." + rua.rsplit(".", 1)[-1]

EU = {"AT","BE","BG","HR","CY","CZ","DK","EE","FI","FR","DE","GR","HU","IE","IT","LV","LT",
      "LU","MT","NL","PL","PT","RO","SK","SI","ES","SE"}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("domains")
    ap.add_argument("--providers")
    ap.add_argument("--out", default="results.csv")
    ap.add_argument("--delay", type=float, default=1.0, help="seconds between domains")
    a = ap.parse_args()
    prov = load_providers(a.providers)
    doms = [l.strip().lower() for l in open(a.domains) if l.strip() and not l.startswith("#")]
    stamp = time.strftime("%Y-%m-%dT%H:%MZ", time.gmtime())
    rows = []
    for dom in doms:
        try:
            recs = [r for r in doh_txt("_dmarc." + dom) if r.lower().startswith("v=dmarc1")]
        except Exception as e:
            rows.append(dict(domain=dom, dmarc="error:" + type(e).__name__, rua_domain="", tier="", type="", hq_country="", observed_utc=stamp)); continue
        if not recs:
            rows.append(dict(domain=dom, dmarc="none", rua_domain="", tier="", type="", hq_country="", observed_utc=stamp))
        else:
            ruas = rua_domains(recs[0])
            if not ruas:
                rows.append(dict(domain=dom, dmarc="present", rua_domain="", tier="no-rua", type="", hq_country="", observed_utc=stamp))
            for r in ruas:
                t, typ, cc = classify(dom, r, prov)
                rows.append(dict(domain=dom, dmarc="present", rua_domain=r, tier=t, type=typ, hq_country=cc, observed_utc=stamp))
        time.sleep(a.delay)
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    tiers = {}
    for r in rows:
        tiers.setdefault(r["tier"] or r["dmarc"], set()).add(r["domain"])
    print(f"{len(doms)} domains observed {stamp}")
    for k in sorted(tiers): print(f"  {k}: {len(tiers[k])} domains")

if __name__ == "__main__":
    main()
