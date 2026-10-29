#!/usr/bin/env python3
"""dmarc-rua-classifier: where do a domain's DMARC reports go, and has each
external destination authorised them?

Standards: DMARC is RFC 9989 (May 2026, obsoletes RFC 7489); aggregate
reporting RFC 9990; failure reporting RFC 9991.

Modes
  classify (default)  rua destinations -> generic tiers T0..T5 (as v1.0)
  --check             own-domain check: record syntax (RFC 9989 4.7/4.8),
                      historic tags (9.3), policy discovery and DNS Tree Walk
                      (4.10), external destination verification for rua
                      (RFC 9990 4) and ruf (RFC 9991 5)

MIT licence. https://faultypacket.co.uk
"""
import argparse, csv, datetime as dt, ipaddress, json, os, re, sys, time
import urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor

__version__ = "1.2.0"

GOV_SUFFIXES = (".gov.uk", ".gov", ".gov.scot", ".gov.wales", ".nhs.uk", ".mod.uk",
                ".police.uk", ".gouv.fr", ".bund.de", ".gov.ie", ".europa.eu")
EU = {"AT","BE","BG","HR","CY","CZ","DK","EE","FI","FR","DE","GR","HU","IE","IT","LV","LT",
      "LU","MT","NL","PL","PT","RO","SK","SI","ES","SE"}
DOH_TYPES = {"A": 1, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}
# RFC 9989 9.3 DMARC Tags registry
ACTIVE_TAGS = {"v", "p", "sp", "np", "psd", "t", "rua", "ruf", "adkim", "aspf", "fo"}
HISTORIC_TAGS = {"pct", "rf", "ri"}
TREE_WALK_MAX = 8   # RFC 9989 4.10: at most eight DNS queries


# --------------------------------------------------------------------- DNS
def parse_txt_presentation(s):
    """'"v=DMARC1; " "p=none"' -> 'v=DMARC1; p=none' (handles \\" and \\DDD)."""
    s = s.strip()
    if not s.startswith('"'):
        return s
    out, i, inq = [], 0, False
    while i < len(s):
        c = s[i]
        if c == '"':
            inq = not inq
        elif inq and c == "\\" and i + 1 < len(s):
            if len(s[i + 1:i + 4]) == 3 and s[i + 1:i + 4].isdigit():
                out.append(chr(int(s[i + 1:i + 4]))); i += 3
            else:
                out.append(s[i + 1]); i += 1
        elif inq:
            out.append(c)
        i += 1
    return "".join(out)


class Resolver:
    """query(name, rtype) -> (values, status); status ok | void | error:<why>.
    void = NXDOMAIN or no answer of that type."""

    def __init__(self, nameserver=None, timeout=5.0, doh=None):
        self.doh, self.timeout, self.r = doh, timeout, None
        if not doh:
            import dns.resolver
            self.r = dns.resolver.Resolver()
            if nameserver:
                self.r.nameservers = [nameserver]
            self.r.lifetime = timeout

    @property
    def servers(self):
        return [self.doh] if self.doh else list(self.r.nameservers)

    def query(self, name, rtype):
        return self._doh(name, rtype) if self.doh else self._dns(name, rtype)

    def _dns(self, name, rtype):
        import dns.exception, dns.resolver
        try:
            ans = self.r.resolve(name, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return [], "void"
        except dns.exception.DNSException as e:
            return [], "error:" + type(e).__name__
        if rtype == "TXT":
            return [b"".join(r.strings).decode("utf-8", "replace") for r in ans], "ok"
        return [r.to_text() for r in ans], "ok"

    def _doh(self, name, rtype):
        url = self.doh + "?" + urllib.parse.urlencode({"name": name, "type": rtype})
        try:
            req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
            with urllib.request.urlopen(req, timeout=self.timeout) as f:
                j = json.load(f)
        except Exception as e:
            return [], "error:" + type(e).__name__
        if j.get("Status") == 3:
            return [], "void"
        if j.get("Status") != 0:
            return [], f"error:rcode{j.get('Status')}"
        data = [a["data"] for a in j.get("Answer", []) or [] if a.get("type") == DOH_TYPES[rtype]]
        if rtype == "TXT":
            data = [parse_txt_presentation(d) for d in data]
        return (data, "ok") if data else ([], "void")


# ------------------------------------------------ organizational domain
_PSL = None
def org_domain_psl(name):
    """Legacy RFC 7489 3.2 Organizational Domain via the Public Suffix List.
    Kept only to compare with the RFC 9989 DNS Tree Walk."""
    global _PSL
    if _PSL is None:
        from publicsuffixlist import PublicSuffixList
        _PSL = PublicSuffixList()
    return _PSL.privatesuffix(name.lower().rstrip(".")) or name.lower().rstrip(".")


def walk_targets(domain, include_start=True):
    """RFC 9989 4.10 steps 3-7: names to query, at most 8."""
    labels = domain.lower().rstrip(".").split(".")
    out = [".".join(labels)] if include_start else []
    x = len(labels)
    cur = labels[1:] if x < 8 else labels[x - 7:]
    while cur:
        out.append(".".join(cur))
        cur = cur[1:]
    return out[:TREE_WALK_MAX]


class Cached:
    """Wrap a resolver with a per-run cache (tree walks repeat queries)."""
    def __init__(self, res):
        self.res, self.c = res, {}
    @property
    def servers(self):
        return self.res.servers
    def query(self, name, rtype):
        k = (name.lower().rstrip("."), rtype)
        if k not in self.c:
            self.c[k] = self.res.query(name, rtype)
        return self.c[k]


def valid_record_at(name, res):
    """-> (record or None, status). RFC 9989 4.10 step 2: more than one
    DMARC record at a name means all are discarded."""
    txts, st = res.query("_dmarc." + name, "TXT")
    if st.startswith("error"):
        return None, st
    recs = dmarc_records(txts)
    return (recs[0], "ok") if len(recs) == 1 else (None, "multiple" if recs else "none")


def psd_value(record):
    tags, _ = parse_tags(record)
    for k, v in tags:
        if k == "psd":
            return v.strip().lower()
    return None


def tree_walk(domain, res, include_start=True):
    """RFC 9989 4.10 DNS Tree Walk. -> {queried, found{name: record}, errors}."""
    found, queried, errors = {}, [], []
    for name in walk_targets(domain, include_start):
        rec, st = valid_record_at(name, res)
        queried.append(name)
        if st.startswith("error"):
            errors.append(f"_dmarc.{name}: {st}")
            continue
        if rec:
            found[name] = rec
            if psd_value(rec) in ("y", "n"):
                break
    return {"queried": queried, "found": found, "errors": errors}


def org_domain(domain, res):
    """RFC 9989 4.10.2 Organizational Domain selection from a Tree Walk
    starting at domain. -> (org_domain, walk)."""
    d = domain.lower().rstrip(".")
    w = tree_walk(d, res)
    names = sorted(w["found"], key=lambda n: -n.count("."))   # longest first
    for n in names:
        if psd_value(w["found"][n]) == "n":
            return n, w
        if psd_value(w["found"][n]) == "y" and n != d:
            one_below = ".".join(d.split(".")[-(n.count(".") + 2):])
            return one_below, w
    if names:
        return names[-1], w
    return d, w


# ------------------------------------------------------------ DMARC parsing
def dmarc_records(txts):
    """RFC 9989 4.7: v is REQUIRED, MUST be first, and its value "DMARC1" is
    case-sensitive; any other TXT at _dmarc is not a DMARC record."""
    return [t for t in txts if re.match(r"^\s*[vV]\s*=\s*DMARC1\s*(;|$)", t)]


def near_miss_records(txts):
    """TXT that look like DMARC but fail the case-sensitive version check."""
    return [t for t in txts if re.match(r"^\s*v\s*=\s*dmarc1\s*(;|$)", t, re.I) and t not in dmarc_records([t])]


def parse_tags(record):
    """-> (ordered list of (tag, value), issues). Tag names case-insensitive."""
    tags, issues = [], []
    for part in record.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            issues.append(("error", "syntax", f"tag without '=': {part!r} (RFC 9989 4.8)"))
            continue
        k, v = part.split("=", 1)
        tags.append((k.strip().lower(), v.strip()))
    return tags, issues


def parse_uris(value):
    """RFC 9989 4.6/4.8 DMARC URI list (a !size suffix is obs-dmarc-report-size) -> list of dicts {uri, scheme, address, host, size}."""
    out = []
    for raw in value.split(","):
        raw = raw.strip()
        if not raw:
            continue
        uri, size = raw, None
        m = re.match(r"^(.*)!(\d+[kmgt]?)$", raw, re.I)
        if m:
            uri, size = m.group(1), m.group(2)
        scheme = uri.split(":", 1)[0].lower() if ":" in uri else ""
        addr = urllib.parse.unquote(uri.split(":", 1)[1]) if scheme else uri
        addr = addr.split("?", 1)[0]
        host = addr.rsplit("@", 1)[1].strip().lower().rstrip(".") if "@" in addr else ""
        out.append({"uri": raw, "scheme": scheme, "address": addr, "host": host, "size": size})
    return out


def rua_domains(record):
    """v1.0 behaviour: unique rua host domains in order."""
    tags, _ = parse_tags(record)
    doms = []
    for k, v in tags:
        if k == "rua":
            for u in parse_uris(v):
                if u["host"] and u["host"] not in doms:
                    doms.append(u["host"])
            break
    return doms


POLICIES = ("none", "quarantine", "reject")


def valid_fo(value):
    """RFC 9989 4.8 dmarc-fo: 0/1 mutually exclusive, d and s at most once."""
    opts = [o.strip().lower() for o in value.split(":")]
    if not opts or not all(o in ("0", "1", "d", "s") for o in opts):
        return False
    if "0" in opts and "1" in opts:
        return False
    return all(opts.count(o) <= 1 for o in opts)


def validate(record):
    """Syntax/semantics per RFC 9989 4.7/4.8/9.3. -> (tags dict, issues list).
    Never prints; issues are (severity, code, message)."""
    tags, issues = parse_tags(record)
    d = {}
    if not tags or tags[0][0] != "v" or tags[0][1] != "DMARC1":
        issues.append(("error", "version", "v=DMARC1 must be the first tag; the value is case-sensitive, otherwise the record is ignored (RFC 9989 4.7)"))
    for k, v in tags:
        if k in d:
            issues.append(("warning", "duplicate_tag", f"tag {k} appears more than once; first value used"))
            continue
        d[k] = v
        if k in HISTORIC_TAGS:
            if k == "pct" and v.strip() == "0":
                issues.append(("warning", "historic_pct", "pct=0 is historic and ignored by RFC 9989 receivers, so the full policy now applies; t=y is the replacement (RFC 9989 9.3, A.6)"))
            elif k == "pct" and v.strip() != "100":
                issues.append(("warning", "historic_pct", f"pct={v} is historic and ignored by RFC 9989 receivers: the policy now applies to all failing mail, not {v}% (RFC 9989 9.3, A.6)"))
            else:
                issues.append(("info", "historic_tag", f"tag {k!r} is historic in the DMARC Tags registry and ignored by RFC 9989 receivers; safe to remove (RFC 9989 9.3)"))
        elif k not in ACTIVE_TAGS:
            issues.append(("warning", "unknown_tag", f"unknown tag {k!r} MUST be ignored by receivers (RFC 9989 4.7)"))
    rua_ok = any(u["scheme"] == "mailto" and u["host"] for u in parse_uris(d.get("rua", "")))
    p = d.get("p")
    if p is None:
        issues.append(("warning", "no_p", "p is missing: treated as p=none (RFC 9989 4.7); publish p explicitly"))
    elif p.lower() not in POLICIES:
        issues.append(("error", "bad_p", f"p={p!r} is not none|quarantine|reject; receivers act as p=none if rua holds a valid URI, otherwise skip DMARC (RFC 9989 4.10.1)"))
    for k in ("sp", "np"):
        if k in d and d[k].lower() not in POLICIES:
            issues.append(("error", "bad_" + k, f"{k}={d[k]!r} is not none|quarantine|reject (RFC 9989 4.7, 4.10.1)"))
    for k in ("adkim", "aspf"):
        if k in d and d[k].lower() not in ("r", "s"):
            issues.append(("error", "bad_" + k, f"{k}={d[k]!r} is not r|s; default r applies (RFC 9989 4.7, 4.8)"))
    if "psd" in d and d["psd"].lower() not in ("y", "n", "u"):
        issues.append(("error", "bad_psd", f"psd={d['psd']!r} is not y|n|u; default u applies (RFC 9989 4.7)"))
    if "t" in d:
        if d["t"].lower() not in ("y", "n"):
            issues.append(("error", "bad_t", f"t={d['t']!r} is not y|n; default n applies (RFC 9989 4.7)"))
        elif d["t"].lower() == "y":
            issues.append(("info", "test_mode", "t=y: test mode; receivers are asked to apply one level below the stated policy (reject->quarantine, quarantine->none) (RFC 9989 4.7)"))
    if "fo" in d:
        if not valid_fo(d["fo"]):
            issues.append(("error", "bad_fo", f"fo={d['fo']!r}: options 0,1,d,s separated by ':', 0 and 1 mutually exclusive, d and s at most once (RFC 9989 4.8)"))
        if "ruf" not in d:
            issues.append(("info", "fo_without_ruf", "fo has no effect without ruf (RFC 9989 4.7)"))
    for k in ("rua", "ruf"):
        if k in d:
            uris = parse_uris(d[k])
            if not uris:
                issues.append(("error", "empty_" + k, f"{k} is present but empty (RFC 9989 4.7)"))
            for u in uris:
                if u["scheme"] != "mailto":
                    issues.append(("warning", "scheme_" + k, f"{k} URI {u['uri']!r} is not mailto; mailto is the scheme receivers MUST support (RFC 9989 4.6)"))
                elif not u["host"]:
                    issues.append(("error", "bad_uri_" + k, f"{k} URI {u['uri']!r} has no domain (RFC 9989 4.6)"))
                if u["size"]:
                    issues.append(("info", "obsolete_size", f"{k} URI {u['uri']!r}: the !size suffix is obsolete and ignored (RFC 9989 4.8)"))
    if "rua" not in d:
        issues.append(("warning", "no_rua", "no rua: you receive no aggregate reports (RFC 9989 4.7; RFC 9990)"))
    if p and p.lower() == "none":
        issues.append(("info", "p_none", "p=none: monitoring only, no enforcement requested (RFC 9989 4.7)"))
    return d, issues


def org_compare(name, res):
    """Tree Walk Organizational Domain vs legacy PSL. -> dict."""
    tw, walk = org_domain(name, res)
    try:
        psl = org_domain_psl(name)
    except Exception as e:          # PSL package missing or broken
        psl = f"error:{type(e).__name__}"
    # with no record anywhere DMARC does not apply (4.10.1), so no comparison
    return {"name": name, "tree_walk": tw, "psl": psl,
            "differs": bool(walk["found"]) and tw != psl,
            "queries": len(walk["queried"]), "walk_errors": walk["errors"]}


def external_check(domain, uris, res, tag, policy_org=None):
    """RFC 9990 4 (rua) / RFC 9991 5 (ruf): when the Organizational Domain at
    which the policy was found differs from the destination host's, query
    <domain>._report._dmarc.<host> TXT; at least one record whose first tag
    is v=DMARC1 authorises it. Organizational Domains use the RFC 9989 4.10
    Tree Walk; the legacy PSL answer is reported when it disagrees.
    -> (rows, issues)."""
    cite = "RFC 9990 4" if tag == "rua" else "RFC 9991 5; RFC 9990 4"
    out, issues = [], []
    od = policy_org or org_domain(domain, res)[0]
    od_psl = org_domain_psl(domain)
    for u in uris:
        if u["scheme"] != "mailto" or not u["host"]:
            continue
        host_od = org_domain(u["host"], res)[0]
        ext = host_od != od
        ext_psl = org_domain_psl(u["host"]) != od_psl
        row = {"tag": tag, "uri": u["uri"], "host": u["host"], "external": ext,
               "external_psl": ext_psl, "query": None, "authorised": None, "status": "same-org"}
        if ext != ext_psl:
            issues.append(("info", "org_method_differs",
                           f"{tag} {u['host']}: Tree Walk says {'external' if ext else 'same organization'}, "
                           f"legacy PSL says {'external' if ext_psl else 'same organization'} (RFC 9989 4.10.2)"))
        if ext:
            q = f"{domain}._report._dmarc.{u['host']}"
            row["query"] = q
            if len(q) > 253 or any(len(l) > 63 for l in q.split(".")):
                row["status"] = "name-too-long"
                issues.append(("error", "verify_too_long_" + tag, f"{q} exceeds DNS limits; authorisation cannot be confirmed ({cite} step 4)"))
                out.append(row); continue
            txts, st = res.query(q, "TXT")
            if st.startswith("error"):
                row["status"] = st
                issues.append(("error", "verify_error_" + tag,
                               f"could not verify {tag} destination {u['host']}: {st} querying {q}"))
            else:
                ok = bool(dmarc_records(txts))
                row["authorised"] = ok
                row["status"] = "authorised" if ok else "missing"
                if not ok:
                    issues.append(("error", "unauthorised_" + tag,
                                   f"{tag} destination {u['host']} has not authorised {domain}: no v=DMARC1 TXT at {q}; "
                                   f"compliant receivers MUST ignore this URI ({cite})"))
        out.append(row)
    return out, issues


def check_domain(domain, res):
    """Own-domain check per RFC 9989 4.10.1 policy discovery. Never prints."""
    res = res if isinstance(res, Cached) else Cached(res)
    domain = domain.lower().rstrip(".")
    issues, record, tags, dests, applied_from = [], None, {}, [], None
    txts, st = res.query("_dmarc." + domain, "TXT")
    org = org_compare(domain, res)
    if org["differs"]:
        issues.append(("info", "org_method_differs",
                       f"Organizational Domain: Tree Walk {org['tree_walk']} vs legacy PSL {org['psl']} (RFC 9989 4.10.2)"))
        if org["psl"].endswith("." + org["tree_walk"]):
            issues.append(("warning", "parent_psd_without_psd_y",
                           f"the Tree Walk climbs to _dmarc.{org['tree_walk']}, a public suffix whose record lacks psd=y "
                           f"(a PSO MUST publish psd=y, RFC 9989 5.2), so RFC 9989 receivers treat {org['tree_walk']} as your "
                           f"Organizational Domain; add psd=n to your own record (RFC 9989 11.8)"))
    if st.startswith("error"):
        issues.append(("error", "dns_error", f"_dmarc.{domain} TXT lookup failed: {st}"))
    else:
        recs = dmarc_records(txts)
        for t in near_miss_records(txts):
            issues.append(("error", "version_case", f"_dmarc.{domain} has {t[:40]!r}...: 'DMARC1' is case-sensitive, receivers ignore this record (RFC 9989 4.7)"))
        if len(recs) > 1:
            issues.append(("error", "multiple_records", f"{len(recs)} DMARC records at _dmarc.{domain}: all are discarded (RFC 9989 4.10 step 2)"))
        elif recs:
            record, applied_from = recs[0], domain
        else:
            # 4.10.1: Organizational Domain record, then PSD record
            od = org["tree_walk"]
            walk = tree_walk(domain, res, include_start=False)
            if od != domain and od in walk["found"]:
                applied_from = od
                issues.append(("warning", "no_record_sub", f"no DMARC record at _dmarc.{domain}; receivers use the Organizational Domain record at _dmarc.{od} (sp or np applies) (RFC 9989 4.10.1)"))
            elif walk["found"]:
                applied_from = sorted(walk["found"], key=lambda n: n.count("."))[0]
                issues.append(("warning", "psd_policy", f"no DMARC record for {domain} or its Organizational Domain; a Public Suffix Domain record at _dmarc.{applied_from} applies (RFC 9989 4.10.1)"))
            else:
                issues.append(("error", "no_record", f"no DMARC record at _dmarc.{domain} and none found by the Tree Walk: DMARC does not apply (RFC 9989 4.10.1)"))
        if record:
            tags, iss = validate(record)
            issues += iss
            for t in ("rua", "ruf"):
                if t in tags:
                    rows, iss = external_check(domain, parse_uris(tags[t]), res, t, org["tree_walk"])
                    dests += rows; issues += iss
    issues = [{"severity": s, "code": c, "message": m} for s, c, m in issues]
    return {"domain": domain, "record": record, "policy": tags.get("p"),
            "policy_source": applied_from, "org_domain": org,
            "destinations": dests, "issues": issues, "result": verdict(issues)}


def verdict(issues):
    sev = {i["severity"] for i in issues}
    return "fail" if "error" in sev else "warn" if "warning" in sev else "ok"


# -------------------------------------------------------- classify (v1.0)
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


def classify_domain(dom, res, prov, stamp):
    base = dict(domain=dom, dmarc="", rua_domain="", tier="", type="", hq_country="", observed_utc=stamp)
    txts, st = res.query("_dmarc." + dom, "TXT")
    if st.startswith("error"):
        return [dict(base, dmarc="error:" + st.split(":", 1)[1])]
    recs = dmarc_records(txts)
    if not recs:
        return [dict(base, dmarc="none")]
    ruas = rua_domains(recs[0])
    if not ruas:
        return [dict(base, dmarc="present", tier="no-rua")]
    return [dict(base, dmarc="present", rua_domain=r, **dict(zip(("tier", "type", "hq_country"),
            classify(dom, r, prov)))) for r in ruas]


# -------------------------------------------------------------------- input
def extract_domain(raw):
    """URL, email, host:port or bare name -> lowercase ASCII domain. ValueError."""
    s = raw.strip()
    if not s:
        raise ValueError("empty")
    if "://" in s:
        s = urllib.parse.urlsplit(s).netloc
    s = s.split("/")[0].split("?")[0].split("#")[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    if s.startswith("["):
        raise ValueError("IP literal, not a domain")
    s = s.split(":")[0].rstrip(".").strip().lower()
    if not s:
        raise ValueError("no host")
    try:
        ipaddress.ip_address(s)
    except ValueError:
        pass
    else:
        raise ValueError("IP address, not a domain")
    try:
        s = s.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("invalid IDN")
    labels = s.split(".")
    if len(s) > 253 or len(labels) < 2 or not all(
            re.fullmatch(r"(?!-)[a-z0-9_-]{1,63}(?<!-)", l) for l in labels):
        raise ValueError("not a valid domain name")
    return s


def read_lines(lines):
    out = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if line:
            out.extend(line.replace(",", " ").split())
    return out


def collect(args, files, stdin, auto_stdin=False):
    """-> (deduped domains in first-seen order, [{input, error}]).
    A positional argument naming an existing file is read as a list (v1.0 usage)."""
    raw = []
    def read(f):
        if f == "-":
            return read_lines(stdin)
        with open(f, encoding="utf-8") as fh:
            return read_lines(fh)
    for a in args:
        raw += read(a) if os.path.isfile(a) else [a]
    for f in files or []:
        raw += read(f)
    if auto_stdin and stdin is not None and not stdin.isatty():
        raw += read_lines(stdin)
    seen, domains, bad = set(), [], []
    for r in raw:
        try:
            d = extract_domain(r)
        except ValueError as e:
            bad.append({"input": r, "error": str(e)}); continue
        if d not in seen:
            seen.add(d); domains.append(d)
    return domains, bad


# --------------------------------------------------------------------- main
def now_utc():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def safe(fn, dom, *a):
    try:
        return fn(dom, *a)
    except Exception as e:  # per-domain isolation
        return {"domain": dom, "record": None, "policy": None, "destinations": [],
                "issues": [{"severity": "error", "code": "internal", "message": f"{type(e).__name__}: {e}"}],
                "result": "error"}


def write_json(path, data):
    s = json.dumps(data, indent=2) + "\n"
    if path == "-":
        sys.stdout.write(s)
    else:
        with open(path, "w") as f:
            f.write(s)


def main(argv=None, stdin=None):
    stdin = sys.stdin if stdin is None else stdin
    p = argparse.ArgumentParser(prog="dmarc_rua_classifier.py",
        description="Classify DMARC report destinations, or check your own domain (RFC 9989 / 9990 / 9991).")
    p.add_argument("domains", nargs="*", help="domains, URLs, email addresses, or a file of them")
    p.add_argument("-f", "--file", action="append", help="file with one input per line ('-' = stdin); repeatable")
    p.add_argument("--check", action="store_true", help="own-domain check mode (RFC 9989 syntax, Tree Walk, RFC 9990 4 verification)")
    p.add_argument("--providers", help="classify mode: your providers.csv (suffix,type,hq_country)")
    p.add_argument("--out", default="results.csv", help="CSV output (default %(default)s)")
    p.add_argument("--json", help="also write JSON to file, '-' for stdout")
    p.add_argument("--resolver", help="nameserver IP (port 53)")
    p.add_argument("--doh", action="store_true", help="use DNS-over-HTTPS JSON API instead of port 53")
    p.add_argument("--doh-url", default="https://cloudflare-dns.com/dns-query", help="DoH JSON endpoint (default %(default)s)")
    p.add_argument("--timeout", type=float, default=5.0, help="per-query timeout, seconds (default 5)")
    p.add_argument("--delay", type=float, default=1.0, help="classify mode: seconds between domains (default 1)")
    p.add_argument("-c", "--concurrency", type=int, default=4, help="check mode: domains in parallel (default 4, max 32)")
    p.add_argument("-q", "--quiet", action="store_true", help="check mode: summary only")
    p.add_argument("--version", action="version", version=f"dmarc-rua-classifier {__version__}")
    a = p.parse_args(argv)
    if not 1 <= a.concurrency <= 32:
        p.error("--concurrency must be 1..32")
    try:
        domains, bad = collect(a.domains, a.file, stdin, auto_stdin=not a.domains and not a.file)
    except OSError as e:
        p.error(str(e))
    for b in bad:
        print(f"skipped input {b['input']!r}: {b['error']}", file=sys.stderr)
    if not domains:
        p.error("no valid domains given")
    res = Resolver(a.resolver, a.timeout, a.doh_url if a.doh else None)
    out = sys.stderr if a.json == "-" else sys.stdout
    stamp = now_utc()

    if not a.check:
        prov = load_providers(a.providers)
        rows = []
        for i, dom in enumerate(domains):
            try:
                rows += classify_domain(dom, res, prov, stamp)
            except Exception as e:
                rows.append(dict(domain=dom, dmarc="error:" + type(e).__name__, rua_domain="", tier="",
                                 type="", hq_country="", observed_utc=stamp))
            if a.delay and i < len(domains) - 1:
                time.sleep(a.delay)
        with open(a.out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
        if a.json:
            write_json(a.json, rows)
        tiers = {}
        for r in rows:
            tiers.setdefault(r["tier"] or r["dmarc"], set()).add(r["domain"])
        print(f"{len(domains)} domains observed {stamp} via {','.join(res.servers)}", file=out)
        for k in sorted(tiers):
            print(f"  {k}: {len(tiers[k])} domains", file=out)
        return 1 if (bad or any(r["dmarc"].startswith("error") for r in rows)) else 0

    cres = Cached(res)
    with ThreadPoolExecutor(max_workers=min(a.concurrency, len(domains))) as ex:
        results = list(ex.map(lambda d: safe(check_domain, d, cres), domains))
    for r in results:
        r.update({"tool": "dmarc-rua-classifier", "version": __version__,
                  "checked_at_utc": stamp, "resolvers": res.servers})
        if not a.quiet:
            print(f"{r['domain']}: {r['result'].upper()}", file=out)
            if r["record"]:
                print(f"  record: {r['record']}", file=out)
            for d in r["destinations"]:
                print(f"  {d['tag']} -> {d['host']}: {d['status']}" + (f" ({d['query']})" if d["query"] else ""), file=out)
            for i in r["issues"]:
                print(f"  [{i['severity']}] {i['message']}", file=out)
            print(file=out)
    w = max([6] + [len(r["domain"]) for r in results])
    print(f"{'domain':<{w}}  result  policy      ext_dests  unauthorised", file=out)
    for r in results:
        ext = [d for d in r["destinations"] if d["external"]]
        miss = sum(d["status"] == "missing" for d in ext)
        print(f"{r['domain']:<{w}}  {r['result']:<6}  {str(r['policy'] or '-'):<10}  {len(ext):>9}  {miss:>12}", file=out)
    print(f"checked {stamp} via {','.join(res.servers)}", file=out)
    with open(a.out, "w", newline="") as f:
        cw = csv.writer(f)
        cw.writerow(["checked_at_utc", "domain", "result", "policy", "external_destinations",
                     "unauthorised_destinations", "org_domain_tree_walk", "org_domain_psl",
                     "issues", "record", "resolver"])
        for r in results:
            ext = [d for d in r["destinations"] if d["external"]]
            cw.writerow([stamp, r["domain"], r["result"], r["policy"] or "", len(ext),
                         " ".join(f"{d['tag']}:{d['host']}" for d in ext if d["status"] == "missing"),
                         (r.get("org_domain") or {}).get("tree_walk", ""), (r.get("org_domain") or {}).get("psl", ""),
                         " | ".join(f"{i['severity']}:{i['code']}" for i in r["issues"]),
                         r["record"] or "", ",".join(res.servers)])
    if a.json:
        write_json(a.json, results)
    return 1 if (bad or any(r["result"] in ("fail", "error") for r in results)) else 0


if __name__ == "__main__":
    sys.exit(main())
