import csv, io, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import dmarc_rua_classifier as m


class FakeRes:
    def __init__(self, txt, errors=()):
        self.txt, self.errors, self.asked = txt, set(errors), []
    servers = ["fake"]
    def query(self, name, rtype):
        self.asked.append(name)
        if name in self.errors:
            return [], "error:Timeout"
        v = self.txt.get(name)
        return (list(v), "ok") if v else ([], "void")


def codes(r):
    return {i["code"] for i in r["issues"]}


# ---- parsing
def test_txt_presentation():
    assert m.parse_txt_presentation('"v=DMARC1; " "p=none"') == "v=DMARC1; p=none"
    assert m.parse_txt_presentation(r'"a\"b\059c"') == 'a"b;c'
    assert m.parse_txt_presentation("plain") == "plain"

def test_dmarc_records_filter():
    assert m.dmarc_records(["v=spf1 -all", "v=DMARC1; p=none", " v = dmarc1 ;p=none", "v=DMARC10; p=none"]) == \
        ["v=DMARC1; p=none"]   # RFC 9989 4.7: "DMARC1" is case-sensitive
    assert m.dmarc_records(["V=DMARC1; p=none"]) == ["V=DMARC1; p=none"]   # tag name is not
    assert m.near_miss_records([" v = dmarc1 ;p=none"]) == [" v = dmarc1 ;p=none"]

def test_parse_uris_size_and_encoding():
    u = m.parse_uris("mailto:a@X.Example.com!10m, mailto:b%40c@d.example.net,https://x.test/r")
    assert u[0]["host"] == "x.example.com" and u[0]["size"] == "10m"
    assert u[1]["host"] == "d.example.net"
    assert u[2]["scheme"] == "https" and u[2]["host"] == ""

def test_rua_domains_v10_behaviour():
    assert m.rua_domains("v=DMARC1; p=none; rua=mailto:a@x.test,mailto:b@x.test,mailto:c@y.test") == ["x.test", "y.test"]
    assert m.rua_domains("v=DMARC1; p=none") == []
    assert m.rua_domains("v=DMARC1; p=none; ruf=mailto:a@x.test") == []

# ---- validation
def test_valid_record_clean():
    _, iss = m.validate("v=DMARC1; p=reject; rua=mailto:d@example.com; adkim=s; aspf=r; np=reject; psd=n; t=n")
    assert not [i for i in iss if i[0] != "info"]

def test_bad_values():
    _, iss = m.validate("v=DMARC1; p=block; sp=x; np=y; psd=maybe; t=1; adkim=q; fo=2; foo=1; rua=mailto:x")
    c = {i[1] for i in iss}
    assert {"bad_p", "bad_sp", "bad_np", "bad_psd", "bad_t", "bad_adkim", "bad_fo", "unknown_tag", "bad_uri_rua", "fo_without_ruf"} <= c

import pytest
@pytest.mark.parametrize("fo,ok", [("0", True), ("1", True), ("d:s", True), ("1:d:s", True),
                                   ("0:1", False), ("d:d", False), ("s:1:s", False), ("x", False), ("", False)])
def test_fo_abnf(fo, ok):
    assert m.valid_fo(fo) is ok

def test_historic_tags_flagged():
    iss = m.validate("v=DMARC1; p=reject; pct=100; rf=afrf; ri=3600; rua=mailto:a@b.test")[1]
    hist = [i for i in iss if i[1] == "historic_tag"]
    assert len(hist) == 3 and all(i[0] == "info" and "9.3" in i[2] for i in hist)

@pytest.mark.parametrize("pct,needle", [("50", "not 50%"), ("0", "t=y")])
def test_partial_pct_is_a_behaviour_change(pct, needle):
    iss = m.validate(f"v=DMARC1; p=quarantine; pct={pct}; rua=mailto:a@b.test")[1]
    w = [i for i in iss if i[1] == "historic_pct"]
    assert w and w[0][0] == "warning" and needle in w[0][2] and "A.6" in w[0][2]

def test_dmarcbis_tags_are_valid_no_noise():
    iss = m.validate("v=DMARC1; p=reject; np=reject; psd=u; t=n; rua=mailto:a@b.test")[1]
    assert not [i for i in iss if i[0] != "info"]

def test_test_mode_info_and_obsolete_size():
    c = {i[1] for i in m.validate("v=DMARC1; p=reject; t=y; rua=mailto:a@b.test!10m")[1]}
    assert {"test_mode", "obsolete_size"} <= c

def test_version_must_be_first_and_p_missing():
    c = {i[1] for i in m.validate("p=none; v=DMARC1")[1]}
    assert "version" in c
    iss = m.validate("v=DMARC1; rua=mailto:a@b.test")[1]
    assert ("warning", "no_p") in [(i[0], i[1]) for i in iss]   # treated as p=none (4.7)

def test_no_rua_warning():
    assert "no_rua" in {i[1] for i in m.validate("v=DMARC1; p=quarantine")[1]}

def test_duplicate_tag():
    c = {i[1] for i in m.validate("v=DMARC1; p=none; p=reject; rua=mailto:a@b.test")[1]}
    assert "duplicate_tag" in c

def test_non_mailto_scheme_warns():
    c = {i[1] for i in m.validate("v=DMARC1; p=none; rua=https://r.test/x")[1]}
    assert "scheme_rua" in c

# ---- org domain
def test_org_domain_psl_legacy():
    assert m.org_domain_psl("mail.council.gov.uk") == "council.gov.uk"
    assert m.org_domain_psl("a.b.example.co.uk") == "example.co.uk"
    assert m.org_domain_psl("example.com") == "example.com"

# ---- RFC 9989 4.10 DNS Tree Walk
def test_walk_targets_short_and_long():
    assert m.walk_targets("a.b.example.com") == ["a.b.example.com", "b.example.com", "example.com", "com"]
    long = ".".join("abcdefghijklm")        # 13 labels
    t = m.walk_targets(long)
    assert len(t) == 8 and t[0] == long and t[1] == "g.h.i.j.k.l.m" and t[-1] == "m"
    assert len(m.walk_targets(".".join("abcdefgh"))) == 8   # 8 labels -> start + 7..1

def test_walk_query_cap_is_8():
    res = FakeRes({})
    m.tree_walk(".".join("abcdefghijklmnop"), res)
    assert len(res.asked) == 8

def test_tree_walk_fewest_labels_wins():
    res = FakeRes({"_dmarc.example.com": ["v=DMARC1; p=reject"]})
    assert m.org_domain("mail.dept.example.com", res)[0] == "example.com"

def test_tree_walk_psd_n_stops_and_selects():
    res = FakeRes({"_dmarc.dept.example.com": ["v=DMARC1; p=reject; psd=n"],
                   "_dmarc.example.com": ["v=DMARC1; p=none"]})
    od, w = m.org_domain("a.dept.example.com", res)
    assert od == "dept.example.com" and "_dmarc.example.com" not in res.asked

def test_tree_walk_psd_y_one_below():
    res = FakeRes({"_dmarc.gov.example": ["v=DMARC1; p=reject; psd=y"]})
    assert m.org_domain("mail.council.gov.example", res)[0] == "council.gov.example"
    # psd=y on the starting record itself is skipped by rule 2
    assert m.org_domain("gov.example", res)[0] == "gov.example"

def test_tree_walk_multiple_records_discarded():
    res = FakeRes({"_dmarc.example.com": ["v=DMARC1; p=none", "v=DMARC1; p=reject"]})
    assert m.org_domain("a.example.com", res)[0] == "a.example.com"

def test_tree_walk_vs_psl_difference_reported():
    # parent publishes a record without psd=y: Tree Walk climbs to it, PSL stops below
    res = FakeRes({"_dmarc.gov.uk": ["v=DMARC1; p=none"],
                   "_dmarc.a.gov.uk": ["v=DMARC1; p=none; rua=mailto:d@b.gov.uk"]})
    oc = m.org_compare("a.gov.uk", res)
    assert (oc["tree_walk"], oc["psl"], oc["differs"]) == ("gov.uk", "a.gov.uk", True)
    r = m.check_domain("a.gov.uk", res)
    assert {"org_method_differs", "parent_psd_without_psd_y"} <= codes(r)
    d = r["destinations"][0]          # same org by Tree Walk, external by PSL
    assert d["external"] is False and d["external_psl"] is True

def test_no_records_no_difference_noise():
    assert not m.org_compare("sub.example.co.uk", FakeRes({}))["differs"]

# ---- RFC 9990 4 external verification
def test_external_authorised_and_missing():
    res = FakeRes({
        "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:a@reports.vendor-a.test,mailto:b@example.com; ruf=mailto:f@vendor-b.test"],
        "example.com._report._dmarc.reports.vendor-a.test": ["v=DMARC1"],
    })
    r = m.check_domain("example.com", res)
    st = {(d["tag"], d["host"]): d["status"] for d in r["destinations"]}
    assert st[("rua", "reports.vendor-a.test")] == "authorised"
    assert st[("rua", "example.com")] == "same-org"
    assert st[("ruf", "vendor-b.test")] == "missing"
    assert "unauthorised_ruf" in codes(r) and r["result"] == "fail"
    assert "example.com._report._dmarc.vendor-b.test" in res.asked

def test_same_org_subdomain_not_queried():
    res = FakeRes({"_dmarc.example.co.uk": ["v=DMARC1; p=none; rua=mailto:d@reports.example.co.uk"]})
    r = m.check_domain("example.co.uk", res)
    assert r["destinations"][0]["status"] == "same-org"
    assert not any("_report._dmarc" in q for q in res.asked)

def test_sibling_under_public_suffix_is_external():
    # two different councils under gov.uk are different Organizational Domains
    res = FakeRes({"_dmarc.a.gov.uk": ["v=DMARC1; p=none; rua=mailto:d@b.gov.uk"]})
    r = m.check_domain("a.gov.uk", res)
    assert r["destinations"][0]["external"] and r["destinations"][0]["status"] == "missing"

def test_wrong_txt_at_report_name_is_missing():
    res = FakeRes({"_dmarc.example.com": ["v=DMARC1; p=none; rua=mailto:a@v.test"],
                   "example.com._report._dmarc.v.test": ["v=spf1 -all"]})
    assert m.check_domain("example.com", res)["destinations"][0]["status"] == "missing"

def test_verify_dns_error_reported_not_missing():
    res = FakeRes({"_dmarc.example.com": ["v=DMARC1; p=none; rua=mailto:a@v.test"]},
                  errors={"example.com._report._dmarc.v.test"})
    r = m.check_domain("example.com", res)
    assert r["destinations"][0]["status"].startswith("error") and "verify_error_rua" in codes(r)

def test_multiple_records():
    res = FakeRes({"_dmarc.example.com": ["v=DMARC1; p=none", "v=DMARC1; p=reject"]})
    r = m.check_domain("example.com", res)
    assert "multiple_records" in codes(r) and r["result"] == "fail"

def test_no_record_org_and_subdomain():
    assert "no_record" in codes(m.check_domain("example.com", FakeRes({})))
    r = m.check_domain("sub.example.com", FakeRes({"_dmarc.example.com": ["v=DMARC1; p=reject"]}))
    assert "no_record_sub" in codes(r) and r["result"] == "warn" and r["policy_source"] == "example.com"
    r = m.check_domain("sub.example.com", FakeRes({}))
    assert "no_record" in codes(r) and r["result"] == "fail"

def test_psd_policy_fallback():
    res = FakeRes({"_dmarc.gov.example": ["v=DMARC1; p=reject; psd=y"]})
    r = m.check_domain("council.gov.example", res)
    assert "psd_policy" in codes(r) and r["policy_source"] == "gov.example"

def test_version_case_near_miss_reported():
    r = m.check_domain("example.com", FakeRes({"_dmarc.example.com": ["v=dmarc1; p=reject"]}))
    assert "version_case" in codes(r)

def test_dns_error_isolated():
    r = m.check_domain("example.com", FakeRes({}, errors={"_dmarc.example.com"}))
    assert "dns_error" in codes(r)

# ---- classify (v1.0 compatibility)
def test_classify_tiers():
    prov = [("eu.example-saas.test", "dmarc_saas", "US"), ("rua.eu-prov.test", "dmarc_saas", "DE"),
            ("gw.test", "bundled_infrastructure", "US")]
    assert m.classify("council.gov.uk", "council.gov.uk", prov)[0] == "T0"
    assert m.classify("council.gov.uk", "dmarc.service.gov.uk", prov)[0] == "T1"
    assert m.classify("x.org", "a.gw.test", prov)[0] == "T2"
    assert m.classify("x.org", "rua.eu-prov.test", prov)[0] == "T3"
    assert m.classify("x.org", "eu.example-saas.test", prov) == ("T4", "dmarc_saas", "US")
    assert m.classify("x.org", "other.fr", prov) == ("T5", "unclassified", "tld:.fr")

def test_example_providers_file_loads():
    p = m.load_providers(os.path.join(os.path.dirname(__file__), "..", "providers.example.csv"))
    assert len(p) == 4 and p[2] == ("rua.example-eu-provider.eu", "dmarc_saas", "DE")

def test_data_file_intact():
    rows = list(csv.DictReader(open(os.path.join(os.path.dirname(__file__), "..", "aggregate_uk_councils_2026-10-29.csv"))))
    t4 = [r for r in rows if r["scope"] == "all" and r["tier"] == "T4"]
    assert t4 and t4[0]["domains"] == "94"

# ---- input handling
def test_extract_domain():
    assert m.extract_domain("https://WWW.Example.com:443/x?y") == "www.example.com"
    assert m.extract_domain("postmaster@example.org") == "example.org"
    assert m.extract_domain("bücher.example") == "xn--bcher-kva.example"
    for bad in ("1.2.3.4", "[::1]", "localhost", "-a.com", ""):
        try:
            m.extract_domain(bad); assert False, bad
        except ValueError:
            pass

def test_collect_dedupe_file_stdin(tmp_path):
    f = tmp_path / "d.txt"; f.write_text("# c\nexample.com\nhttps://example.com/\nfoo@example.org, bad..x\n")
    d, bad = m.collect([str(f), "EXAMPLE.org"], ["-"], io.StringIO("example.net\n"))
    assert d == ["example.com", "example.org", "example.net"] and len(bad) == 1

# ---- CLI end-to-end with fake DNS
def run_cli(monkeypatch, tmp_path, argv, txt):
    monkeypatch.setattr(m, "Resolver", lambda *a, **k: FakeRes(txt))
    return m.main(argv + ["--out", str(tmp_path / "o.csv")], stdin=io.StringIO(""))

def test_cli_check_json_and_exit(monkeypatch, tmp_path, capsys):
    txt = {"_dmarc.good.test": ["v=DMARC1; p=reject; rua=mailto:a@good.test"],
           "_dmarc.bad.test": ["v=DMARC1; p=reject; rua=mailto:a@v.test"]}
    rc = run_cli(monkeypatch, tmp_path, ["--check", "--json", str(tmp_path / "o.json"), "good.test", "bad.test", "good.test"], txt)
    assert rc == 1
    j = json.load(open(tmp_path / "o.json"))
    assert [r["domain"] for r in j] == ["good.test", "bad.test"]
    assert j[0]["result"] == "ok" and j[1]["result"] == "fail"
    rows = list(csv.DictReader(open(tmp_path / "o.csv")))
    assert rows[1]["unauthorised_destinations"] == "rua:v.test"

def test_cli_check_all_ok_exit0(monkeypatch, tmp_path):
    assert run_cli(monkeypatch, tmp_path, ["--check", "good.test"],
                   {"_dmarc.good.test": ["v=DMARC1; p=reject; rua=mailto:a@good.test"]}) == 0

def test_cli_classify_compatible_csv(monkeypatch, tmp_path):
    rc = run_cli(monkeypatch, tmp_path, ["--delay", "0", "a.test", "b.test"],
                 {"_dmarc.a.test": ["v=DMARC1; p=none; rua=mailto:x@a.test"]})
    rows = list(csv.DictReader(open(tmp_path / "o.csv")))
    assert list(rows[0].keys()) == ["domain", "dmarc", "rua_domain", "tier", "type", "hq_country", "observed_utc"]
    assert rows[0]["tier"] == "T0" and rows[1]["dmarc"] == "none" and rc == 0

def test_cli_internal_error_isolated(monkeypatch, tmp_path):
    class Boom(FakeRes):
        def query(self, name, rtype):
            if name.startswith("_dmarc.boom"): raise RuntimeError("x")
            return super().query(name, rtype)
    monkeypatch.setattr(m, "Resolver", lambda *a, **k: Boom({"_dmarc.ok.test": ["v=DMARC1; p=reject; rua=mailto:a@ok.test"]}))
    rc = m.main(["--check", "--json", str(tmp_path / "j"), "--out", str(tmp_path / "o"), "boom.test", "ok.test"], stdin=io.StringIO(""))
    j = json.load(open(tmp_path / "j"))
    assert rc == 1 and j[0]["result"] == "error" and j[1]["result"] == "ok"

def test_version(capsys):
    try:
        m.main(["--version"])
    except SystemExit:
        pass
    assert m.__version__ in capsys.readouterr().out


def test_psd_n_fixes_parent_without_psd_y():
    res = FakeRes({"_dmarc.gov.uk": ["v=DMARC1; p=none"],
                   "_dmarc.a.gov.uk": ["v=DMARC1; p=none; psd=n; rua=mailto:d@a.gov.uk"]})
    r = m.check_domain("a.gov.uk", res)
    assert r["org_domain"]["tree_walk"] == "a.gov.uk" and "parent_psd_without_psd_y" not in codes(r)
