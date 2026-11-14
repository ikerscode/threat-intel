"""Pure helpers: public suffix split, defanging, alias normalisation."""
from threatintel import aliases, defang, psl


def test_registered_domain_icann_and_private():
    assert psl.registered_domain("login.secure.paypal.co.uk") == "paypal.co.uk"
    assert psl.registered_domain("a.b.example.com") == "example.com"
    assert psl.registered_domain("evil.pages.dev") == "evil.pages.dev"
    assert psl.registered_domain("x.y.github.io") == "y.github.io"
    assert psl.split("www.bbc.co.uk") == ("www", "bbc", "co.uk")
    assert psl.registered_domain("co.uk") == ""
    assert psl.registered_domain("203.0.113.5") == "203.0.113.5"
    assert psl.is_private_suffix("pages.dev") and not psl.is_private_suffix("co.uk")


def test_psl_wildcard_and_exception_rules():
    # *.ck and !www.ck are in the bundled list
    assert psl.public_suffix("foo.bar.ck") == "bar.ck"
    assert psl.registered_domain("www.ck") == "www.ck"


def test_defang_roundtrip():
    url = "http://login.evil-bank.example/path?a=1"
    d = defang.defang_url(url)
    assert d.startswith("hxxp://") and "[.]" in d and "evil-bank[.]example" in d
    assert defang.refang(d) == url
    assert defang.defang_domain("a.b.test") == "a[.]b[.]test"
    assert defang.url_host("hxxps://Sub.Example[.]com:8443/x") == "sub.example.com"


def test_detect_kinds():
    cases = {"CVE-2023-4966": "cve", "T1059.001": "technique", "TA0001": "tactic", "G0010": "attack-group",
             "S0154": "software", "1.2.3.4": "ip", "2001:db8::1": "ip", "10.0.0.0/8": "cidr",
             "hxxp://bad[.]example/a": "url", "bad[.]example": "domain", "a" * 64: "hash", "AS13335": "asn",
             "lockbit": "name"}
    for value, kind in cases.items():
        assert defang.detect(value) == kind, value


def test_alias_normalisation():
    assert aliases.norm("Vexy Ransomware") == "vexy"
    assert aliases.norm("INC Ransom") == "inc"
    assert aliases.norm("incransom") == "inc"
    assert aliases.norm("win.cobalt_strike") == "cobaltstrike"
    assert aliases.canonical_group("lockbit3") == aliases.canonical_group("LockBit 3.0") == "lockbit"
    assert aliases.canonical_group("Cl0p") == "clop"
    assert aliases.canonical_group("BlackCat") == "alphv"
    assert aliases.canonical_malware("Qbot") == "qakbot"
    assert aliases.strip_version("lockbit30") == "lockbit"
    assert aliases.is_generic_tag("elf") and aliases.is_generic_tag("32-bit") and not aliases.is_generic_tag("mirai")
