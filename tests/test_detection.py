"""Unit tests for the inspector, blacklist checker, attack detector and verdict engine."""

import base64

import pytest

from gateway import db
from gateway.blacklist import BlacklistChecker, add_domains, parse_list, suffix_match
from gateway.config import DEFAULTS
from gateway.detector import EXCESSIVE, SUSPICIOUS_NAME, TUNNELING, AttackDetector
from gateway.inspector import inspect, registered_domain, shannon_entropy
from gateway.verdict import ALLOWED, BLOCKED, MALICIOUS, SUSPICIOUS, VerdictEngine

SETTINGS = DEFAULTS["detection"]

LEGIT = ["google.com", "www.google.com", "mail.google.com", "en.wikipedia.org", "github.com",
         "api.github.com", "stackoverflow.com", "www.nmims.edu", "portal.nmims.edu", "amazon.in",
         "www.bbc.co.uk", "login.microsoftonline.com", "outlook.office365.com", "youtube.com",
         "i.ytimg.com", "connectivitycheck.gstatic.com", "www.msftconnecttest.com", "python.org",
         "pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "web.whatsapp.com",
         "instagram.com", "static.cdninstagram.com", "netflix.com", "spotify.com",
         "open.spotify.com", "zoom.us", "us05web.zoom.us", "teams.microsoft.com",
         "docs.google.com", "drive.google.com", "accounts.google.com", "chatgpt.com",
         "claude.ai", "x.com", "reddit.com", "linkedin.com", "flipkart.com", "paytm.com",
         "hdfcbank.com", "onlinesbi.sbi", "irctc.co.in", "timesofindia.indiatimes.com",
         "kubernetes.io", "docker.com", "ubuntu.com", "archive.ubuntu.com", "nlnetlabs.nl"]

DGA = ["xjw9k2pq8vmz4ta1.com", "a8f3k2j9x7q1zz.net", "qwrtzpsdfghjkl.info", "kq3z8x7v2w9b4n5m.xyz",
       "zxcvbnmlkjhgfdsa.top", "p0o9i8u7y6t5r4e3.com"]


@pytest.fixture
def checker(tmp_path):
    path = str(tmp_path / "t.db")
    conn = db.init_db(path)
    add_domains(conn, ["malware-test.example", "doubleclick.net"], "test")
    allow = tmp_path / "allow.txt"
    allow.write_text("googlevideo.com\n")
    return BlacklistChecker(path, str(allow), refresh_seconds=0)


def engine(checker):
    return VerdictEngine(checker, AttackDetector(SETTINGS), SETTINGS)


# --- inspector ------------------------------------------------------------- #
def test_registered_domain():
    assert registered_domain("a.b.example.com") == "example.com"
    assert registered_domain("www.bbc.co.uk") == "bbc.co.uk"
    assert registered_domain("portal.nmims.ac.in") == "nmims.ac.in"
    assert registered_domain("com") == "com"


def test_inspect_features():
    info = inspect("ABC.Sub.Example.com.", "TXT", "10.0.0.5")
    assert info.domain == "abc.sub.example.com"
    assert info.parent == "example.com" and info.subdomain == "abc.sub" and info.sld == "example"
    assert info.subdomain_depth == 2
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == 2


# --- blacklist ------------------------------------------------------------- #
def test_parse_hosts_and_plain():
    text = "# comment\n0.0.0.0 evil.com\n127.0.0.1 localhost\nbad.net # trailing\n0.0.0.0 a.com b.com\n"
    assert parse_list(text) == {"evil.com", "bad.net", "a.com", "b.com"}


def test_suffix_match():
    domains = {"evil.com"}
    assert suffix_match("evil.com", domains) == "evil.com"
    assert suffix_match("x.y.evil.com", domains) == "evil.com"
    assert suffix_match("notevil.com", domains) is None


def test_blacklist_reload(checker, tmp_path):
    assert checker.check("ads.doubleclick.net") == "doubleclick.net"
    conn = db.connect(checker.db_path)
    add_domains(conn, ["newbad.example"], "test")
    assert checker.check("newbad.example") == "newbad.example"


# --- verdict engine -------------------------------------------------------- #
def test_blacklisted_blocked(checker):
    v = engine(checker).decide(inspect("beacon.malware-test.example", "A", "10.0.0.2"))
    assert v.verdict == BLOCKED and v.attack_type == MALICIOUS
    assert "blacklisted domain" in v.reason


@pytest.mark.parametrize("domain", LEGIT)
def test_legit_allowed(checker, domain):
    v = engine(checker).decide(inspect(domain, "A", "10.0.0.2"))
    assert v.verdict == ALLOWED, (domain, v.reason)


@pytest.mark.parametrize("domain", DGA)
def test_dga_flagged(checker, domain):
    v = engine(checker).decide(inspect(domain, "A", "10.0.0.2"))
    assert v.verdict in (BLOCKED, SUSPICIOUS), (domain, v)
    assert v.attack_type == SUSPICIOUS_NAME


def test_tunneling_payload_blocked(checker):
    data = base64.b32encode(b"secret payroll data for exfiltration test!!").decode().rstrip("=").lower()
    v = engine(checker).decide(inspect(f"{data}.0001.exfil.example", "TXT", "10.0.0.9"))
    assert v.verdict == BLOCKED and v.attack_type == TUNNELING


def test_tunneling_traffic_short_labels(checker):
    """Short random labels evade payload checks but the unique-subdomain count catches them."""
    e = engine(checker)
    verdicts = [e.decide(inspect(f"q{i:04x}.tun.example", "TXT", "10.0.0.9"), now=1000 + i * 0.1)
                for i in range(70)]
    assert verdicts[0].verdict == ALLOWED
    assert verdicts[-1].verdict == BLOCKED and verdicts[-1].attack_type == TUNNELING


def test_rate_limit_burst(checker):
    e = engine(checker)
    verdicts = [e.decide(inspect("example.com", "A", "10.0.0.7"), now=2000 + i * 0.01) for i in range(40)]
    limit = SETTINGS["client_domain_rate_limit"]
    assert all(v.verdict == ALLOWED for v in verdicts[:limit])
    assert verdicts[limit].verdict == BLOCKED and verdicts[limit].attack_type == EXCESSIVE
    # another client is unaffected
    assert e.decide(inspect("example.com", "A", "10.0.0.8"), now=2001).verdict == ALLOWED
    # and the window expires
    assert e.decide(inspect("example.com", "A", "10.0.0.7"), now=2000 + 60).verdict == ALLOWED


def test_allowlist_skips_name_checks(checker):
    v = engine(checker).decide(inspect("rr3---sn-a5mekn7s.googlevideo.com", "A", "10.0.0.2"))
    assert v.verdict == ALLOWED
