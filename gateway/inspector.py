"""Domain Inspector: parses a raw DNS query and extracts domain features.

This is the "Parsing" step of Section 4.3. It produces a QueryInfo object
that the blacklist checker, attack detector and verdict engine all consume.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass, field

from dnslib import QTYPE

# Common multi-label public suffixes. Without a full Public Suffix List this
# keeps "example.co.uk" / "example.co.in" grouped correctly as one parent.
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "net.in", "org.in", "ac.in",
    "gov.in", "edu.in", "res.in", "nic.in", "com.au", "net.au", "org.au",
    "co.jp", "ne.jp", "or.jp", "com.br", "com.cn", "net.cn", "com.sg",
    "co.nz", "co.za", "com.mx", "com.tr", "co.kr", "com.hk", "com.tw",
    "github.io", "herokuapp.com", "cloudfront.net", "azurewebsites.net",
    "appspot.com", "blogspot.com", "s3.amazonaws.com",
}

VOWELS = set("aeiou")

# The ~150 most frequent English letter pairs. Human-chosen names are mostly
# built from these; algorithmically generated (DGA) names mostly are not.
COMMON_BIGRAMS = set("""
th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io
le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la ns di fo ho
pe ec pr no ct us ac ot il tr ly nc et ut ss so rs un lo wa ge ie wh ee wi em ad ol rt
po we na ul ni ts mo ow pa im mi ai sh ir su id os iv ia am fi ci vi pl ig tu ev ld ry
mp fe bl ab gh ty op wo sa ay ex ke fr oo av ag if ap gr od bo sp rd do uc bu ei ov by
rm ep tt oc fa ef cu rn sc gi da yo cr cl du ga qu ue ff ba ey ls va um pp ua up lu go
ht ru ug ds lt pi rc rr eg au ck ew mu br bi pt ak pu ui rg ib tl ny ki rk ys ob mm fu
ph og ms ye ud mb ip ub oi rl gu dr hr cc tw ft wn nu af hu nn eo vo rv nf xp gn sm fl
""".split())
BASE32_RE = re.compile(r"^[a-z2-7=]+$")
HEX_RE = re.compile(r"^[0-9a-f]+$")
BASE64ISH_RE = re.compile(r"^[a-z0-9_\-+/=]+$")


def shannon_entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def registered_domain(domain):
    """Return the parent ("registered") domain, e.g. a.b.example.co.uk -> example.co.uk."""
    labels = domain.split(".")
    if len(labels) <= 2:
        return domain
    for size in (3, 2):  # check the longest known suffix first
        if len(labels) > size and ".".join(labels[-size:]) in MULTI_LABEL_SUFFIXES:
            return ".".join(labels[-(size + 1):])
    return ".".join(labels[-2:])


def common_bigram_ratio(text):
    """Share of adjacent letter pairs that are common in English (None if too short)."""
    pairs = [text[i:i + 2] for i in range(len(text) - 1) if text[i:i + 2].isalpha()]
    if len(pairs) < 5:
        return None
    return sum(p in COMMON_BIGRAMS for p in pairs) / len(pairs)


def longest_consonant_run(text):
    best = run = 0
    for ch in text:
        if ch.isalpha() and ch not in VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


@dataclass
class QueryInfo:
    domain: str                 # normalised FQDN without trailing dot
    qtype: str                  # A, AAAA, TXT ...
    client: str                 # requesting client IP
    labels: list = field(default_factory=list)
    parent: str = ""            # registered domain
    subdomain: str = ""         # everything left of the parent
    sld: str = ""               # leftmost label of the parent (e.g. "google")
    qname_length: int = 0
    longest_label: int = 0
    subdomain_entropy: float = 0.0
    sld_entropy: float = 0.0
    sld_digit_ratio: float = 0.0
    sld_vowel_ratio: float = 0.0
    sld_consonant_run: int = 0
    sld_bigram_ratio: float = None
    subdomain_depth: int = 0
    subdomain_charset: str = ""  # base32 | hex | base64ish | text | ""


def inspect(domain, qtype, client):
    """Build a QueryInfo from an already-decoded domain and qtype."""
    domain = domain.rstrip(".").lower()
    labels = [l for l in domain.split(".") if l]
    parent = registered_domain(domain)
    subdomain = domain[: -len(parent)].rstrip(".") if domain != parent else ""
    sld = parent.split(".")[0] if parent else ""
    sub_flat = subdomain.replace(".", "")

    charset = ""
    if sub_flat:
        if HEX_RE.match(sub_flat):
            charset = "hex"
        elif BASE32_RE.match(sub_flat):
            charset = "base32"
        elif BASE64ISH_RE.match(sub_flat):
            charset = "base64ish"
        else:
            charset = "text"

    letters = [c for c in sld if c.isalpha()]
    return QueryInfo(
        domain=domain,
        qtype=qtype,
        client=client,
        labels=labels,
        parent=parent,
        subdomain=subdomain,
        sld=sld,
        qname_length=len(domain),
        longest_label=max((len(l) for l in labels), default=0),
        subdomain_entropy=shannon_entropy(sub_flat),
        sld_entropy=shannon_entropy(sld),
        sld_digit_ratio=(sum(c.isdigit() for c in sld) / len(sld)) if sld else 0.0,
        sld_vowel_ratio=(sum(c in VOWELS for c in letters) / len(letters)) if letters else 0.0,
        sld_consonant_run=longest_consonant_run(sld),
        sld_bigram_ratio=common_bigram_ratio(sld),
        subdomain_depth=len(subdomain.split(".")) if subdomain else 0,
        subdomain_charset=charset,
    )


def inspect_record(record, client):
    """Parse a dnslib DNSRecord (the raw query) into a QueryInfo."""
    q = record.q
    qtype = QTYPE.get(q.qtype, str(q.qtype))
    return inspect(str(q.qname), str(qtype), client)
