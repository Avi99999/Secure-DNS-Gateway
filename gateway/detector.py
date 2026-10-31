"""Attack Detector (Section 4.5).

Each check returns zero or more Findings: a weak signal with an attack type,
a score in 0..1 and a human-readable reason. The verdict engine combines
them, so no single indicator has to be perfect.

Attack types produced here:
  dns_tunneling       payload or traffic indicators of data hidden in DNS
  excessive_requests  sliding-window rate exceeded per client / client+domain
  suspicious_domain   DGA-like or random-looking names, newly-seen bursts
"""

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

TUNNELING = "dns_tunneling"
EXCESSIVE = "excessive_requests"
SUSPICIOUS_NAME = "suspicious_domain"

TUNNEL_QTYPES = {"TXT", "NULL", "CNAME", "MX", "ANY"}


@dataclass
class Finding:
    attack_type: str
    score: float
    reason: str


def _over_limit_score(count, limit, base=0.5):
    """Score that starts at `base` when the limit is crossed and reaches 1.0 at 2x."""
    if count <= limit:
        return 0.0
    return min(1.0, base + (1.0 - base) * (count - limit) / max(limit, 1))


class SlidingWindow:
    """Per-key timestamp counter over a sliding time window."""

    def __init__(self, window):
        self.window = window
        self._data = defaultdict(deque)

    def add(self, key, now):
        q = self._data[key]
        q.append(now)
        self._trim(q, now)
        return len(q)

    def _trim(self, q, now):
        cutoff = now - self.window
        while q and q[0] < cutoff:
            q.popleft()

    def prune(self, now):
        for key in list(self._data):
            self._trim(self._data[key], now)
            if not self._data[key]:
                del self._data[key]


class UniqueWindow:
    """Number of distinct values seen per key over a sliding time window."""

    def __init__(self, window):
        self.window = window
        self._data = defaultdict(deque)            # key -> deque[(ts, value)]
        self._counts = defaultdict(lambda: defaultdict(int))

    def add(self, key, value, now):
        q, counts = self._data[key], self._counts[key]
        q.append((now, value))
        counts[value] += 1
        self._trim(key, now)
        return len(counts)

    def _trim(self, key, now):
        q, counts = self._data[key], self._counts[key]
        cutoff = now - self.window
        while q and q[0][0] < cutoff:
            _, old = q.popleft()
            counts[old] -= 1
            if counts[old] <= 0:
                del counts[old]

    def prune(self, now):
        for key in list(self._data):
            self._trim(key, now)
            if not self._data[key]:
                del self._data[key]
                self._counts.pop(key, None)


class AttackDetector:
    def __init__(self, settings):
        self.s = settings
        self._lock = threading.Lock()
        self.client_rate = SlidingWindow(settings["rate_window_seconds"])
        self.pair_rate = SlidingWindow(settings["rate_window_seconds"])
        self.tunnel_qtypes = SlidingWindow(settings["tunnel_window_seconds"])
        self.unique_subs = UniqueWindow(settings["tunnel_window_seconds"])
        self.domain_rate = SlidingWindow(settings["newly_seen_window_seconds"])
        self.first_seen = {}
        self._last_prune = time.time()

    # ------------------------------------------------------------------ #
    def analyse(self, info, skip_name_checks=False, now=None):
        """Update behavioural state with this query and return all findings."""
        now = now or time.time()
        findings = []
        with self._lock:
            findings += self._rate_checks(info, now)
            findings += self._tunnel_traffic_checks(info, now)
            findings += self._newly_seen_check(info, now)
            self._maybe_prune(now)
        if not skip_name_checks:
            findings += self.payload_checks(info)
            findings += self.naming_checks(info)
        return findings

    # ---- payload analysis: tunneling ---------------------------------- #
    def payload_checks(self, info):
        s, out = self.s, []
        if info.longest_label > s["max_label_length"]:
            out.append(Finding(TUNNELING, 0.6,
                               f"label of {info.longest_label} chars (limit {s['max_label_length']})"))
        if info.qname_length > s["max_qname_length"]:
            out.append(Finding(TUNNELING, 0.4,
                               f"query name of {info.qname_length} chars (limit {s['max_qname_length']})"))
        sub_len = len(info.subdomain.replace(".", ""))
        if sub_len >= s["entropy_min_length"] and info.subdomain_entropy >= s["entropy_threshold"]:
            score = 0.5
            if info.subdomain_charset in ("base32", "hex", "base64ish"):
                score = 0.65
            out.append(Finding(TUNNELING, score,
                               f"high-entropy subdomain ({info.subdomain_entropy:.2f} bits, "
                               f"{info.subdomain_charset or 'mixed'} charset)"))
        if info.subdomain_depth >= 6:
            out.append(Finding(TUNNELING, 0.3, f"excessive subdomain nesting ({info.subdomain_depth} levels)"))
        return out

    # ---- traffic analysis: tunneling ---------------------------------- #
    def _tunnel_traffic_checks(self, info, now):
        s, out = self.s, []
        if info.qtype in TUNNEL_QTYPES and info.subdomain:
            n = self.tunnel_qtypes.add(info.parent, now)
            score = _over_limit_score(n, s["txt_null_limit"], base=0.6)
            if score:
                out.append(Finding(TUNNELING, score,
                                   f"{n} {'/'.join(sorted(TUNNEL_QTYPES))} queries to {info.parent} "
                                   f"in {s['tunnel_window_seconds']}s"))
        if info.subdomain:
            n = self.unique_subs.add(info.parent, info.subdomain, now)
            score = _over_limit_score(n, s["unique_subdomain_limit"], base=0.5)
            if score:
                out.append(Finding(TUNNELING, score,
                                   f"{n} unique subdomains of {info.parent} in {s['tunnel_window_seconds']}s"))
        return out

    # ---- excessive request volume ------------------------------------- #
    def _rate_checks(self, info, now):
        s, out = self.s, []
        n = self.client_rate.add(info.client, now)
        if n > s["client_rate_limit"]:
            out.append(Finding(EXCESSIVE, max(0.8, _over_limit_score(n, s["client_rate_limit"])),
                               f"client sent {n} queries in {s['rate_window_seconds']}s "
                               f"(limit {s['client_rate_limit']})"))
        n = self.pair_rate.add((info.client, info.domain), now)
        if n > s["client_domain_rate_limit"]:
            out.append(Finding(EXCESSIVE, max(0.8, _over_limit_score(n, s["client_domain_rate_limit"])),
                               f"{n} queries for {info.domain} in {s['rate_window_seconds']}s "
                               f"(limit {s['client_domain_rate_limit']})"))
        return out

    # ---- suspicious naming / DGA -------------------------------------- #
    def naming_checks(self, info):
        s, sld, out = self.s, info.sld, []
        if not sld or sld.startswith("xn--"):  # skip punycode (internationalised) names
            return out
        signals = []
        # High entropy alone is common in long real words, so it stays a weak signal.
        if len(sld) >= s["dga_min_length"] and info.sld_entropy >= s["dga_entropy_threshold"]:
            signals.append((0.3, f"high-entropy name ({info.sld_entropy:.2f} bits)"))
        if len(sld) >= 10 and info.sld_bigram_ratio is not None \
                and info.sld_bigram_ratio < s["bigram_ratio_threshold"]:
            signals.append((0.5, f"unpronounceable / random-looking name "
                                 f"({info.sld_bigram_ratio:.0%} common letter pairs)"))
        if len(sld) >= 8 and info.sld_digit_ratio >= s["digit_ratio_threshold"]:
            signals.append((0.4, f"high digit density ({info.sld_digit_ratio:.0%})"))
        switches = sum(a.isdigit() != b.isdigit() for a, b in zip(sld, sld[1:]))
        if switches >= 4:
            signals.append((0.4, f"letters and digits interleaved ({switches} switches)"))
        if info.sld_consonant_run >= s["consonant_run_threshold"]:
            signals.append((0.3, f"{info.sld_consonant_run} consecutive consonants"))
        if len(sld) >= 10 and info.sld_vowel_ratio < 0.2:
            signals.append((0.3, f"very low vowel ratio ({info.sld_vowel_ratio:.0%})"))
        for score, reason in signals:
            out.append(Finding(SUSPICIOUS_NAME, score, f"{reason} in '{sld}'"))
        return out

    def _newly_seen_check(self, info, now):
        s = self.s
        first = self.first_seen.setdefault(info.parent, now)
        n = self.domain_rate.add(info.parent, now)
        if now - first <= s["newly_seen_window_seconds"] and n > s["newly_seen_query_limit"]:
            return [Finding(SUSPICIOUS_NAME, _over_limit_score(n, s["newly_seen_query_limit"], 0.4),
                            f"newly-seen domain {info.parent} queried {n} times in "
                            f"{int(now - first) or 1}s")]
        return []

    def _maybe_prune(self, now):
        if now - self._last_prune < 30:
            return
        self._last_prune = now
        for w in (self.client_rate, self.pair_rate, self.tunnel_qtypes, self.unique_subs, self.domain_rate):
            w.prune(now)
        # forget first-seen times older than an hour to bound memory
        cutoff = now - 3600
        self.first_seen = {k: v for k, v in self.first_seen.items() if v >= cutoff}
