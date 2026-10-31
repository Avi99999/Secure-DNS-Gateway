"""Verdict Engine (Section 5.2).

Decision logic:
  1. domain (or a parent) is blacklisted      -> BLOCK, "blacklisted domain"
  2. heuristic composite score >= block_score -> BLOCK, detected attack type
  3. composite score >= suspicious_score      -> SUSPICIOUS (allowed, but alerted)
  4. otherwise                                -> ALLOW

The composite score is a noisy-OR of the individual finding scores,
1 - prod(1 - s_i), so several weak signals add up to a strong one while a
single weak signal stays below the block threshold.
"""

from dataclasses import dataclass, field

ALLOWED = "allowed"
BLOCKED = "blocked"
SUSPICIOUS = "suspicious"
MALICIOUS = "malicious_domain"


@dataclass
class Verdict:
    verdict: str
    score: float = 0.0
    reason: str = None
    attack_type: str = None
    findings: list = field(default_factory=list)

    @property
    def blocked(self):
        return self.verdict == BLOCKED


def composite_score(findings):
    remaining = 1.0
    for f in findings:
        remaining *= (1.0 - max(0.0, min(1.0, f.score)))
    return 1.0 - remaining


class VerdictEngine:
    def __init__(self, blacklist, detector, settings):
        self.blacklist = blacklist
        self.detector = detector
        self.block_score = settings["block_score"]
        self.suspicious_score = settings["suspicious_score"]

    def decide(self, info, now=None):
        allowlisted = self.blacklist.is_allowlisted(info.domain)

        # Behavioural state is always updated, even for blacklisted queries,
        # so that rate statistics reflect real traffic.
        findings = self.detector.analyse(info, skip_name_checks=allowlisted, now=now)

        hit = None if allowlisted else self.blacklist.check(info.domain)
        if hit:
            reason = "blacklisted domain" + (f" (matched {hit})" if hit != info.domain else "")
            return Verdict(BLOCKED, 1.0, reason, MALICIOUS, findings)

        if not findings:
            return Verdict(ALLOWED)

        score = composite_score(findings)
        top = max(findings, key=lambda f: f.score)
        reason = "; ".join(f.reason for f in sorted(findings, key=lambda f: -f.score))
        if score >= self.block_score:
            return Verdict(BLOCKED, score, reason, top.attack_type, findings)
        if score >= self.suspicious_score:
            return Verdict(SUSPICIOUS, score, reason, top.attack_type, findings)
        return Verdict(ALLOWED, score, None, None, findings)
