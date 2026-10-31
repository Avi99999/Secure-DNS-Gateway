"""Measure the latency the Python security layer adds on top of Unbound.

For each domain it queries Unbound directly and through the gateway with a
warm cache, so the difference is the inspection overhead alone (Section 6,
"acceptable performance overhead"). Rounds are spaced out so the gateway's
own rate limits are never triggered.

  python scripts/benchmark_latency.py --gateway 127.0.0.1:53 --unbound 127.0.0.1:5335
"""

import argparse
import statistics
import sys
import time

from dnslib import DNSRecord

DOMAINS = ["google.com", "wikipedia.org", "github.com", "microsoft.com", "amazon.in",
           "nmims.edu", "stackoverflow.com", "python.org", "cloudflare.com", "youtube.com",
           "linkedin.com", "bbc.co.uk", "apple.com", "netflix.com", "reddit.com",
           "mozilla.org", "ubuntu.com", "docker.com", "flipkart.com", "irctc.co.in"]


def timed(host, port, name, timeout=4.0):
    start = time.perf_counter()
    try:
        DNSRecord.question(name).send(host, port, timeout=timeout)
    except Exception:
        return None
    return (time.perf_counter() - start) * 1000


def hostport(text):
    host, _, port = text.rpartition(":")
    return host, int(port)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--gateway", default="127.0.0.1:53")
    p.add_argument("--unbound", default="127.0.0.1:5335")
    p.add_argument("--public", default="1.1.1.1:53", help="public resolver for reference")
    p.add_argument("--rounds", type=int, default=5)
    args = p.parse_args(argv)
    gw, ub, pub = hostport(args.gateway), hostport(args.unbound), hostport(args.public)

    cold = [timed(*gw, d) for d in DOMAINS]  # first lookup also warms Unbound's cache
    samples = {"gateway": [], "unbound": [], "public": []}
    for _ in range(args.rounds):
        for d in DOMAINS:
            for key, target in (("unbound", ub), ("gateway", gw), ("public", pub)):
                t = timed(*target, d)
                if t is not None:
                    samples[key].append(t)
        time.sleep(2.5)

    def stats(values):
        values = sorted(values)
        p95 = values[int(0.95 * (len(values) - 1))]
        return f"median {statistics.median(values):6.2f} ms   mean {statistics.mean(values):6.2f} ms   p95 {p95:6.2f} ms   (n={len(values)})"

    cold_ok = [c for c in cold if c is not None]
    print(f"Domains: {len(DOMAINS)}, warm rounds: {args.rounds}")
    print(f"  gateway, first lookup : {stats(cold_ok)}")
    print(f"  gateway, warm cache   : {stats(samples['gateway'])}")
    print(f"  Unbound direct, warm  : {stats(samples['unbound'])}")
    print(f"  public {args.public:<14} : {stats(samples['public'])}")
    overhead = statistics.median(samples["gateway"]) - statistics.median(samples["unbound"])
    print(f"  => inspection overhead (median gateway - median Unbound): {overhead:+.2f} ms")
    return 0


if __name__ == "__main__":
    sys.exit(main())
