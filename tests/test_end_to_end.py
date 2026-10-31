"""End-to-end test: real UDP gateway in front of a fake 'Unbound' upstream.

  test client -> gateway (random port) -> fake upstream (random port)
then checks the SQLite log and the dashboard API.
"""

import socket
import time

import pytest
from dnslib import QTYPE, RCODE, RR, A, DNSRecord
from dnslib.server import BaseResolver, DNSServer

from dashboard.app import create_app
from gateway import db
from gateway.config import DEFAULTS, _merge
from gateway.server import QuietLogger, start_servers


class FakeUpstream(BaseResolver):
    def __init__(self):
        self.seen = []

    def resolve(self, request, handler):
        self.seen.append(str(request.q.qname).rstrip("."))
        reply = request.reply()
        if request.q.qtype == QTYPE.A:
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("93.184.216.34"), ttl=60))
        return reply


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def stack(tmp_path):
    upstream = FakeUpstream()
    up_port = free_port()
    up_server = DNSServer(upstream, address="127.0.0.1", port=up_port, logger=QuietLogger())
    up_server.start_thread()

    seed = tmp_path / "seed.txt"
    seed.write_text("malware-test.example\n")
    cfg = _merge(DEFAULTS, {
        "listen_address": "127.0.0.1", "listen_port": free_port(), "enable_tcp": False,
        "upstreams": [{"host": "127.0.0.1", "port": up_port}], "upstream_timeout": 1,
        "database": str(tmp_path / "e2e.db"), "blacklist_seed": str(seed),
        "allowlist_file": str(tmp_path / "none.txt"), "blacklist_refresh_seconds": 0,
        "dashboard": {"username": "", "password": ""},
    })
    cfg["_path"] = "test"
    servers, events = start_servers(cfg)
    yield cfg, upstream
    for s in servers:
        s.stop()
    events.close()
    up_server.stop()


def ask(cfg, name, qtype="A"):
    raw = DNSRecord.question(name, qtype).send("127.0.0.1", cfg["listen_port"], timeout=3)
    return DNSRecord.parse(raw)


def test_full_pipeline(stack):
    cfg, upstream = stack

    ok = ask(cfg, "example.com")
    assert RCODE.get(ok.header.rcode) == "NOERROR" and str(ok.rr[0].rdata) == "93.184.216.34"

    bad = ask(cfg, "c2.malware-test.example")
    assert RCODE.get(bad.header.rcode) == "REFUSED"
    assert "c2.malware-test.example" not in upstream.seen  # never forwarded

    tunnel = ask(cfg, "mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dzpiytemzu.gm5tqojqgezdgnbv.exfil.example", "TXT")
    assert RCODE.get(tunnel.header.rcode) == "REFUSED"

    time.sleep(1.2)  # let the batch writer flush
    conn = db.connect(cfg["database"])
    rows = {r["domain"]: dict(r) for r in conn.execute("SELECT * FROM events")}
    assert rows["example.com"]["verdict"] == "allowed"
    assert rows["c2.malware-test.example"]["verdict"] == "blocked"
    assert rows["c2.malware-test.example"]["attack_type"] == "malicious_domain"
    tunnel_row = next(r for d, r in rows.items() if d.endswith("exfil.example"))
    assert tunnel_row["attack_type"] == "dns_tunneling"

    client = create_app(cfg).test_client()
    s = client.get("/api/summary?range=1h").get_json()
    assert s["total"] == 3 and s["blocked"] == 2 and s["allowed"] == 1
    assert s["gateway"]["online"] is True
    assert client.get("/api/timeseries?range=15m").status_code == 200
    ev = client.get("/api/events?verdict=blocked").get_json()
    assert ev["total"] == 2
    assert client.get("/").status_code == 200
    assert client.get("/events.csv").status_code == 200

    # Dashboard blacklist edit is picked up by the running gateway.
    r = client.post("/api/blacklist", json={"domains": "example.org, not a domain"}).get_json()
    assert r["added"] == 1 and r["invalid"]
    time.sleep(0.05)
    assert RCODE.get(ask(cfg, "www.example.org").header.rcode) == "REFUSED"
    assert client.delete("/api/blacklist/example.org").get_json()["removed"] == 1
