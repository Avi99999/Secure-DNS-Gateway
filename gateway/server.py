"""DNS server glue: wires the pipeline of Figure 2 together.

  Incoming query -> Domain Inspector -> Verdict Engine (Blacklist Checker +
  Attack Detector) -> Action Handler (forward to Unbound / block)
                   -> Event Logger (SQLite, every request)
"""

import logging
import socket
import sys
import time

from dnslib import RCODE
from dnslib.server import BaseResolver, DNSLogger, DNSServer, TCPServer, UDPServer

from . import db
from .action import ActionHandler, summarise_answer
from .blacklist import BlacklistChecker, load_file_into_db
from .detector import AttackDetector
from .eventlog import EventLogger
from .inspector import inspect_record
from .verdict import VerdictEngine

log = logging.getLogger("gateway")


class SecurityResolver(BaseResolver):
    def __init__(self, engine, action, events):
        self.engine = engine
        self.action = action
        self.events = events

    def resolve(self, request, handler):
        start = time.perf_counter()
        ts = time.time()
        client = handler.client_address[0]
        tcp = handler.protocol == "tcp"
        try:
            info = inspect_record(request, client)
        except Exception:
            reply = request.reply()
            reply.header.rcode = RCODE.FORMERR
            return reply

        verdict = self.engine.decide(info, now=ts)
        if verdict.blocked:
            reply = self.action.block(request)
            log.info("BLOCK %-15s %-5s %s [%s] %s", client, info.qtype, info.domain,
                     verdict.attack_type, verdict.reason)
        else:
            reply = self.action.forward(request, tcp=tcp)
            if verdict.verdict == "suspicious":
                log.info("ALERT %-15s %-5s %s [%s] %s", client, info.qtype, info.domain,
                         verdict.attack_type, verdict.reason)

        latency = (time.perf_counter() - start) * 1000
        self.events.log(ts, info, verdict, RCODE.get(reply.header.rcode),
                        summarise_answer(reply), latency)
        return reply


class QuietLogger(DNSLogger):
    """Silence dnslib's per-packet logging; we do our own."""

    def __init__(self):
        super().__init__(log="-request,-reply,-truncated,-data,-recv,-send,+error")


def build_pipeline(cfg):
    conn = db.init_db(cfg["database"])
    count = conn.execute("SELECT COUNT(*) FROM blacklist").fetchone()[0]
    if count == 0:
        try:
            added = load_file_into_db(conn, cfg["blacklist_seed"], "seed", "malicious")
            log.info("loaded %d seed blacklist entries from %s", added, cfg["blacklist_seed"])
        except FileNotFoundError:
            log.warning("blacklist seed file not found: %s", cfg["blacklist_seed"])
    db.set_meta(conn, "gateway_started", time.time())
    conn.close()

    blacklist = BlacklistChecker(cfg["database"], cfg["allowlist_file"], cfg["blacklist_refresh_seconds"])
    detector = AttackDetector(cfg["detection"])
    engine = VerdictEngine(blacklist, detector, cfg["detection"])
    action = ActionHandler(cfg["upstreams"], cfg["upstream_timeout"], cfg["block_response"])
    events = EventLogger(cfg["database"])
    return SecurityResolver(engine, action, events), blacklist, events


class _ExclusiveBind:
    """On Windows, SO_REUSEADDR lets a second program silently bind a port that is
    already in use, and queries are then split between the two. Claim the port
    exclusively instead, so a conflict fails loudly at startup."""

    def server_bind(self):
        if sys.platform == "win32":
            self.allow_reuse_address = False
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


class ExclusiveUDPServer(_ExclusiveBind, UDPServer):
    pass


class ExclusiveTCPServer(_ExclusiveBind, TCPServer):
    pass


def listen_addresses(setting):
    """Resolve listen_address: one address, a list, or "auto" (loopback + every LAN IPv4).

    "auto" binds specific addresses rather than 0.0.0.0, so the gateway takes
    priority over a wildcard listener such as Windows Internet Connection Sharing.
    """
    if isinstance(setting, list):
        return setting
    if setting != "auto":
        return [setting]
    addrs = {"127.0.0.1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addrs.add(info[4][0])
    except OSError:
        pass
    return sorted(a for a in addrs if not a.startswith("169.254."))


def start_servers(cfg):
    resolver, blacklist, events = build_pipeline(cfg)
    port = int(cfg["listen_port"])
    kinds = [("udp", ExclusiveUDPServer)] + ([("tcp", ExclusiveTCPServer)] if cfg["enable_tcp"] else [])
    servers, bound = [], []
    for addr in listen_addresses(cfg["listen_address"]):
        try:
            pair = [DNSServer(resolver, address=addr, port=port, server=cls, logger=QuietLogger())
                    for _, cls in kinds]
        except OSError as exc:
            log.error("cannot listen on %s:%d (%s) - another program is using this port. On Windows "
                      "this is often Internet Connection Sharing / Mobile Hotspot; try "
                      "\"listen_address\": \"auto\" or stop that service.", addr, port, exc)
            continue
        servers += pair
        bound.append(addr)
    if not servers:
        events.close()
        raise SystemExit(f"Secure DNS Gateway could not bind port {port} on any address")
    for s in servers:
        s.start_thread()
    ups = ", ".join(f"{u['host']}:{u['port']}" for u in cfg["upstreams"])
    log.info("Secure DNS Gateway listening on %s port %d (%s) -> upstream %s | %d blacklisted domains",
             ", ".join(bound), port, "+".join(k for k, _ in kinds), ups, len(blacklist))
    return servers, events


def run(cfg):
    servers, events = start_servers(cfg)
    try:
        while all(s.isAlive() for s in servers):
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        for s in servers:
            s.stop()
        events.close()
