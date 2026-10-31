"""Action Handler: Allow -> forward to Unbound, Block -> refuse/drop.

Blocked queries are answered locally and are never sent upstream, so a
blocked domain never resolves to an IP address.
"""

import logging
import time

from dnslib import AAAA, A, DNSRecord, QTYPE, RCODE, RR

log = logging.getLogger("gateway.action")


class ActionHandler:
    BACKOFF_SECONDS = 30  # skip a failed upstream for this long

    def __init__(self, upstreams, timeout=3.0, block_response="refused"):
        self.upstreams = upstreams
        self.timeout = timeout
        self.block_response = block_response
        self._down_until = {}

    @staticmethod
    def _key(up):
        return f"{up['host']}:{up['port']}"

    def forward(self, request, tcp=False):
        """Send the query to the first upstream (Unbound) that answers."""
        last_error = None
        now = time.monotonic()
        # Prefer upstreams that are not in back-off; fall back to all of them.
        candidates = [u for u in self.upstreams if self._down_until.get(self._key(u), 0) <= now]
        for up in candidates or self.upstreams:
            host, port = up["host"], int(up["port"])
            try:
                reply = DNSRecord.parse(request.send(host, port, tcp=tcp, timeout=self.timeout))
                # Retry over TCP if the UDP answer was truncated.
                if not tcp and reply.header.tc:
                    reply = DNSRecord.parse(request.send(host, port, tcp=True, timeout=self.timeout))
                self._down_until.pop(self._key(up), None)
                return reply
            except Exception as exc:  # timeout / refused / bad packet: try the next upstream
                last_error = exc
                if self._key(up) not in self._down_until:
                    log.warning("upstream %s:%s failed (%s); backing off %ds",
                                host, port, exc, self.BACKOFF_SECONDS)
                self._down_until[self._key(up)] = time.monotonic() + self.BACKOFF_SECONDS
        reply = request.reply()
        reply.header.rcode = RCODE.SERVFAIL
        log.error("all upstreams failed for %s: %s", request.q.qname, last_error)
        return reply

    def block(self, request):
        reply = request.reply()
        mode = self.block_response
        qtype = QTYPE.get(request.q.qtype)
        if mode == "sinkhole" and qtype in ("A", "AAAA"):
            rdata = A("0.0.0.0") if qtype == "A" else AAAA("::")
            reply.add_answer(RR(request.q.qname, request.q.qtype, rdata=rdata, ttl=60))
        elif mode == "nxdomain":
            reply.header.rcode = RCODE.NXDOMAIN
        else:
            reply.header.rcode = RCODE.REFUSED
        return reply


def summarise_answer(reply, limit=4):
    """Short text summary of the answer section for the event log."""
    parts = []
    for rr in reply.rr[:limit]:
        parts.append(f"{QTYPE.get(rr.rtype)} {str(rr.rdata)[:80]}")
    if len(reply.rr) > limit:
        parts.append(f"+{len(reply.rr) - limit} more")
    return ", ".join(parts) or None
