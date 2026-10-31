"""Blacklist Checker (Section 4.4).

The blacklist lives in the SQLite `blacklist` table (indexed by domain) so it
can be queried, edited from the dashboard, and grown from public feeds. For
hot-path speed the gateway keeps an in-memory copy that is reloaded whenever
the `blacklist_version` meta key changes.

Matching is suffix/parent based: if "evil.com" is listed, then
"a.b.evil.com" is also blocked.
"""

import re
import threading
import time
import urllib.request

from . import db

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_\-]{0,61}[a-z0-9_])?\.)+[a-z0-9\-]{2,63}$")
HOSTS_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1", "255.255.255.255"}
IGNORED = {"localhost", "localhost.localdomain", "local", "broadcasthost",
           "ip6-localhost", "ip6-loopback", "0.0.0.0"}


def normalise(domain):
    domain = domain.strip().lower().rstrip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    return domain


def parse_list(text):
    """Parse hosts-file format ("0.0.0.0 evil.com") or plain one-domain-per-line."""
    out = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        candidates = parts[1:] if parts[0] in HOSTS_IPS else parts[:1]
        for cand in candidates:
            d = normalise(cand)
            if d and d not in IGNORED and DOMAIN_RE.match(d):
                out.add(d)
    return out


def load_file_into_db(conn, path, source, category):
    with open(path, encoding="utf-8", errors="ignore") as fh:
        domains = parse_list(fh.read())
    return add_domains(conn, domains, source, category)


def fetch_feed(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "secure-dns-gateway/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def add_domains(conn, domains, source="manual", category="malicious"):
    now = time.time()
    before = conn.execute("SELECT COUNT(*) FROM blacklist").fetchone()[0]
    conn.executemany(
        "INSERT OR IGNORE INTO blacklist(domain, source, category, added_at) VALUES(?,?,?,?)",
        ((d, source, category, now) for d in domains))
    conn.commit()
    after = conn.execute("SELECT COUNT(*) FROM blacklist").fetchone()[0]
    db.bump_blacklist_version(conn)
    return after - before


def remove_domain(conn, domain):
    cur = conn.execute("DELETE FROM blacklist WHERE domain=?", (normalise(domain),))
    conn.commit()
    db.bump_blacklist_version(conn)
    return cur.rowcount


def load_allowlist(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return parse_list(fh.read())
    except FileNotFoundError:
        return set()


def suffix_match(domain, domains):
    """Return the listed entry matching `domain` or one of its parents, else None."""
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        if candidate in domains:
            return candidate
    return domain if domain in domains else None


class BlacklistChecker:
    def __init__(self, db_path, allowlist_path=None, refresh_seconds=10):
        self.db_path = db_path
        self.refresh_seconds = refresh_seconds
        self.allowlist = load_allowlist(allowlist_path) if allowlist_path else set()
        self._domains = set()
        self._version = None
        self._last_check = 0.0
        self._lock = threading.Lock()
        self._conn_lock = threading.Lock()
        self._conn = db.connect(db_path)
        self.reload(force=True)

    def __len__(self):
        return len(self._domains)

    def reload(self, force=False):
        with self._conn_lock:
            version = db.get_meta(self._conn, "blacklist_version")
            if not force and version == self._version:
                return False
            domains = {r[0] for r in self._conn.execute("SELECT domain FROM blacklist")}
        with self._lock:
            self._domains = domains
            self._version = version
        return True

    def _maybe_refresh(self):
        now = time.time()
        if now - self._last_check >= self.refresh_seconds:
            self._last_check = now
            try:
                self.reload()
            except Exception:  # never let a refresh failure break resolution
                pass

    def check(self, domain):
        """Return the matching blacklist entry, or None."""
        self._maybe_refresh()
        with self._lock:
            return suffix_match(domain, self._domains)

    def is_allowlisted(self, domain):
        return suffix_match(domain, self.allowlist) is not None
