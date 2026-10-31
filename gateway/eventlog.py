"""SQLite Logging Layer (Section 4.6).

Events are queued by the request threads and written in batches by one
background thread, keeping disk I/O off the DNS hot path.
"""

import logging
import queue
import threading
import time

from . import db

log = logging.getLogger("gateway.eventlog")

INSERT = ("INSERT INTO events(ts, client, domain, qtype, verdict, reason, attack_type, "
          "score, rcode, answer, latency_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)")


class EventLogger:
    def __init__(self, db_path, batch_size=200, flush_interval=0.5):
        self.db_path = db_path
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._q = queue.Queue(maxsize=100_000)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="event-writer", daemon=True)
        self._thread.start()

    def log(self, ts, info, verdict, rcode, answer, latency_ms):
        row = (ts, info.client, info.domain, info.qtype, verdict.verdict, verdict.reason,
               verdict.attack_type, round(verdict.score, 3), rcode, answer, round(latency_ms, 2))
        try:
            self._q.put_nowait(row)
        except queue.Full:
            log.warning("event queue full, dropping log row for %s", info.domain)

    def _run(self):
        conn = db.connect(self.db_path)
        last_heartbeat = 0.0
        while not self._stop.is_set() or not self._q.empty():
            batch = []
            try:
                batch.append(self._q.get(timeout=self.flush_interval))
                while len(batch) < self.batch_size:
                    batch.append(self._q.get_nowait())
            except queue.Empty:
                pass
            if batch:
                try:
                    conn.executemany(INSERT, batch)
                    conn.commit()
                except Exception:
                    log.exception("failed to write %d events", len(batch))
            now = time.time()
            if now - last_heartbeat >= 5:
                last_heartbeat = now
                try:
                    db.set_meta(conn, "gateway_heartbeat", now)
                except Exception:
                    log.exception("failed to write heartbeat")
        conn.close()

    def close(self):
        self._stop.set()
        self._thread.join(timeout=5)
