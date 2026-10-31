"""Monitoring Layer - Flask dashboard (Section 4.7).

Reads the SQLite event log written by the gateway and presents live and
historical telemetry: totals, allowed vs blocked vs suspicious, attack-type
breakdown, top domains / clients, a live event feed with alerts, a searchable
event log with CSV export, and blacklist management.
"""

import csv
import io
import time

from flask import Flask, Response, g, jsonify, render_template, request

from gateway import __version__, db
from gateway.blacklist import DOMAIN_RE, add_domains, normalise, remove_domain

RANGES = {  # name -> (seconds, bucket seconds for the timeline)
    "15m": (900, 30),
    "1h": (3600, 60),
    "24h": (86400, 1800),
    "7d": (604800, 21600),
}
ATTACK_LABELS = {
    "malicious_domain": "Blacklisted domain",
    "dns_tunneling": "DNS tunneling",
    "excessive_requests": "Excessive requests",
    "suspicious_domain": "Suspicious naming / DGA",
}


def create_app(cfg):
    app = Flask(__name__)
    app.config["GATEWAY_CFG"] = cfg
    db.init_db(cfg["database"]).close()
    auth_user = cfg["dashboard"].get("username")
    auth_pass = cfg["dashboard"].get("password")

    # ---------------------------------------------------------------- helpers
    def conn():
        if "db" not in g:
            g.db = db.connect(cfg["database"])
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        c = g.pop("db", None)
        if c is not None:
            c.close()

    @app.before_request
    def require_auth():
        if not (auth_user and auth_pass):
            return None
        a = request.authorization
        if a and a.username == auth_user and a.password == auth_pass:
            return None
        return Response("Authentication required", 401,
                        {"WWW-Authenticate": 'Basic realm="Secure DNS Gateway"'})

    def since_ts():
        rng = request.args.get("range", "1h")
        if rng == "all":
            return 0.0, rng
        seconds = RANGES.get(rng, RANGES["1h"])[0]
        return time.time() - seconds, rng

    def rows(sql, params=()):
        return [dict(r) for r in conn().execute(sql, params).fetchall()]

    def gateway_status():
        hb = db.get_meta(conn(), "gateway_heartbeat")
        started = db.get_meta(conn(), "gateway_started")
        age = time.time() - float(hb) if hb else None
        return {
            "online": age is not None and age < 15,
            "last_heartbeat_age": round(age, 1) if age is not None else None,
            "started": float(started) if started else None,
        }

    # ------------------------------------------------------------------ pages
    @app.route("/")
    def index():
        return render_template("index.html", page="overview", version=__version__)

    @app.route("/events")
    def events_page():
        return render_template("events.html", page="events", version=__version__,
                               attack_labels=ATTACK_LABELS)

    @app.route("/blacklist")
    def blacklist_page():
        return render_template("blacklist.html", page="blacklist", version=__version__)

    @app.route("/settings")
    def settings_page():
        shown = {k: v for k, v in cfg.items() if k not in ("dashboard", "_path")}
        return render_template("settings.html", page="settings", version=__version__,
                               cfg=shown, cfg_path=cfg["_path"])

    # -------------------------------------------------------------------- API
    @app.route("/api/summary")
    def api_summary():
        since, rng = since_ts()
        totals = {r["verdict"]: r["n"] for r in rows(
            "SELECT verdict, COUNT(*) n FROM events WHERE ts>=? GROUP BY verdict", (since,))}
        total = sum(totals.values())
        attacks = rows("SELECT attack_type, COUNT(*) n FROM events WHERE ts>=? AND attack_type IS NOT NULL "
                       "GROUP BY attack_type ORDER BY n DESC", (since,))
        for a in attacks:
            a["label"] = ATTACK_LABELS.get(a["attack_type"], a["attack_type"])
        lat = conn().execute("SELECT AVG(latency_ms) FROM events WHERE ts>=? AND verdict!='blocked'",
                             (since,)).fetchone()[0]
        return jsonify({
            "range": rng,
            "total": total,
            "allowed": totals.get("allowed", 0),
            "blocked": totals.get("blocked", 0),
            "suspicious": totals.get("suspicious", 0),
            "block_rate": round(100 * totals.get("blocked", 0) / total, 1) if total else 0,
            "avg_latency_ms": round(lat, 1) if lat else None,
            "attack_types": attacks,
            "top_blocked": rows("SELECT domain, attack_type, COUNT(*) n FROM events WHERE ts>=? "
                                "AND verdict='blocked' GROUP BY domain ORDER BY n DESC LIMIT 8", (since,)),
            "top_domains": rows("SELECT domain, COUNT(*) n FROM events WHERE ts>=? "
                                "GROUP BY domain ORDER BY n DESC LIMIT 8", (since,)),
            "top_clients": rows("SELECT client, COUNT(*) n, SUM(verdict='blocked') blocked FROM events "
                                "WHERE ts>=? GROUP BY client ORDER BY n DESC LIMIT 8", (since,)),
            "blacklist_size": conn().execute("SELECT COUNT(*) FROM blacklist").fetchone()[0],
            "gateway": gateway_status(),
        })

    @app.route("/api/timeseries")
    def api_timeseries():
        rng = request.args.get("range", "1h")
        seconds, bucket = RANGES.get(rng, RANGES["1h"])
        now = time.time()
        start = (int(now - seconds) // bucket) * bucket
        data = rows("SELECT CAST(ts / ? AS INTEGER) * ? AS b, verdict, COUNT(*) n FROM events "
                    "WHERE ts>=? GROUP BY b, verdict", (bucket, bucket, start))
        series = {v: {} for v in ("allowed", "blocked", "suspicious")}
        for d in data:
            series.setdefault(d["verdict"], {})[d["b"]] = d["n"]
        buckets = list(range(start, int(now) + 1, bucket))
        return jsonify({
            "bucket_seconds": bucket,
            "labels": buckets,
            "allowed": [series["allowed"].get(b, 0) for b in buckets],
            "blocked": [series["blocked"].get(b, 0) for b in buckets],
            "suspicious": [series["suspicious"].get(b, 0) for b in buckets],
        })

    def event_filters():
        where, params = [], []
        since, _ = since_ts()
        if since:
            where.append("ts>=?"); params.append(since)
        verdict = request.args.get("verdict")
        if verdict in ("allowed", "blocked", "suspicious"):
            where.append("verdict=?"); params.append(verdict)
        elif verdict == "alerts":
            where.append("verdict IN ('blocked','suspicious')")
        attack = request.args.get("attack_type")
        if attack:
            where.append("attack_type=?"); params.append(attack)
        q = request.args.get("q", "").strip().lower()
        if q:
            where.append("(domain LIKE ? OR client LIKE ?)"); params += [f"%{q}%", f"%{q}%"]
        since_id = request.args.get("since_id", type=int)
        if since_id:
            where.append("id>?"); params.append(since_id)
        return (" WHERE " + " AND ".join(where)) if where else "", params

    @app.route("/api/events")
    def api_events():
        clause, params = event_filters()
        limit = min(request.args.get("limit", 50, type=int), 500)
        offset = request.args.get("offset", 0, type=int)
        total = conn().execute(f"SELECT COUNT(*) FROM events{clause}", params).fetchone()[0]
        items = rows(f"SELECT * FROM events{clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                     params + [limit, offset])
        return jsonify({"total": total, "items": items})

    @app.route("/events.csv")
    def events_csv():
        clause, params = event_filters()
        cur = conn().execute(f"SELECT * FROM events{clause} ORDER BY id DESC LIMIT 100000", params)
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([c[0] for c in cur.description] + ["time_utc"])
        for r in cur:
            writer.writerow(list(r) + [time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(r["ts"]))])
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=dns_events.csv"})

    @app.route("/api/blacklist", methods=["GET"])
    def api_blacklist_list():
        q = request.args.get("q", "").strip().lower()
        limit = min(request.args.get("limit", 50, type=int), 500)
        offset = request.args.get("offset", 0, type=int)
        where, params = ("WHERE domain LIKE ?", [f"%{q}%"]) if q else ("", [])
        total = conn().execute(f"SELECT COUNT(*) FROM blacklist {where}", params).fetchone()[0]
        items = rows(f"SELECT * FROM blacklist {where} ORDER BY added_at DESC, domain LIMIT ? OFFSET ?",
                     params + [limit, offset])
        sources = rows("SELECT source, COUNT(*) n FROM blacklist GROUP BY source ORDER BY n DESC")
        return jsonify({"total": total, "items": items, "sources": sources})

    @app.route("/api/blacklist", methods=["POST"])
    def api_blacklist_add():
        data = request.get_json(silent=True) or {}
        raw = data.get("domains") or data.get("domain") or ""
        candidates = raw if isinstance(raw, list) else raw.replace(",", "\n").split()
        domains = {normalise(d) for d in candidates}
        valid = sorted(d for d in domains if DOMAIN_RE.match(d))
        invalid = sorted(domains - set(valid))
        added = add_domains(conn(), valid, "manual", data.get("category") or "malicious") if valid else 0
        return jsonify({"added": added, "valid": valid, "invalid": invalid})

    @app.route("/api/blacklist/<path:domain>", methods=["DELETE"])
    def api_blacklist_delete(domain):
        return jsonify({"removed": remove_domain(conn(), domain)})

    @app.route("/api/health")
    def api_health():
        return jsonify({"ok": True, "gateway": gateway_status(), "version": __version__})

    return app
