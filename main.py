"""Secure DNS Gateway - command line entry point.

  python main.py gateway            run the DNS security gateway
  python main.py dashboard          run the Flask monitoring dashboard
  python main.py all                run both in one process
  python main.py init-db            create the database and load the seed blacklist
  python main.py update-blacklist   download the public feeds listed in the config
  python main.py blacklist add|remove|check DOMAIN
  python main.py simulate           run the validation test scenarios (Section 4.8)

Add  --config config.dev.json  to any command to use the local dev config.
"""

import argparse
import logging
import os
import socket
import sys

from gateway import db
from gateway.blacklist import add_domains, fetch_feed, load_file_into_db, parse_list, remove_domain, suffix_match
from gateway.config import load_config


def cmd_gateway(cfg, args):
    from gateway.server import run
    run(cfg)


def ensure_port_free(host, port):
    """Werkzeug binds with SO_REUSEADDR, which on Windows lets two dashboards share
    a port and serve each other's requests. Probe it exclusively first."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if sys.platform == "win32":
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    try:
        probe.bind((host, port))
    except OSError:
        sys.exit(f"dashboard port {host}:{port} is already in use - is another gateway "
                 f"or dashboard still running?")
    finally:
        probe.close()


def cmd_dashboard(cfg, args):
    from dashboard.app import create_app
    app = create_app(cfg)
    d = cfg["dashboard"]
    ensure_port_free(d["host"], int(d["port"]))
    logging.getLogger("werkzeug").setLevel(logging.WARNING)  # hide per-request access logs
    logging.info("dashboard on http://%s:%s", d["host"], d["port"])
    app.run(host=d["host"], port=int(d["port"]), debug=False, threaded=True, use_reloader=False)


def cmd_all(cfg, args):
    from gateway.server import start_servers
    servers, events = start_servers(cfg)
    try:
        cmd_dashboard(cfg, args)
    finally:
        for s in servers:
            s.stop()
        events.close()


def cmd_init_db(cfg, args):
    conn = db.init_db(cfg["database"])
    added = load_file_into_db(conn, cfg["blacklist_seed"], "seed", "malicious")
    total = conn.execute("SELECT COUNT(*) FROM blacklist").fetchone()[0]
    print(f"database ready at {cfg['database']}: +{added} seed entries, {total} blacklisted domains")


def cmd_update_blacklist(cfg, args):
    conn = db.init_db(cfg["database"])
    load_file_into_db(conn, cfg["blacklist_seed"], "seed", "malicious")
    feeds = cfg["blacklist_feeds"]
    if args.feed:
        feeds = [f for f in feeds if f["name"] in args.feed]
    for feed in feeds:
        try:
            print(f"downloading {feed['name']} from {feed['url']} ...", flush=True)
            domains = parse_list(fetch_feed(feed["url"]))
            added = add_domains(conn, domains, feed["name"], feed.get("category", "malicious"))
            print(f"  {len(domains)} domains parsed, {added} new")
        except Exception as exc:
            print(f"  failed: {exc}")
    if args.file:
        for path in args.file:
            added = load_file_into_db(conn, path, os.path.basename(path), "custom")
            print(f"{path}: {added} new")
    total = conn.execute("SELECT COUNT(*) FROM blacklist").fetchone()[0]
    print(f"blacklist now holds {total} domains (a running gateway picks this up within "
          f"{cfg['blacklist_refresh_seconds']}s)")


def cmd_blacklist(cfg, args):
    conn = db.init_db(cfg["database"])
    if args.action == "add":
        n = add_domains(conn, [d.lower().rstrip(".") for d in args.domains], "manual", args.category)
        print(f"added {n}")
    elif args.action == "remove":
        for d in args.domains:
            print(f"{d}: {'removed' if remove_domain(conn, d) else 'not found'}")
    else:
        domains = {r[0] for r in conn.execute("SELECT domain FROM blacklist")}
        for d in args.domains:
            hit = suffix_match(d.lower().rstrip("."), domains)
            print(f"{d}: {'BLACKLISTED (matched ' + hit + ')' if hit else 'not listed'}")


def cmd_simulate(cfg, args):
    from scripts.simulate_traffic import main as simulate
    listen = cfg["listen_address"]
    default_server = listen if isinstance(listen, str) and listen not in ("0.0.0.0", "", "auto") else "127.0.0.1"
    argv = ["--server", args.server or default_server, "--port", str(args.port or cfg["listen_port"])]
    if args.scenario:
        argv += ["--scenario", args.scenario]
    sys.exit(simulate(argv))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Secure DNS Gateway")
    parser.add_argument("--config", help="path to config JSON (default: config.json)")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("gateway", help="run the DNS security gateway")
    sub.add_parser("dashboard", help="run the Flask dashboard")
    sub.add_parser("all", help="run gateway and dashboard together")
    sub.add_parser("init-db", help="create database and load seed blacklist")
    p = sub.add_parser("update-blacklist", help="download public blacklist feeds")
    p.add_argument("--feed", action="append", help="only this feed name (repeatable)")
    p.add_argument("--file", action="append", help="also import a local list file (repeatable)")
    p = sub.add_parser("blacklist", help="manage blacklist entries")
    p.add_argument("action", choices=["add", "remove", "check"])
    p.add_argument("domains", nargs="+")
    p.add_argument("--category", default="malicious")
    p = sub.add_parser("simulate", help="run validation scenarios against the gateway")
    p.add_argument("--server")
    p.add_argument("--port", type=int)
    p.add_argument("--scenario", choices=["legit", "blacklist", "tunnel", "burst", "dga", "all"])
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-5s %(name)s: %(message)s")
    cfg = load_config(args.config)
    handlers = {
        "gateway": cmd_gateway, "dashboard": cmd_dashboard, "all": cmd_all,
        "init-db": cmd_init_db, "update-blacklist": cmd_update_blacklist,
        "blacklist": cmd_blacklist, "simulate": cmd_simulate,
    }
    handlers[args.command](cfg, args)


if __name__ == "__main__":
    main()
