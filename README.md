# Secure DNS Gateway with a Python-Based Real-Time Threat Detection Layer

Implementation of the project described in the preliminary report
(K041 / K046 / K047 / K072). A self-hosted DNS gateway that puts a Python
inspection layer in front of the **Unbound** resolver, blocks blacklisted and
suspicious queries *before* they resolve, logs every request to **SQLite**, and
shows live telemetry in a **Flask** dashboard.

```
Test device ──► Python Security Layer :53 ──► Unbound 127.0.0.1:5335 ──► Trusted DNS (DoT) ──► Internet
                     │
                     ├─ Domain Inspector     (parse: domain, record type, client, features)
                     ├─ Blacklist Checker    (SQLite, suffix/parent matching)
                     ├─ Attack Detector      (tunneling, rate, entropy, DGA naming)
                     ▼
                Verdict Engine ──► Action Handler (allow → forward / block → REFUSED)
                     └────────────► SQLite event log ──► Flask dashboard
```

## Project layout

| Path | Report section | What it does |
|---|---|---|
| `gateway/inspector.py` | 4.3 Parsing | Decodes the query; computes length, entropy, digit ratio, nesting, charset, etc. |
| `gateway/blacklist.py` | 4.4 | Blacklist in SQLite (indexed), hosts/plain feed parser, suffix matching, allowlist, hot reload |
| `gateway/detector.py` | 4.5 | Tunneling (payload + traffic), sliding-window rate limits, DGA/suspicious naming, newly-seen bursts |
| `gateway/verdict.py` | 5.2 | Blacklist → block; composite (noisy-OR) heuristic score ≥ threshold → block; otherwise allow / suspicious |
| `gateway/action.py` | 4.3 Action | Forwards allowed queries to Unbound (with fallback + TCP retry); answers blocked ones locally |
| `gateway/eventlog.py`, `gateway/db.py` | 4.6, 5.1 | SQLite schema and batched background writer (keeps disk I/O off the hot path) |
| `gateway/server.py` | Fig. 2 | UDP + TCP DNS server that wires the pipeline together |
| `dashboard/` | 4.7 | Flask dashboard: KPIs, timeline, attack breakdown, top lists, live feed with alerts, event log + CSV, blacklist management |
| `deploy/unbound/secure-gateway.conf` | 4.2 | Unbound: loopback-only, ACLs, DNSSEC, caching, DNS-over-TLS upstreams |
| `deploy/setup_ubuntu.sh`, `deploy/systemd/` | 4.1 | One-shot installer for the Ubuntu VM + systemd services |
| `docker-compose.yml`, `deploy/unbound/Dockerfile`, `deploy/unbound/docker.conf` | 4.1–4.2 | Unbound in Docker for a Windows host (no VM) |
| `scripts/simulate_traffic.py` | 4.8 | The three test scenario categories (legit, blacklisted, simulated attacks) |
| `tests/` | – | Unit tests + an end-to-end test with a fake upstream |

## Event log schema (Section 5.1)

`events(id, ts, client, domain, qtype, verdict, reason, attack_type, score, rcode, answer, latency_ms)`

`verdict` is `allowed`, `blocked`, or `suspicious` (allowed but alerted).
`attack_type` is `malicious_domain`, `dns_tunneling`, `excessive_requests` or `suspicious_domain`.

---

## How to run it

### Option A: quick local demo (Windows / macOS / Linux, no Unbound needed)

This runs the whole pipeline on your laptop. It listens on `127.0.0.1:5300` and
forwards to Unbound if one is running on `127.0.0.1:5335`, otherwise to
1.1.1.1 / 9.9.9.9.

```bash
cd secure-dns-gateway
pip install -r requirements.txt
python main.py --config config.dev.json all
```

Open **http://127.0.0.1:5000** for the dashboard. In a second terminal, run the
validation scenarios:

```bash
python main.py --config config.dev.json simulate
```

You can also query it by hand: `nslookup -port=5300 google.com 127.0.0.1`, or
`dig @127.0.0.1 -p 5300 malware-test.example`.

Optional: pull the public blacklists (about 350k domains):

```bash
python main.py --config config.dev.json update-blacklist
```

### Option B: full deployment on Windows (Unbound in Docker, no VM)

The same pipeline as the report, but the Ubuntu VM is replaced by Docker:
Unbound runs in a container published only on `127.0.0.1:5335`. The Python
security layer runs natively on Windows on port 53 and forwards only to that
Unbound, using the same DNSSEC and DNS-over-TLS policy as the Ubuntu config
(`deploy/unbound/docker.conf`).

```
Phone / test device ──► Python gateway (Windows) :53 ──► Unbound (Docker) 127.0.0.1:5335 ──► Cloudflare / Quad9 (DoT)
```

1. Start **Docker Desktop**, then build and start Unbound:

   ```bash
   docker compose up -d --build
   ```

2. Load the public blacklists (once, then whenever you want to refresh them):

   ```bash
   python main.py --config config.windows.json update-blacklist
   ```

3. Run the gateway and dashboard. If Windows Firewall asks, allow Python:

   ```bash
   python main.py --config config.windows.json all
   ```

   You should see `listening on 127.0.0.1, 192.168.x.x ... port 53 (udp+tcp) -> upstream 127.0.0.1:5335`.
   `"listen_address": "auto"` binds loopback and each LAN address separately, so the
   gateway takes priority over Windows' Internet Connection Sharing DNS proxy, which
   listens on all addresses (0.0.0.0:53). Ports are claimed exclusively, so a second
   copy of the gateway or dashboard fails with a clear error instead of silently
   sharing the port. The dashboard is at **http://127.0.0.1:5000**.

   To measure the latency the inspection layer adds on top of Unbound:

   ```bash
   python scripts/benchmark_latency.py
   ```

4. Test from the laptop itself:

   ```bash
   python main.py --config config.windows.json simulate
   ```

5. Use a phone as the test device. Find the laptop's Wi-Fi IP with `ipconfig`
   (look for *IPv4 Address*). Then on the phone, on the same Wi-Fi:
   - Settings → Network → **Private DNS: Off** (otherwise it skips the gateway).
   - Wi-Fi → your network → IP settings **Static** → **DNS 1** = laptop IP.

   Browse on the phone and watch the dashboard.

To make the laptop itself use the gateway, set its Wi-Fi DNS to `127.0.0.1`
(Settings → Network & internet → Wi-Fi → your network → DNS server assignment →
Manual). Also turn off "Use secure DNS" in Chrome or Edge, and disconnect any
VPN. **Set it back to Automatic** when the gateway isn't running, or you'll
lose internet.

Stop everything with **Ctrl+C** in the gateway terminal, then:

```bash
docker compose down
```

**Troubleshooting**

- *"cannot listen on ...:53"*: another program has that address. Make sure no other
  gateway is still running, and keep `"listen_address": "auto"`. If it still fails,
  turn off Mobile Hotspot / Internet Connection Sharing.
- *Every query gets SERVFAIL*: Unbound isn't running. Run `docker ps`; the
  `secure-dns-unbound` container should be *healthy*. Run
  `docker logs secure-dns-unbound` to see why. If your network blocks DNS-over-TLS
  (port 853), edit `deploy/unbound/docker.conf` as described under Option C, then
  run `docker compose up -d --build`.
- *Phone can't reach the gateway*: allow `python.exe` through Windows Firewall
  for your network type (Public or Private).

### Option C: full deployment on an Ubuntu VM (the setup in the report)

1. Create an Ubuntu 22.04/24.04 VM in VirtualBox or VMware. Set its network
   adapter to **Bridged** (to your Wi-Fi or hotspot) so other devices can reach it.
2. Copy this folder into the VM, then run:

   ```bash
   cd secure-dns-gateway
   sudo bash deploy/setup_ubuntu.sh
   ```

   The script installs Unbound and configures it on `127.0.0.1:5335`. It frees
   port 53 from systemd-resolved, creates a venv, initialises the DB, downloads
   the feeds, and starts the `dns-gateway` and `dns-dashboard` services. It prints
   the VM's IP address when it finishes.
3. **Change the dashboard password** in `config.json` (`dashboard.password`),
   then run `sudo systemctl restart dns-dashboard`.
4. Check it from the VM: `dig @127.0.0.1 example.com` should return an answer.
   `dig @127.0.0.1 malware-test.example` should return `status: REFUSED`.

**Test device (Section 4.8).** On a second laptop or phone on the same network,
set the DNS server to the VM's IP:

- Windows: Settings → Network → your adapter → DNS server assignment → Manual → IPv4 DNS = VM IP
- Android: Wi-Fi → network → Advanced → IP settings Static → DNS 1 = VM IP
- Then browse normally and watch `http://<VM-IP>:5000`.

Run the attack scenarios from the test device:

```bash
pip install dnslib
python scripts/simulate_traffic.py --server <VM-IP> --port 53 --compare 1.1.1.1
```

`--compare` also reports the latency the inspection layer adds over a direct lookup.

Useful service commands on the VM:

```bash
sudo systemctl status dns-gateway dns-dashboard unbound
journalctl -u dns-gateway -f        # live BLOCK / ALERT lines
```

If your network blocks DNS-over-TLS (port 853), edit
`/etc/unbound/unbound.conf.d/secure-gateway.conf`. Set `forward-tls-upstream: no`,
change the addresses to `1.1.1.1` and `9.9.9.9` (drop the `@853#...` part), then
run `sudo systemctl restart unbound`.

### Manual Linux run (without the installer)

```bash
pip install -r requirements.txt
sudo python3 main.py gateway        # port 53 needs root or CAP_NET_BIND_SERVICE
python3 main.py dashboard
```

---

## CLI reference

```
python main.py [--config FILE] gateway | dashboard | all
python main.py init-db
python main.py update-blacklist [--feed NAME] [--file my_list.txt]
python main.py blacklist add|remove|check DOMAIN... [--category phishing]
python main.py simulate [--scenario legit|blacklist|dga|tunnel|burst|all]
```

Blacklist changes, whether from the CLI or the dashboard, reach a running
gateway within `blacklist_refresh_seconds` (default 10 s). No restart is needed.

## Configuration

`config.json` is for the VM and `config.dev.json` is for local runs. Any key
you leave out falls back to the default in `gateway/config.py`. The main knobs
are under `detection`:

| Key | Default | Meaning |
|---|---|---|
| `max_label_length` / `max_qname_length` | 50 / 120 | Tunneling payload length limits |
| `entropy_threshold` (with `entropy_min_length`) | 3.8 bits (20 chars) | Encoded-looking subdomain |
| `unique_subdomain_limit` / `txt_null_limit` | 30 / 20 per 60 s | Tunneling traffic per parent domain |
| `client_rate_limit` / `client_domain_rate_limit` | 150 / 30 per 10 s | Excessive request volume |
| `dga_*`, `bigram_ratio_threshold`, `digit_ratio_threshold` | – | Suspicious / DGA naming |
| `block_score` / `suspicious_score` | 0.65 / 0.35 | Composite-score thresholds |

`block_response` can be `refused` (default), `nxdomain`, or `sinkhole` (answer
0.0.0.0). `data/allowlist.txt` lists CDNs that skip the naming heuristics, to
avoid false positives on long random-looking CDN hostnames.

## Tests

```bash
python -m pytest -q
```

The suite covers the inspector, suffix matching, a 49-domain false-positive check
on legitimate domains, DGA, tunneling (payload and short-label traffic), rate
limiting with window expiry, and an end-to-end run. The end-to-end test sends real
UDP queries through the gateway to a fake upstream, then checks the SQLite rows,
the dashboard API, and a live blacklist edit from the dashboard.

## Measured results (local demo run)

| Scenario | Result |
|---|---|
| Legitimate domains | 15/15 resolved, median about 10 ms through the gateway |
| Blacklisted domains (incl. subdomains) | 8/8 blocked (100%), never forwarded upstream |
| DNS tunneling (base32 over TXT) | 9/9 blocked (100%) |
| Query burst | Blocked from query #31 (limit 30 per 10 s) |
| DGA-style names | 8/10 blocked; the rest were logged as suspicious |

On 500 random 13–20 character names, the naming heuristics blocked about 72% and
flagged about 97% as blocked or suspicious. Machine-learning classification is
left as future work, as stated in the report's scope.
