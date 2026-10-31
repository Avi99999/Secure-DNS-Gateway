# Live demo guide

How to show the Secure DNS Gateway working, without needing Claude open. It
takes about 10–15 minutes and follows the order of the project report.

## Open the project in VS Code

1. Open **Docker Desktop** and wait until it says **Engine running**.
2. In VS Code: **File → Open Folder** → `Desktop\secure-dns-gateway`.
3. Open a terminal with **Ctrl + `** (the key above Tab). It opens in the project folder already.
4. Make sure the laptop has internet. Unbound needs it to reach Cloudflare and Quad9.

## Option 1 (easiest): the guided script

Paste this into the VS Code terminal:

```powershell
powershell -ExecutionPolicy Bypass -File demo.ps1
```

It walks through every step below. Each step shows the command and waits for
**Enter**, so you can explain it first. Step 4 opens the gateway in a separate
window and opens the dashboard in your browser.

## Option 2: run the commands yourself

Copy each command into the VS Code terminal. Steps 4 onwards need **two
terminals**: click **+** in the terminal panel to add a second one.

**1. Tests.** 66 automated tests (report Section 5.2):

```powershell
python -m pytest -q
```

**2. Start Unbound** in Docker, listening only on 127.0.0.1:5335:

```powershell
docker compose up -d --build
docker ps
```

**3. DNSSEC.** A signed domain shows the `ad` flag; a broken one shows `SERVFAIL`:

```powershell
docker exec secure-dns-unbound drill -D -p 5335 '@127.0.0.1' nlnetlabs.nl
docker exec secure-dns-unbound drill -p 5335 '@127.0.0.1' dnssec-failed.org
```

**4. Gateway and dashboard.** Run this in **terminal 1** and leave it running:

```powershell
python main.py --config config.windows.json all
```

Then open **http://127.0.0.1:5000** in a browser. It should say *Gateway online*.

**5. Manual queries.** Run these in **terminal 2** and watch the dashboard:

```powershell
nslookup google.com 127.0.0.1
nslookup malware-test.example 127.0.0.1
nslookup beacon.c2-callback.example 127.0.0.1
```

The first resolves. The other two are refused: one is blacklisted, and the other
is a subdomain of a blacklisted domain.

**6. Attack scenarios** (report Section 5.3):

```powershell
python main.py --config config.windows.json simulate
```

Then show the dashboard **Overview**. Next, open **Event log**, filter to
**Blocked + suspicious**, and click **Export CSV**.

**7. Live blacklist update.** On the dashboard **Blacklist** page, add
`example.org`, then run:

```powershell
nslookup example.org 127.0.0.1
```

It is refused without a restart. Remove `example.org` again afterwards.

**8. Performance** (report Section 6.1):

```powershell
python scripts/benchmark_latency.py
```

The last line shows the overhead the security layer adds, about 2 ms.

**9. Optional: phone as the test device.** Connect the phone to the same Wi-Fi.
Turn **Private DNS** off, and set Wi-Fi IP settings to **Static** with
**DNS 1** = the laptop's IPv4 address (run `ipconfig` to find it). Browse on the
phone and its queries appear on the dashboard.

**To finish:** press **Ctrl+C** in terminal 1, then run:

```powershell
docker compose down
```

## Optional: start with an empty dashboard

This clears the old events but keeps the blacklist:

```powershell
python -c "import sqlite3; c=sqlite3.connect('data/gateway.db'); c.execute('DELETE FROM events'); c.commit()"
```

## If something goes wrong

| Problem | Fix |
|---|---|
| `cannot listen on ...:53` | An old gateway is still running. Close that terminal or window, or restart the laptop. |
| `dashboard port ... already in use` | Same cause: an old dashboard is still running. |
| Every query gives SERVFAIL | Unbound isn't running (`docker ps`), or there is no internet. |
| `docker` errors | Docker Desktop isn't open yet. Wait for *Engine running*. |
| `demo.ps1 cannot be loaded` | Run it exactly as shown, with `-ExecutionPolicy Bypass`. |
| Phone queries don't show up | Use your mobile hotspot instead of college Wi-Fi, and check Private DNS is off. |

Rehearse once the day before. The first `docker compose up --build` on a new
network can take a minute.
