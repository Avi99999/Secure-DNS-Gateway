# Guided live demo of the Secure DNS Gateway (Windows + Docker).
#
# Run from a VS Code terminal in the project folder:
#   powershell -ExecutionPolicy Bypass -File demo.ps1
#
# Each step prints what it is about to do and waits for Enter, so you can
# explain it first. Docker Desktop must already be running.

Set-Location $PSScriptRoot
$Config = "config.windows.json"

function Pause-Step($text) {
    Write-Host ""
    Read-Host $text | Out-Null
}

function Step($number, $title, $explain, [string[]]$commands) {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor DarkCyan
    Write-Host " STEP $number - $title" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor DarkCyan
    Write-Host " $explain" -ForegroundColor Gray
    foreach ($c in $commands) { Write-Host "   > $c" -ForegroundColor Yellow }
    Pause-Step " Press Enter to run"
    foreach ($c in $commands) {
        Write-Host ""
        Write-Host "> $c" -ForegroundColor Yellow
        Invoke-Expression $c
    }
}

# --- Pre-flight -------------------------------------------------------------
Write-Host "Secure DNS Gateway - live demo" -ForegroundColor Green
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker is not running. Open Docker Desktop, wait for 'Engine running', then run this script again." -ForegroundColor Red
    exit 1
}
$clear = Read-Host "Clear old events so the dashboard starts at zero? (y/n)"
if ($clear -eq "y") {
    python -c "import sqlite3; c=sqlite3.connect('data/gateway.db'); c.execute('DELETE FROM events'); c.commit(); print('event log cleared (blacklist kept)')"
}

# --- Steps ------------------------------------------------------------------
Step 1 "Automated tests" "66 unit and end-to-end tests verify every module (report Section 5.2)." @(
    "python -m pytest -q"
)

Step 2 "Start the Unbound resolver" "Unbound runs in Docker and listens only on 127.0.0.1:5335, so clients cannot bypass the security layer." @(
    "docker compose up -d --build",
    "docker ps --filter name=secure-dns-unbound"
)

Step 3 "DNSSEC validation" "A signed domain gets the 'ad' (authenticated) flag; a deliberately broken one is rejected with SERVFAIL." @(
    "docker exec secure-dns-unbound drill -D -p 5335 '@127.0.0.1' nlnetlabs.nl",
    "docker exec secure-dns-unbound drill -p 5335 '@127.0.0.1' dnssec-failed.org"
)

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor DarkCyan
Write-Host " STEP 4 - Start the gateway and dashboard" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor DarkCyan
Write-Host " Opens a NEW window running the Python security layer on port 53 and the dashboard." -ForegroundColor Gray
Write-Host " Blocks and alerts scroll there live. Keep it open." -ForegroundColor Gray
Write-Host "   > python main.py --config $Config all" -ForegroundColor Yellow
Pause-Step " Press Enter to start"
Start-Process powershell -WorkingDirectory $PSScriptRoot -ArgumentList "-NoExit", "-Command", "python main.py --config $Config all"
Start-Sleep -Seconds 6
Start-Process "http://127.0.0.1:5000"
Write-Host " Dashboard opened at http://127.0.0.1:5000 - check it says 'Gateway online'." -ForegroundColor Green

Step 5 "Manual queries" "A normal site resolves; a blacklisted domain and its subdomain are refused. Watch them appear on the dashboard." @(
    "nslookup google.com 127.0.0.1",
    "nslookup malware-test.example 127.0.0.1",
    "nslookup beacon.c2-callback.example 127.0.0.1"
)

Step 6 "Attack scenarios" "Legitimate, blacklisted, DGA, tunneling and burst traffic (report Section 5.3). Then show the dashboard: Overview, and Event log filtered to 'Blocked + suspicious'." @(
    "python main.py --config $Config simulate"
)

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor DarkCyan
Write-Host " STEP 7 - Live blacklist update" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor DarkCyan
Write-Host " In the dashboard, open the Blacklist page and add:  example.org" -ForegroundColor Gray
Pause-Step " Press Enter once you have added it"
Start-Sleep -Seconds 3
Write-Host "> nslookup example.org 127.0.0.1" -ForegroundColor Yellow
nslookup example.org 127.0.0.1
Write-Host " It is refused without restarting anything. Remove example.org again on the Blacklist page." -ForegroundColor Green

Step 8 "Performance" "Compares lookups through the gateway with Unbound directly; the last line is the inspection overhead (about 2 ms)." @(
    "python scripts/benchmark_latency.py"
)

# --- Shut down --------------------------------------------------------------
Write-Host ""
Write-Host ("=" * 70) -ForegroundColor DarkCyan
Write-Host " Demo complete" -ForegroundColor Green
Write-Host ("=" * 70) -ForegroundColor DarkCyan
$stop = Read-Host "Stop Unbound now? (press Ctrl+C in the gateway window yourself) (y/n)"
if ($stop -eq "y") { docker compose down }
