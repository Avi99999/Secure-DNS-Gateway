#!/usr/bin/env bash
# One-shot installer for the Secure DNS Gateway on Ubuntu 22.04 / 24.04.
#
#   cd secure-dns-gateway
#   sudo bash deploy/setup_ubuntu.sh
#
# What it does:
#   1. installs Unbound, Python venv tooling and dig
#   2. installs the Unbound config (loopback :5335, DoT upstreams, DNSSEC)
#   3. frees port 53 by turning off systemd-resolved's stub listener
#   4. creates .venv and installs Python requirements
#   5. initialises the SQLite database and seed blacklist
#   6. installs and starts the dns-gateway and dns-dashboard systemd services
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo: sudo bash deploy/setup_ubuntu.sh" >&2
  exit 1
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_USER="${SUDO_USER:-root}"
echo "==> Project directory: $DIR (services will run as $RUN_USER)"

echo "==> [1/6] Installing packages"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unbound python3 python3-venv python3-pip dnsutils ca-certificates

echo "==> [2/6] Configuring Unbound on 127.0.0.1:5335"
install -m 644 "$DIR/deploy/unbound/secure-gateway.conf" /etc/unbound/unbound.conf.d/secure-gateway.conf
# The Ubuntu package can ship a resolvconf hook that conflicts with a custom listener.
rm -f /etc/unbound/unbound.conf.d/resolvconf_resolvers.conf
unbound-checkconf
systemctl enable unbound
systemctl restart unbound
sleep 1
if dig +short @127.0.0.1 -p 5335 example.com >/dev/null; then
  echo "    Unbound is resolving."
else
  echo "    WARNING: Unbound did not answer; check 'journalctl -u unbound'."
fi

echo "==> [3/6] Freeing port 53 (systemd-resolved stub listener)"
if systemctl is-active --quiet systemd-resolved; then
  mkdir -p /etc/systemd/resolved.conf.d
  cat > /etc/systemd/resolved.conf.d/secure-gateway.conf <<'EOF'
[Resolve]
DNSStubListener=no
DNS=1.1.1.1 9.9.9.9
EOF
  ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
  systemctl restart systemd-resolved
fi

echo "==> [4/6] Creating Python virtual environment"
sudo -u "$RUN_USER" python3 -m venv "$DIR/.venv"
sudo -u "$RUN_USER" "$DIR/.venv/bin/pip" install -q --upgrade pip
sudo -u "$RUN_USER" "$DIR/.venv/bin/pip" install -q -r "$DIR/requirements.txt"

echo "==> [5/6] Initialising database and blacklist"
sudo -u "$RUN_USER" bash -c "cd '$DIR' && .venv/bin/python main.py --config config.json init-db"
sudo -u "$RUN_USER" bash -c "cd '$DIR' && .venv/bin/python main.py --config config.json update-blacklist" \
  || echo "    (feed download failed - the seed blacklist is still active; retry later)"

echo "==> [6/6] Installing systemd services"
for svc in dns-gateway dns-dashboard; do
  sed -e "s#__DIR__#$DIR#g" -e "s#__USER__#$RUN_USER#g" "$DIR/deploy/systemd/$svc.service" > "/etc/systemd/system/$svc.service"
done
systemctl daemon-reload
systemctl enable --now dns-gateway dns-dashboard

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow 53/udp; ufw allow 53/tcp; ufw allow 5000/tcp
fi

IP="$(hostname -I | awk '{print $1}')"
echo
echo "Secure DNS Gateway is running."
echo "  DNS server for test devices : $IP  (port 53)"
echo "  Dashboard                   : http://$IP:5000   (login from config.json -> dashboard)"
echo "  Quick check                 : dig @$IP example.com    /    dig @$IP malware-test.example"
echo "  Logs                        : journalctl -u dns-gateway -f"
