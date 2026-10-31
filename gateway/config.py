"""Configuration loading for the Secure DNS Gateway.

Configuration is a JSON file. Every key has a default, so a config file only
needs to contain the values it wants to override. Relative paths inside the
config are resolved against the project root (the folder holding main.py).
"""

import copy
import json
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULTS = {
    # --- DNS listener (what client devices point at) ---
    # One address, a list of addresses, or "auto" (loopback + every LAN IPv4).
    "listen_address": "0.0.0.0",
    "listen_port": 53,
    "enable_tcp": True,

    # --- Upstream resolver (Unbound). Tried in order until one answers. ---
    "upstreams": [{"host": "127.0.0.1", "port": 5335}],
    "upstream_timeout": 3.0,

    # How blocked queries are answered: "refused", "nxdomain" or "sinkhole"
    # (sinkhole answers A/AAAA with 0.0.0.0 / ::).
    "block_response": "refused",

    # --- Storage ---
    "database": "data/gateway.db",
    "blacklist_seed": "data/blacklist_seed.txt",
    "allowlist_file": "data/allowlist.txt",
    "blacklist_refresh_seconds": 10,
    "blacklist_feeds": [
        {"name": "urlhaus", "category": "malware",
         "url": "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt"},
        {"name": "phishing-army", "category": "phishing",
         "url": "https://phishing.army/download/phishing_army_blocklist.txt"},
        {"name": "hagezi-tif", "category": "threat-intel",
         "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt"},
        {"name": "stevenblack", "category": "ads-malware",
         "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"},
    ],

    # --- Heuristic / statistical detection thresholds ---
    "detection": {
        # payload analysis (DNS tunneling)
        "max_label_length": 50,
        "max_qname_length": 120,
        "entropy_min_length": 20,
        "entropy_threshold": 3.8,
        # traffic analysis (DNS tunneling)
        "tunnel_window_seconds": 60,
        "unique_subdomain_limit": 30,
        "txt_null_limit": 20,
        # excessive request volume
        "rate_window_seconds": 10,
        "client_rate_limit": 150,
        "client_domain_rate_limit": 30,
        # suspicious naming / DGA
        "dga_min_length": 12,
        "dga_entropy_threshold": 3.5,
        "bigram_ratio_threshold": 0.35,
        "digit_ratio_threshold": 0.35,
        "consonant_run_threshold": 6,
        "newly_seen_window_seconds": 60,
        "newly_seen_query_limit": 50,
        # verdict thresholds on the composite score (0..1)
        "block_score": 0.65,
        "suspicious_score": 0.35,
    },

    # --- Flask dashboard ---
    "dashboard": {
        "host": "127.0.0.1",
        "port": 5000,
        # Set both to require HTTP basic auth on the dashboard.
        "username": "",
        "password": "",
    },
}


def _merge(base, override):
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def resolve_path(path):
    if os.path.isabs(path):
        return path
    return os.path.join(PROJECT_ROOT, path)


def load_config(path=None):
    """Load config from `path` (or $GATEWAY_CONFIG, or config.json)."""
    path = path or os.environ.get("GATEWAY_CONFIG") or os.path.join(PROJECT_ROOT, "config.json")
    path = resolve_path(path)
    user = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            user = json.load(fh)
    cfg = _merge(DEFAULTS, user)
    cfg["_path"] = path
    for key in ("database", "blacklist_seed", "allowlist_file"):
        cfg[key] = resolve_path(cfg[key])
    return cfg
