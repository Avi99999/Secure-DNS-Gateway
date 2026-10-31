// Shared helpers for all dashboard pages.
const ATTACK_LABELS = {
  malicious_domain: "Blacklisted domain",
  dns_tunneling: "DNS tunneling",
  excessive_requests: "Excessive requests",
  suspicious_domain: "Suspicious naming / DGA",
};
const COLORS = { allowed: "#3fb27f", blocked: "#e5534b", suspicious: "#d4a72c",
                 attacks: ["#e5534b", "#a371f7", "#d4a72c", "#4f9cf9", "#3fb27f"] };

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function fmtTime(ts, withDate) {
  const d = new Date(ts * 1000);
  return withDate ? d.toLocaleString() : d.toLocaleTimeString();
}
function fmtNum(n) { return (n ?? 0).toLocaleString(); }
function badge(v) { return `<span class="badge ${esc(v)}">${esc(v)}</span>`; }
function attackTag(a) { return a ? `<span class="tag">${esc(ATTACK_LABELS[a] || a)}</span>` : ""; }

async function getJSON(url, opts) {
  const r = await fetch(url, opts);
  if (!r.ok) throw new Error(`${r.status} ${url}`);
  return r.json();
}

function toast(ev) {
  const box = document.getElementById("toasts");
  const el = document.createElement("div");
  el.className = `toast ${ev.verdict}`;
  el.innerHTML = `<b>${ev.verdict === "blocked" ? "Blocked" : "Suspicious"}: ${esc(ATTACK_LABELS[ev.attack_type] || ev.attack_type || "")}</b>
                  <div class="d">${esc(ev.domain)}</div><div class="muted">from ${esc(ev.client)}</div>`;
  box.appendChild(el);
  while (box.children.length > 4) box.firstChild.remove();
  setTimeout(() => el.remove(), 6000);
}

async function refreshStatus() {
  const el = document.getElementById("gw-status");
  try {
    const h = await getJSON("/api/health");
    el.className = "status " + (h.gateway.online ? "online" : "offline");
    el.querySelector(".txt").textContent = h.gateway.online ? "Gateway online" : "Gateway offline";
  } catch (e) {
    el.className = "status offline";
    el.querySelector(".txt").textContent = "Dashboard error";
  }
}
refreshStatus();
setInterval(refreshStatus, 5000);
