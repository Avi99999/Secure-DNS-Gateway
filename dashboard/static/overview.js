// Overview page: KPIs, timeline, attack breakdown, top lists and live feed.
let range = "1h";
let lastId = 0;
let timeline, attacks;

Chart.defaults.color = "#8b98a5";
Chart.defaults.borderColor = "#2a3542";
Chart.defaults.font.family = getComputedStyle(document.documentElement).fontFamily;

function initCharts() {
  timeline = new Chart(document.getElementById("timeline"), {
    type: "bar",
    data: { labels: [], datasets: [
      { label: "Allowed", data: [], backgroundColor: COLORS.allowed, stack: "s" },
      { label: "Suspicious", data: [], backgroundColor: COLORS.suspicious, stack: "s" },
      { label: "Blocked", data: [], backgroundColor: COLORS.blocked, stack: "s" },
    ] },
    options: {
      maintainAspectRatio: false, animation: false,
      interaction: { mode: "index", intersect: false },
      scales: { x: { stacked: true, grid: { display: false }, ticks: { maxTicksLimit: 10 } },
                y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } },
      plugins: { legend: { position: "bottom", labels: { boxWidth: 12 } } },
    },
  });
  attacks = new Chart(document.getElementById("attacks"), {
    type: "doughnut",
    data: { labels: [], datasets: [{ data: [], backgroundColor: COLORS.attacks, borderWidth: 0 }] },
    options: { maintainAspectRatio: false, animation: false, cutout: "62%",
               plugins: { legend: { position: "bottom", labels: { boxWidth: 12 } } } },
  });
}

function miniRows(id, items, key, extra) {
  document.getElementById(id).innerHTML = items.length
    ? items.map(i => `<tr><td>${esc(i[key])}${extra ? " " + extra(i) : ""}</td><td class="num">${fmtNum(i.n)}</td></tr>`).join("")
    : `<tr><td class="muted">No data yet</td></tr>`;
}

async function loadSummary() {
  const s = await getJSON(`/api/summary?range=${range}`);
  document.getElementById("k-total").textContent = fmtNum(s.total);
  document.getElementById("k-allowed").textContent = fmtNum(s.allowed);
  document.getElementById("k-blocked").textContent = fmtNum(s.blocked);
  document.getElementById("k-suspicious").textContent = fmtNum(s.suspicious);
  document.getElementById("k-bl").textContent = fmtNum(s.blacklist_size);
  document.getElementById("k-rate").textContent = s.total ? `${s.block_rate}% of requests` : "";
  document.getElementById("k-latency").textContent = s.avg_latency_ms != null ? `avg ${s.avg_latency_ms} ms per resolution` : "";

  attacks.data.labels = s.attack_types.map(a => a.label);
  attacks.data.datasets[0].data = s.attack_types.map(a => a.n);
  attacks.update();
  document.getElementById("attacks-empty").hidden = s.attack_types.length > 0;

  miniRows("top-blocked", s.top_blocked, "domain", i => attackTag(i.attack_type));
  miniRows("top-domains", s.top_domains, "domain");
  miniRows("top-clients", s.top_clients, "client", i => i.blocked ? `<span class="badge blocked">${i.blocked} blocked</span>` : "");
}

async function loadTimeline() {
  const t = await getJSON(`/api/timeseries?range=${range}`);
  const withDate = t.bucket_seconds >= 1800;
  timeline.data.labels = t.labels.map(ts => {
    const d = new Date(ts * 1000);
    return withDate ? d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
                    : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: t.bucket_seconds < 60 ? "2-digit" : undefined });
  });
  timeline.data.datasets[0].data = t.allowed;
  timeline.data.datasets[1].data = t.suspicious;
  timeline.data.datasets[2].data = t.blocked;
  timeline.update();
}

function eventRow(e, isNew) {
  return `<tr class="${isNew ? "new" : ""}"><td class="num">${fmtTime(e.ts)}</td><td>${esc(e.client)}</td><td>${esc(e.qtype)}</td>
          <td class="domain">${esc(e.domain)}</td><td>${badge(e.verdict)}</td><td>${attackTag(e.attack_type)}</td>
          <td class="reason">${esc(e.reason || e.answer || "")}</td><td class="num">${e.latency_ms ?? ""}</td></tr>`;
}

async function loadFeed(initial) {
  const alertsOnly = document.getElementById("alerts-only").checked;
  const params = new URLSearchParams({ range: "all", limit: initial ? 40 : 100 });
  if (alertsOnly) params.set("verdict", "alerts");
  if (!initial && lastId) params.set("since_id", lastId);
  const data = await getJSON(`/api/events?${params}`);
  const tbody = document.getElementById("feed");
  if (initial) tbody.innerHTML = "";
  if (data.items.length) {
    if (!initial) data.items.filter(e => e.verdict !== "allowed").slice(0, 3).forEach(toast);
    lastId = Math.max(lastId, ...data.items.map(e => e.id));
    tbody.insertAdjacentHTML("afterbegin", data.items.map(e => eventRow(e, !initial)).join(""));
    while (tbody.rows.length > 60) tbody.deleteRow(-1);
  } else if (initial) {
    tbody.innerHTML = `<tr><td colspan="8" class="muted">No DNS requests logged yet. Point a device at the gateway or run <code>python main.py simulate</code>.</td></tr>`;
  }
}

async function tick() {
  try { await Promise.all([loadSummary(), loadTimeline(), loadFeed(false)]); } catch (e) { console.error(e); }
}

document.querySelectorAll("#range button").forEach(b => b.addEventListener("click", () => {
  document.querySelectorAll("#range button").forEach(x => x.classList.toggle("on", x === b));
  range = b.dataset.range;
  tick();
}));
document.getElementById("alerts-only").addEventListener("change", () => { lastId = 0; loadFeed(true); });

initCharts();
Promise.all([loadSummary(), loadTimeline(), loadFeed(true)]).catch(console.error);
setInterval(tick, 2000);
