// Event log page: filterable, paginated view of every logged DNS request.
const PAGE = 50;
let offset = 0;
const form = document.getElementById("filters");

function params() {
  const p = new URLSearchParams(new FormData(form));
  for (const [k, v] of [...p]) if (!v) p.delete(k);
  return p;
}

async function load() {
  const p = params();
  document.getElementById("csv").href = `/events.csv?${p}`;
  p.set("limit", PAGE);
  p.set("offset", offset);
  const data = await getJSON(`/api/events?${p}`);
  document.getElementById("rows").innerHTML = data.items.length ? data.items.map(e => `
    <tr><td class="num muted">${e.id}</td><td class="num">${fmtTime(e.ts, true)}</td><td>${esc(e.client)}</td><td>${esc(e.qtype)}</td>
    <td class="domain">${esc(e.domain)}</td><td>${badge(e.verdict)}</td><td>${attackTag(e.attack_type)}</td>
    <td class="num">${e.score ? e.score.toFixed(2) : ""}</td>
    <td class="reason">${esc(e.reason || (e.answer ? "→ " + e.answer : e.rcode))}</td><td class="num">${e.latency_ms ?? ""}</td></tr>`).join("")
    : `<tr><td colspan="10" class="muted">No events match these filters.</td></tr>`;
  const end = Math.min(offset + PAGE, data.total);
  document.getElementById("pageinfo").textContent = data.total ? `${offset + 1}–${end} of ${fmtNum(data.total)}` : "";
  document.getElementById("prev").disabled = offset === 0;
  document.getElementById("next").disabled = end >= data.total;
}

let debounce;
form.addEventListener("input", () => { clearTimeout(debounce); debounce = setTimeout(() => { offset = 0; load(); }, 250); });
form.addEventListener("submit", e => e.preventDefault());
document.getElementById("prev").onclick = () => { offset = Math.max(0, offset - PAGE); load(); };
document.getElementById("next").onclick = () => { offset += PAGE; load(); };

const q = new URLSearchParams(location.search);
for (const [k, v] of q) if (form.elements[k]) form.elements[k].value = v;
load();
setInterval(() => { if (offset === 0) load(); }, 5000);
