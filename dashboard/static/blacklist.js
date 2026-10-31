// Blacklist page: search, add and remove entries.
const PAGE = 50;
let offset = 0;

async function load() {
  const q = document.getElementById("bl-q").value.trim();
  const data = await getJSON(`/api/blacklist?${new URLSearchParams({ q, limit: PAGE, offset })}`);
  document.getElementById("bl-rows").innerHTML = data.items.length ? data.items.map(b => `
    <tr><td class="domain">${esc(b.domain)}</td><td>${esc(b.source)}</td><td><span class="tag">${esc(b.category)}</span></td>
    <td class="muted">${fmtTime(b.added_at, true)}</td>
    <td class="num"><button class="btn danger" data-del="${esc(b.domain)}">Remove</button></td></tr>`).join("")
    : `<tr><td colspan="5" class="muted">No entries${q ? " match" : ""}.</td></tr>`;
  document.getElementById("bl-sources").innerHTML = data.sources.map(s =>
    `<tr><td>${esc(s.source)}</td><td class="num">${fmtNum(s.n)}</td></tr>`).join("");
  const end = Math.min(offset + PAGE, data.total);
  document.getElementById("bl-total").textContent = `${fmtNum(data.total)} ${q ? "matching" : "blacklisted"} domains`;
  document.getElementById("bl-page").textContent = data.total ? `${offset + 1}–${end}` : "";
  document.getElementById("bl-prev").disabled = offset === 0;
  document.getElementById("bl-next").disabled = end >= data.total;
}

document.getElementById("bl-rows").addEventListener("click", async e => {
  const d = e.target.dataset.del;
  if (!d || !confirm(`Remove ${d} from the blacklist?`)) return;
  await getJSON(`/api/blacklist/${encodeURIComponent(d)}`, { method: "DELETE" });
  load();
});

document.getElementById("bl-add").addEventListener("submit", async e => {
  e.preventDefault();
  const f = e.target;
  const res = await getJSON("/api/blacklist", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domains: f.domains.value, category: f.category.value }),
  });
  document.getElementById("bl-msg").textContent =
    `Added ${res.added} new domain(s).` + (res.invalid.length ? ` Ignored invalid: ${res.invalid.join(", ")}` : "");
  f.domains.value = "";
  offset = 0;
  load();
});

let debounce;
document.getElementById("bl-q").addEventListener("input", () => { clearTimeout(debounce); debounce = setTimeout(() => { offset = 0; load(); }, 250); });
document.getElementById("bl-prev").onclick = () => { offset = Math.max(0, offset - PAGE); load(); };
document.getElementById("bl-next").onclick = () => { offset += PAGE; load(); };
load();
