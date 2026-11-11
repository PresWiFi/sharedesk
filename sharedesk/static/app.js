"use strict";

const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const state = { me: null, tab: "overview" };

async function api(path, body) {
  const opts = body === undefined ? {} : {
    method: "POST", body: JSON.stringify(body),
    headers: { "Content-Type": "application/json", "X-ShareDesk": "1" },
  };
  const res = await fetch(path, opts);
  let data = {};
  try { data = await res.json(); } catch { /* empty body */ }
  if (res.status === 401 && path !== "/api/login") { showLogin(); throw new Error("Log in first."); }
  if (!res.ok) { const e = new Error(data.error || data.detail || res.statusText); e.data = data; throw e; }
  return data;
}

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.add("hidden"), 3500);
}

// ---- modal -------------------------------------------------------------------

function openModal(html) {
  $("#modal-body").innerHTML = html;
  const d = $("#modal");
  if (!d.open) d.showModal();
  return $("#modal-body");
}
function closeModal() { $("#modal").close(); }
$("#modal").addEventListener("click", (e) => { if (e.target.id === "modal") closeModal(); });

function diffHtml(diff) {
  return diff.split("\n").map((l) => {
    const cls = l.startsWith("+") && !l.startsWith("+++") ? "diff-add" : l.startsWith("-") && !l.startsWith("---") ? "diff-del" : "";
    return `<span class="${cls}">${esc(l)}</span>`;
  }).join("\n");
}

function stepsHtml(steps) {
  return steps.map((s) => `<div class="step">
      <div>${esc(s.desc)}</div><pre>$ sudo ${esc(s.cmd)}</pre>
      ${s.input === "(hidden)" ? '<div class="hint">Password sent on stdin (not shown, not logged).</div>' : ""}
    </div>`).join("");
}

function resultHtml(r) {
  const rows = r.steps.map((s) => `<div class="step ${s.code === 0 ? "ok" : "fail"}">
      <pre>$ sudo ${esc(s.cmd)}   → exit ${s.code}</pre>${s.output ? `<pre>${esc(s.output)}</pre>` : ""}</div>`).join("");
  const rb = r.rolled_back?.length ? `<h3>Rolled back</h3>` + r.rolled_back.map((s) =>
    `<div class="step ${s.code === 0 ? "ok" : "fail"}"><pre>$ sudo ${esc(s.cmd)}   → exit ${s.code}</pre>${s.output ? `<pre>${esc(s.output)}</pre>` : ""}</div>`).join("") : "";
  return rows + rb;
}

// Every change is previewed first: the user sees the exact commands (and file diff), then applies.
async function change(path, body) {
  let preview;
  try {
    preview = (await api(path, { ...body, preview: true })).preview;
  } catch (e) { toast(e.message); return false; }
  return new Promise((resolve) => {
    const m = openModal(`<h2>${esc(preview.title)}</h2>
      <p class="muted">These commands will run on ${esc(state.me.host)}:</p>
      ${stepsHtml(preview.steps)}
      ${preview.diff ? `<h3>File change</h3><pre>${diffHtml(preview.diff)}</pre>` : ""}
      ${preview.rollback.length ? `<p class="hint">If a step fails, ShareDesk restores the previous file and re-exports.</p>` : ""}
      <div class="modal-actions"><button id="m-cancel">Cancel</button><button class="primary" id="m-apply">Apply</button></div>`);
    $("#m-cancel", m).onclick = () => { closeModal(); resolve(false); };
    $("#m-apply", m).onclick = async () => {
      $("#m-apply", m).disabled = true;
      $("#m-apply", m).textContent = "Applying…";
      try {
        const { result } = await api(path, body);
        closeModal();
        toast(`Done: ${result.title}`);
        resolve(true);
      } catch (e) {
        openModal(`<h2>That didn't work</h2><p class="error">${esc(e.message)}</p>
          ${e.data?.result ? resultHtml(e.data.result) : ""}
          <div class="modal-actions"><button id="m-close">Close</button></div>`);
        $("#m-close").onclick = () => { closeModal(); resolve(false); };
      }
    };
  });
}

// ---- auth --------------------------------------------------------------------

function showLogin() {
  $("#app").classList.add("hidden");
  $("#login").classList.remove("hidden");
  $("#login-password").focus();
}

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#login-error").textContent = "";
  try {
    await api("/api/login", { password: $("#login-password").value });
    $("#login-password").value = "";
    await boot();
  } catch (err) { $("#login-error").textContent = err.message; }
});

$("#logout").onclick = async () => { await api("/api/logout", {}); showLogin(); };

async function boot() {
  state.me = await api("/api/me");
  $("#login-host").textContent = `Managing ${state.me.host}`;
  if (!state.me.logged_in) return showLogin();
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  $("#hostname").textContent = `${state.me.host} · ${state.me.share_root}`;
  const tab = location.hash.slice(1);
  show(VIEWS[tab] ? tab : "overview");
}

$("#tabs").addEventListener("click", (e) => { if (e.target.dataset.tab) show(e.target.dataset.tab); });

async function show(tab) {
  state.tab = tab;
  history.replaceState(null, "", "#" + tab);
  $$("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  const view = $("#view");
  view.innerHTML = `<p class="muted">Loading…</p>`;
  try { await VIEWS[tab](view); } catch (e) { view.innerHTML = `<div class="card"><p class="error">${esc(e.message)}</p></div>`; }
}
const reload = () => show(state.tab);

// ---- helpers -----------------------------------------------------------------

const gb = (n) => (n / 1e12 >= 1 ? (n / 1e12).toFixed(2) + " TB" : (n / 1e9).toFixed(1) + " GB");
const yes = (v) => /^(yes|true|1)$/i.test(v || "");
const worldWritable = (mode) => (parseInt(mode.slice(-1), 8) & 2) !== 0;

function nfsParse(opts) {
  const o = { access: "rw", squash: "root_squash", anonuid: "", anongid: "", other: [] };
  for (const part of (opts || "").split(",").filter(Boolean)) {
    if (part === "rw" || part === "ro") o.access = part;
    else if (["root_squash", "no_root_squash", "all_squash"].includes(part)) o.squash = part;
    else if (part === "no_all_squash") continue;
    else if (part.startsWith("anonuid=")) o.anonuid = part.slice(8);
    else if (part.startsWith("anongid=")) o.anongid = part.slice(8);
    else o.other.push(part);
  }
  return o;
}
function nfsBuild(o) {
  const parts = [o.access, ...o.other, o.squash];
  if (o.anonuid) parts.push("anonuid=" + o.anonuid);
  if (o.anongid) parts.push("anongid=" + o.anongid);
  return parts.filter(Boolean).join(",");
}
function nfsSummary(c) {
  const o = nfsParse(c.options);
  const cls = o.squash === "no_root_squash" ? "warn" : "";
  const squash = o.squash === "all_squash" ? `all→${o.anonuid || "nobody"}` : o.squash.replace("_", " ");
  return `<span class="chip ${cls}" title="${esc(c.options)}">${esc(c.host)} · ${o.access} · ${esc(squash)}</span>`;
}

// ---- overview ----------------------------------------------------------------

async function overview(view) {
  const d = await api("/api/overview");
  const svc = Object.entries(d.services).map(([k, v]) =>
    `<span class="chip ${v === "active" ? "ok" : "bad"}">${esc(k)}: ${esc(v)}</span>`).join(" ");
  const disk = d.disk ? `<div class="stat"><div class="label">${esc(state.me.share_root)}</div>
      <div class="value">${gb(d.disk.avail)} free</div><div class="hint">${gb(d.disk.used)} of ${gb(d.disk.size)} used</div>
      <div class="bar"><div style="width:${(100 * d.disk.used / d.disk.size).toFixed(1)}%"></div></div></div>` : "";
  const rows = d.folders.map((f) => {
    const smb = f.smb.map((s) => {
      const who = s["valid users"] || (yes(s["guest ok"]) ? "guests" : "any user");
      const ro = yes(s["read only"]) ? "read-only" : "read/write";
      return `<span class="chip ${yes(s["guest ok"]) ? "warn" : ""}" title="${esc(ro)}">[${esc(s.name)}] ${esc(who)} · ${ro}</span>`;
    }).join("") || `<span class="muted">—</span>`;
    const exp = f.nfs.flatMap((e) => e.clients.map(nfsSummary)).join("") || `<span class="muted">—</span>`;
    return `<tr><td class="mono">${esc(f.path)}</td>
      <td><span class="mono">${esc(f.owner)}:${esc(f.group)}</span><br><span class="mono ${worldWritable(f.mode) ? "chip warn" : "muted"}">${esc(f.mode)} ${esc(f.symbolic)}</span></td>
      <td>${smb}</td><td>${exp}</td></tr>`;
  }).join("");
  view.innerHTML = `
    <div class="stats"><div class="stat"><div class="label">Services</div><div style="margin-top:6px">${svc}</div></div>${disk}
      <div class="stat"><div class="label">Folders</div><div class="value">${d.folders.length}</div></div></div>
    <div class="card"><h3>Who can reach what</h3>
      <p class="hint">Amber marks things worth a second look: guest access, no_root_squash, or world-writable folders.</p>
      <div class="table-wrap"><table><thead><tr><th>Folder</th><th>Owner · mode</th><th>SMB</th><th>NFS clients</th></tr></thead>
      <tbody>${rows}</tbody></table></div></div>`;
}

// ---- SMB ---------------------------------------------------------------------

const SMB_FIELDS = [
  ["path", "Path", "text"], ["comment", "Comment", "text"],
  ["read only", "Read only", "bool"], ["browseable", "Browseable", "bool"], ["guest ok", "Guest access", "bool"],
  ["valid users", "Valid users", "text", "Who may connect. e.g. alice @sambashare"],
  ["write list", "Write list", "text", "Can write even if read only"],
  ["read list", "Read list", "text", "Read-only even if writable"],
  ["invalid users", "Invalid users", "text"], ["admin users", "Admin users", "text", "Act as root on this share"],
  ["force user", "Force user", "text"], ["force group", "Force group", "text"],
  ["create mask", "Create mask", "text"], ["directory mask", "Directory mask", "text"],
  ["hosts allow", "Hosts allow", "text", "e.g. 10.0.20.0/24"], ["hosts deny", "Hosts deny", "text"],
];
const SMB_KEYS = new Set(SMB_FIELDS.map((f) => f[0]));

async function smb(view) {
  const d = await api("/api/smb");
  const cards = d.shares.map((s) => {
    const p = s.params;
    return `<div class="card"><div class="row spread"><div><h3>[${esc(s.name)}]</h3>
        <div class="mono muted">${esc(p.path || "")}</div></div>
        <div class="row"><button data-edit="${esc(s.name)}">Edit</button><button class="danger" data-del="${esc(s.name)}">Delete</button></div></div>
      <div style="margin-top:8px">
        <span class="chip">${yes(p["read only"]) ? "read-only" : "read/write"}</span>
        <span class="chip ${yes(p["guest ok"]) ? "warn" : ""}">guest ${yes(p["guest ok"]) ? "allowed" : "off"}</span>
        ${p["valid users"] ? `<span class="chip">valid: ${esc(p["valid users"])}</span>` : `<span class="chip warn">valid: any user</span>`}
        ${p["write list"] ? `<span class="chip">write: ${esc(p["write list"])}</span>` : ""}
        ${p["force group"] ? `<span class="chip">group: ${esc(p["force group"])}</span>` : ""}
      </div></div>`;
  }).join("") || `<div class="card muted">No shares in the Samba registry yet.</div>`;
  view.innerHTML = `<div class="toolbar"><h2>SMB shares</h2><button class="primary" id="new-share">New share</button></div>
    ${d.registry ? "" : `<div class="card"><p class="error">smb.conf doesn't include the registry, so changes here won't take effect.
      Add <code>include = registry</code> to [global].</p></div>`}
    ${cards}`;
  $("#new-share").onclick = () => shareForm(null);
  $$("[data-edit]", view).forEach((b) => b.onclick = () => shareForm(d.shares.find((s) => s.name === b.dataset.edit)));
  $$("[data-del]", view).forEach((b) => b.onclick = async () => {
    if (await change("/api/smb/delete", { name: b.dataset.del })) reload();
  });
}

async function shareForm(share) {
  const isNew = !share;
  const p = share ? share.params : { "read only": "no", browseable: "yes", "guest ok": "no",
    "valid users": "@" + state.me.default_group, "force group": state.me.default_group,
    "create mask": "0664", "directory mask": "2775", path: state.me.share_root + "/" };
  const extra = Object.entries(p).filter(([k]) => !SMB_KEYS.has(k));
  const field = ([key, label, type, hint]) => type === "bool"
    ? `<label class="field">${label}<select data-key="${esc(key)}">
        <option value="">(default)</option><option ${yes(p[key]) ? "selected" : ""}>yes</option>
        <option ${p[key] !== undefined && !yes(p[key]) ? "selected" : ""}>no</option></select></label>`
    : `<label class="field">${label}<input data-key="${esc(key)}" value="${esc(p[key] || "")}" placeholder="${esc(hint || "")}"></label>`;
  const paramRow = (k = "", val = "") => `<div class="param-row"><input class="pk" value="${esc(k)}" placeholder="parameter">
      <input class="pv" value="${esc(val)}" placeholder="value"><button class="ghost danger" data-rm>✕</button></div>`;
  const m = openModal(`<h2>${isNew ? "New SMB share" : `Edit [${esc(share.name)}]`}</h2>
    ${isNew ? `<label class="field" style="margin-bottom:12px">Share name<input id="sf-name" placeholder="e.g. Photos"></label>` : ""}
    <div class="grid">${SMB_FIELDS.map(field).join("")}</div>
    <p class="hint">Users and groups are space separated; prefix groups with @. Empty fields are removed from the share.</p>
    <h3 style="margin-top:14px">Other parameters</h3><div id="sf-extra">${extra.map(([k, val]) => paramRow(k, val)).join("")}</div>
    <button id="sf-add" class="ghost">+ Add parameter</button>
    ${isNew ? `<div class="card" style="margin-top:12px"><label class="check"><input type="checkbox" id="sf-mkdir" checked> Create the folder if it doesn't exist</label>
      <div class="row" style="margin-top:8px"><label class="field">Owner<input id="sf-owner" value="root"></label>
      <label class="field">Group<input id="sf-group" value="${esc(state.me.default_group)}"></label>
      <label class="field">Mode<input id="sf-mode" value="2775"></label></div></div>` : ""}
    <div class="modal-actions"><button id="sf-cancel">Cancel</button><button class="primary" id="sf-save">Review changes</button></div>`);
  $("#sf-add", m).onclick = () => $("#sf-extra", m).insertAdjacentHTML("beforeend", paramRow());
  $("#sf-extra", m).onclick = (e) => { if (e.target.dataset.rm !== undefined) e.target.parentElement.remove(); };
  $("#sf-cancel", m).onclick = closeModal;
  $("#sf-save", m).onclick = async () => {
    const params = {};
    $$("[data-key]", m).forEach((el) => { if (el.value.trim()) params[el.dataset.key] = el.value.trim(); });
    $$(".param-row", m).forEach((r) => { const k = $(".pk", r).value.trim(); if (k) params[k] = $(".pv", r).value.trim(); });
    let ok;
    if (isNew) {
      const mkdir = $("#sf-mkdir", m).checked ? { owner: $("#sf-owner", m).value, group: $("#sf-group", m).value, mode: $("#sf-mode", m).value } : null;
      ok = await change("/api/smb/create", { name: $("#sf-name", m).value, params, mkdir });
    } else {
      ok = await change("/api/smb/update", { name: share.name, params });
    }
    if (ok) reload(); else if (!$("#modal").open) shareForm(share);
  };
}

// ---- users & groups ----------------------------------------------------------

async function users(view) {
  const d = await api("/api/users");
  const groupNames = d.groups.map((g) => g.name);
  const rows = d.users.map((u) => `<tr>
      <td><strong>${esc(u.name)}</strong>${u.full_name && u.full_name !== u.name ? `<div class="muted">${esc(u.full_name)}</div>` : ""}</td>
      <td>${u.disabled ? `<span class="chip bad">disabled</span>` : `<span class="chip ok">enabled</span>`}</td>
      <td>${u.groups.map((g) => `<span class="chip">${esc(g)}</span>`).join("") || `<span class="muted">—</span>`}</td>
      <td class="muted">${esc(u.password_last_set)}</td>
      <td><div class="row">
        <button data-act="groups" data-u="${esc(u.name)}">Groups</button>
        <button data-act="password" data-u="${esc(u.name)}">Password</button>
        ${u.protected ? "" : `<button data-act="${u.disabled ? "enable" : "disable"}" data-u="${esc(u.name)}">${u.disabled ? "Enable" : "Disable"}</button>
        <button class="danger" data-act="delete" data-u="${esc(u.name)}">Remove</button>`}
      </div></td></tr>`).join("");
  const groups = d.groups.map((g) => `<tr><td><strong>${esc(g.name)}</strong></td><td class="muted">${g.gid}</td>
      <td>${g.members.map((m) => `<span class="chip">${esc(m)}</span>`).join("") || `<span class="muted">—</span>`}</td></tr>`).join("");
  view.innerHTML = `<div class="toolbar"><h2>Samba users</h2><button class="primary" id="new-user">Add user</button></div>
    <div class="card table-wrap"><table><thead><tr><th>User</th><th>Status</th><th>Groups</th><th>Password set</th><th></th></tr></thead>
      <tbody>${rows || `<tr><td colspan="5" class="muted">No Samba users.</td></tr>`}</tbody></table></div>
    <div class="toolbar" style="margin-top:20px"><h2>Groups</h2><button id="new-group">New group</button></div>
    <div class="card table-wrap"><table><thead><tr><th>Group</th><th>GID</th><th>Members</th></tr></thead><tbody>${groups}</tbody></table></div>`;

  const groupChecks = (selected, primary = "") => groupNames.map((g) =>
    `<label class="check" ${g === primary ? 'title="Primary group"' : ""}><input type="checkbox" value="${esc(g)}"
      ${selected.includes(g) ? "checked" : ""} ${g === primary ? "disabled" : ""}> ${esc(g)}</label>`).join(" ");

  $("#new-user").onclick = () => {
    const m = openModal(`<h2>Add Samba user</h2>
      <div class="grid"><label class="field">Username<input id="nu-name" autocomplete="off"></label>
      <label class="field">Password<input id="nu-pw" type="password" autocomplete="new-password"></label></div>
      <p class="hint">Creates a Linux account with no shell or home if one doesn't exist, then the Samba account.</p>
      <h3>Groups</h3><div class="row" id="nu-groups">${groupChecks([state.me.default_group])}</div>
      <div class="modal-actions"><button id="c">Cancel</button><button class="primary" id="s">Review changes</button></div>`);
    $("#c", m).onclick = closeModal;
    $("#s", m).onclick = async () => {
      const body = { name: $("#nu-name", m).value, password: $("#nu-pw", m).value,
        groups: $$("#nu-groups input:checked", m).map((i) => i.value) };
      if (await change("/api/users/create", body)) reload();
    };
  };
  $("#new-group").onclick = () => {
    const m = openModal(`<h2>New group</h2><label class="field">Group name<input id="ng-name"></label>
      <div class="modal-actions"><button id="c">Cancel</button><button class="primary" id="s">Review changes</button></div>`);
    $("#c", m).onclick = closeModal;
    $("#s", m).onclick = async () => { if (await change("/api/groups/create", { name: $("#ng-name", m).value })) reload(); };
  };
  $$("[data-act]", view).forEach((b) => b.onclick = async () => {
    const name = b.dataset.u, u = d.users.find((x) => x.name === name);
    if (b.dataset.act === "groups") {
      const m = openModal(`<h2>Groups for ${esc(name)}</h2><div class="row" id="ug">${groupChecks(u.groups, u.primary_group)}</div>
        <p class="hint">Primary group: ${esc(u.primary_group || "?")} (not changed here). Group changes apply to new SMB connections.</p>
        <div class="modal-actions"><button id="c">Cancel</button><button class="primary" id="s">Review changes</button></div>`);
      $("#c", m).onclick = closeModal;
      $("#s", m).onclick = async () => {
        if (await change("/api/users/groups", { name, groups: $$("#ug input:checked:not(:disabled)", m).map((i) => i.value) })) reload();
      };
    } else if (b.dataset.act === "password") {
      const m = openModal(`<h2>New Samba password for ${esc(name)}</h2>
        <label class="field">Password<input id="pw" type="password" autocomplete="new-password"></label>
        <div class="modal-actions"><button id="c">Cancel</button><button class="primary" id="s">Review changes</button></div>`);
      $("#c", m).onclick = closeModal;
      $("#s", m).onclick = async () => { if (await change("/api/users/password", { name, password: $("#pw", m).value })) reload(); };
    } else if (b.dataset.act === "delete") {
      if (await change("/api/users/delete", { name })) reload();
    } else {
      if (await change("/api/users/enabled", { name, enabled: b.dataset.act === "enable" })) reload();
    }
  });
}

// ---- NFS ---------------------------------------------------------------------

async function nfsView(view) {
  const d = await api("/api/nfs");
  const cards = d.exports.map((e, i) => `<div class="card"><div class="row spread">
      <div><h3 class="mono">${esc(e.path)}</h3><div class="hint mono">${esc(e.file)}:${e.line + 1}</div></div>
      <div class="row"><button data-edit="${i}">Edit</button><button class="danger" data-del="${i}">Remove</button></div></div>
      <div style="margin-top:8px">${e.clients.map(nfsSummary).join("")}</div>
      ${e.defaults ? `<div class="hint">Line defaults: -${esc(e.defaults)}</div>` : ""}</div>`).join("")
    || `<div class="card muted">No exports.</div>`;
  view.innerHTML = `<div class="toolbar"><h2>NFS exports</h2><button class="primary" id="new-exp">New export</button></div>
    <p class="hint">Files: ${d.files.map((f) => `<code>${esc(f)}</code>`).join(", ")}. New exports go in <code>${esc(d.managed_file)}</code>.
      Each save backs up the file, runs <code>exportfs -ra</code>, and restores the backup if that fails.</p>${cards}`;
  $("#new-exp").onclick = () => exportForm(null);
  $$("[data-edit]", view).forEach((b) => b.onclick = () => exportForm(d.exports[b.dataset.edit]));
  $$("[data-del]", view).forEach((b) => b.onclick = async () => {
    const e = d.exports[b.dataset.del];
    if (await change("/api/nfs/delete", { file: e.file, id: e.id })) reload();
  });
}

function exportForm(exp) {
  const clients = exp ? exp.clients : [{ host: "10.0.20.0/24", options: "rw,sync,no_subtree_check,root_squash" }];
  const clientRow = (c) => {
    const o = nfsParse(c.options);
    const sel = (cls, opts, val) => `<select class="${cls}">${opts.map((x) => `<option ${x === val ? "selected" : ""}>${x}</option>`).join("")}</select>`;
    return `<div class="client-row">
      <input class="c-host" value="${esc(c.host)}" placeholder="host, IP or CIDR">
      ${sel("c-access", ["rw", "ro"], o.access)}
      ${sel("c-squash", ["root_squash", "no_root_squash", "all_squash"], o.squash)}
      <input class="c-uid" value="${esc(o.anonuid)}" placeholder="anonuid">
      <input class="c-gid" value="${esc(o.anongid)}" placeholder="anongid">
      <input class="c-other" value="${esc(o.other.join(","))}" placeholder="other options">
      <button class="ghost danger" data-rm>✕</button></div>`;
  };
  const m = openModal(`<h2>${exp ? "Edit NFS export" : "New NFS export"}</h2>
    <label class="field" style="margin-bottom:12px">Path<input id="ef-path" class="mono" value="${esc(exp ? exp.path : state.me.share_root + "/")}"></label>
    <h3>Clients</h3><div class="hint" style="margin-bottom:6px">host · access · root mapping · anonuid · anongid · other options</div>
    <div id="ef-clients">${clients.map(clientRow).join("")}</div>
    <button class="ghost" id="ef-add">+ Add client</button>
    <p class="hint"><strong>no_root_squash</strong> lets root on the client act as root on these files. <strong>all_squash</strong> maps everyone to anonuid/anongid.</p>
    <div class="modal-actions"><button id="c">Cancel</button><button class="primary" id="s">Review changes</button></div>`);
  $("#ef-add", m).onclick = () => $("#ef-clients", m).insertAdjacentHTML("beforeend", clientRow({ host: "", options: "rw,sync,no_subtree_check,root_squash" }));
  $("#ef-clients", m).onclick = (e) => { if (e.target.dataset.rm !== undefined) e.target.parentElement.remove(); };
  $("#c", m).onclick = closeModal;
  $("#s", m).onclick = async () => {
    const list = $$(".client-row", m).map((r) => ({
      host: $(".c-host", r).value.trim(),
      options: nfsBuild({ access: $(".c-access", r).value, squash: $(".c-squash", r).value,
        anonuid: $(".c-uid", r).value.trim(), anongid: $(".c-gid", r).value.trim(),
        other: $(".c-other", r).value.split(",").map((x) => x.trim()).filter(Boolean) }),
    }));
    const path = $("#ef-path", m).value;
    const ok = exp ? await change("/api/nfs/update", { file: exp.file, id: exp.id, path, clients: list })
      : await change("/api/nfs/create", { path, clients: list });
    if (ok) reload(); else if (!$("#modal").open) exportForm(exp);
  };
}

// ---- folders -----------------------------------------------------------------

async function foldersView(view) {
  const d = await api("/api/folders");
  const rows = d.folders.map((f, i) => `<tr><td class="mono">${esc(f.path)}</td><td class="mono">${esc(f.owner)}</td>
      <td class="mono">${esc(f.group)}</td><td class="mono ${worldWritable(f.mode) ? "chip warn" : ""}">${esc(f.mode)}</td>
      <td class="mono muted">${esc(f.symbolic)}</td><td class="mono muted">${esc(f.selinux)}</td>
      <td><button data-i="${i}">Change</button></td></tr>`).join("");
  view.innerHTML = `<div class="toolbar"><h2>Folders</h2></div>
    <div class="card table-wrap"><table><thead><tr><th>Folder</th><th>Owner</th><th>Group</th><th>Mode</th><th></th><th>SELinux</th><th></th></tr></thead>
    <tbody>${rows}</tbody></table></div>
    <p class="hint">Mode 2775 = owner and group can write, others read, new files inherit the folder's group (setgid).
      For Samba with SELinux enforcing, folders need a samba_share_t label or the samba_export_all_rw boolean.</p>`;
  $$("[data-i]", view).forEach((b) => b.onclick = () => folderForm(d.folders[b.dataset.i]));
}

function folderForm(f) {
  const m = openModal(`<h2 class="mono">${esc(f.path)}</h2>
    <div class="grid"><label class="field">Owner<input id="ff-owner" value="${esc(f.owner)}"></label>
      <label class="field">Group<input id="ff-group" value="${esc(f.group)}"></label>
      <label class="field">Mode<input id="ff-mode" value="${esc(f.mode)}"></label></div>
    <div class="card" style="margin-top:12px"><label class="check"><input type="checkbox" id="ff-rec"> Apply to everything inside</label>
      <div id="ff-recopts" class="hidden" style="margin-top:8px">
        <div class="row"><label class="field">Folder mode (inside)<input id="ff-dmode" disabled></label>
        <label class="field">File mode<input id="ff-fmode" value="0664"></label></div>
        <p class="hint">Folders get the mode above, files get the file mode. This can touch a lot of files and can't be undone automatically.</p>
      </div></div>
    <div class="modal-actions"><button id="c">Cancel</button><button class="primary" id="s">Review changes</button></div>`);
  const sync = () => { $("#ff-dmode", m).value = $("#ff-mode", m).value; $("#ff-recopts", m).classList.toggle("hidden", !$("#ff-rec", m).checked); };
  $("#ff-rec", m).onchange = sync; $("#ff-mode", m).oninput = sync; sync();
  $("#c", m).onclick = closeModal;
  $("#s", m).onclick = async () => {
    const body = { path: f.path, owner: $("#ff-owner", m).value, group: $("#ff-group", m).value, mode: $("#ff-mode", m).value,
      recursive: $("#ff-rec", m).checked, file_mode: $("#ff-fmode", m).value };
    if (await change("/api/folders/update", body)) reload(); else if (!$("#modal").open) folderForm(f);
  };
}

// ---- activity ----------------------------------------------------------------

async function activity(view) {
  const d = await api("/api/activity");
  const items = d.entries.map((e) => `<div class="card"><div class="row spread"><h3>${esc(e.title)}</h3>
      <span class="chip ${e.ok ? "ok" : "bad"}">${e.ok ? "ok" : "failed"}</span></div>
      <div class="hint">${esc(e.ts)} · from ${esc(e.ip)}</div>
      <details><summary class="hint">Commands</summary>${resultHtml(e)}</details></div>`).join("");
  view.innerHTML = `<div class="toolbar"><h2>Activity</h2></div>${items || `<div class="card muted">No changes yet.</div>`}`;
}

const VIEWS = { overview, smb, users, nfs: nfsView, folders: foldersView, activity };
boot().catch((e) => { document.body.textContent = e.message; });
