const state = {
  screen: "libraries",
  libraryId: null,
  entryId: null,
  draft: null,
  libraries: [],
  entries: [],
  query: "",
  syncing: false,
  picks: {},
  session: null,
  access: null,
  needsSetup: false,
  directory: null,
  permRows: [],
  previews: {},
};

const memoryStore = {};
let storageBlocked = false;

function siteStore() {
  try {
    return window.localStorage;
  } catch (error) {
    storageBlocked = true;
    return null;
  }
}

function stored(key) {
  const box = siteStore();
  if (!box) return Object.prototype.hasOwnProperty.call(memoryStore, key) ? memoryStore[key] : null;
  try {
    return box.getItem(key);
  } catch (error) {
    storageBlocked = true;
    return Object.prototype.hasOwnProperty.call(memoryStore, key) ? memoryStore[key] : null;
  }
}

function storeSet(key, value) {
  memoryStore[key] = value;
  const box = siteStore();
  if (!box) return;
  try {
    box.setItem(key, value);
  } catch (error) {
    storageBlocked = true;
  }
}

function storeDrop(key) {
  delete memoryStore[key];
  const box = siteStore();
  if (!box) return;
  try {
    box.removeItem(key);
  } catch (error) {
    storageBlocked = true;
  }
}

let dbPromise = null;
let syncing = false;
let syncQueued = false;

function uuid() {
  if (crypto.randomUUID) return crypto.randomUUID();
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
  });
}

function now() {
  return new Date().toISOString();
}

function clone(value) {
  return JSON.parse(JSON.stringify(value ?? null));
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[ch]));
}

function devices() {
  const raw = stored("cafinewo.devices");
  if (!raw) {
    const first = { id: uuid(), name: "Field phone" };
    storeSet("cafinewo.devices", JSON.stringify([first]));
    storeSet("cafinewo.active", first.id);
    return [first];
  }
  return JSON.parse(raw);
}

function saveDevices(list) {
  storeSet("cafinewo.devices", JSON.stringify(list));
}

function device() {
  const list = devices();
  const active = stored("cafinewo.active");
  return list.find((item) => item.id === active) || list[0];
}

function isOnline() {
  return navigator.onLine && stored("cafinewo.offline") !== "1";
}

function loadSession() {
  try {
    return JSON.parse(stored("cafinewo.session") || "null");
  } catch (error) {
    return null;
  }
}

function saveSession() {
  storeSet("cafinewo.session", JSON.stringify(state.session));
  if (state.access && state.session?.user) {
    storeSet("cafinewo.access." + state.session.user.id, JSON.stringify(state.access));
  }
}

function rankLevel(level) {
  return { none: 0, own: 1, all: 2 }[level] || 0;
}

function bestLevel(libraryId, target, action, fieldId) {
  if (state.access?.is_admin) return "all";
  let best = "none";
  for (const grant of state.access?.grants || []) {
    if (grant.library_id !== libraryId && grant.library_id !== "*") continue;
    if (grant.target !== target) continue;
    if (target === "field" && (grant.field_id || "") !== (fieldId || "")) continue;
    const level = grant[action] || "none";
    if (rankLevel(level) > rankLevel(best)) best = level;
  }
  return best;
}

function fieldLevel(libraryId, fieldId, action) {
  if (state.access?.is_admin) return "all";
  const specific = (state.access?.grants || []).filter(
    (grant) =>
      (grant.library_id === libraryId || grant.library_id === "*") &&
      grant.target === "field" &&
      (grant.field_id || "") === fieldId
  );
  if (!specific.length) return bestLevel(libraryId, "entry", action);
  let best = "none";
  for (const grant of specific) {
    const level = grant[action] || "none";
    if (rankLevel(level) > rankLevel(best)) best = level;
  }
  return best;
}

function can(libraryId, target, action, createdBy, fieldId) {
  const level = target === "field" ? fieldLevel(libraryId, fieldId, action) : bestLevel(libraryId, target, action);
  if (action === "create") return level === "all" || level === "own";
  if (level === "all") return true;
  if (level === "own") return !!createdBy && createdBy === state.session?.user?.id;
  return false;
}

function canCreateLibrary() {
  return !!state.access?.is_admin;
}

function libraryAccess(library) {
  return library?.access || {
    create: { mode: "none", users: [] },
    edit: { mode: "none", users: [] },
    erase: { mode: "none", users: [] },
  };
}

function ruleOk(rule, createdBy) {
  if (!rule) return false;
  if (rule.mode === "all") return true;
  if (rule.mode === "own") return !!createdBy && createdBy === state.session?.user?.id;
  if (rule.mode === "list") return (rule.users || []).includes(state.session?.user?.id);
  return false;
}

function fieldsForRole(library, role) {
  const fields = library?.fields || [];
  const matched = fields.filter((field) => field.role === role);
  if (matched.length || role !== "viewers") return matched;
  return fields.filter((field) => field.type === "users" && !field.role);
}

function roleIds(library, values, role) {
  const ids = [];
  for (const field of fieldsForRole(library, role)) {
    const raw = values?.[field.id]?.v;
    if (Array.isArray(raw)) ids.push(...raw.map(String));
    else if (raw) ids.push(String(raw));
  }
  return ids;
}

function canSeeEntry(library, entry) {
  if (state.access?.is_admin) return true;
  if (can(library.id, "entry", "see", entry?.created_by)) return true;
  if (entry?.created_by && entry.created_by === state.session?.user?.id) return true;
  return roleIds(library, entry?.values, "viewers").includes(state.session?.user?.id);
}

function canEditEntry(library, entry) {
  if (state.access?.is_admin) return true;
  if (can(library.id, "entry", "edit", entry?.created_by)) return true;
  if (roleIds(library, entry?.values, "editors").includes(state.session?.user?.id)) return true;
  return ruleOk(libraryAccess(library).edit, entry?.created_by);
}

function canEditField(library, entry, field) {
  if (canEditEntry(library, entry)) return true;
  if (field?.viewer_edit && field.role !== "viewers" && field.role !== "editors" && canSeeEntry(library, entry)) return true;
  return false;
}

function fieldIsEditable(library, entry, field) {
  if (entry?.isNew) return canCreateEntry(library);
  return canEditField(library, entry, field);
}

function canCreateEntry(library) {
  if (state.access?.is_admin) return true;
  if (can(library.id, "entry", "create")) return true;
  return ruleOk(libraryAccess(library).create, null);
}

function canEraseEntry(library, entry) {
  if (state.access?.is_admin) return true;
  if (can(library.id, "entry", "erase", entry?.created_by)) return true;
  return ruleOk(libraryAccess(library).erase, entry?.created_by);
}

function canSeeLibrary(library) {
  if (state.access?.is_admin) return true;
  if (can(library.id, "library", "see", library.created_by)) return true;
  const entrySee = bestLevel(library.id, "entry", "see");
  if (entrySee === "all" || entrySee === "own") return true;
  const access = libraryAccess(library);
  if (["create", "edit", "erase"].some((key) => ruleOk(access[key], library.created_by))) return true;
  return state.entries.some((entry) => entry.library_id === library.id && !entry.deleted && canSeeEntry(library, entry));
}

async function api(path, body) {
  const headers = {};
  if (state.session?.token) headers.Authorization = "Bearer " + state.session.token;
  const options = { headers };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    options.method = "POST";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  const data = await response.json().catch(() => ({}));
  if (response.status === 401) {
    await signOut(false);
    throw new Error("signed out");
  }
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

async function signOut(tellServer) {
  const token = state.session?.token;
  state.session = null;
  state.access = null;
  state.screen = "libraries";
  state.libraryId = null;
  state.entryId = null;
  state.draft = null;
  state.directory = null;
  state.permRows = [];
  state.query = "";
  storeDrop("cafinewo.session");
  if (tellServer && token) {
    await fetch("/api/logout", {
      method: "POST",
      headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
      body: "{}",
    }).catch(() => {});
  }
  await resetDb();
  renderAuth();
}

function dbName() {
  const userId = state.session?.user?.id || "signed-out";
  return `cafinewo:${userId}:${device().id}`;
}

function openDb() {
  const name = dbName();
  return new Promise((resolve, reject) => {
    let request;
    try {
      request = indexedDB.open(name, 2);
    } catch (error) {
      storageBlocked = true;
      reject(error);
      return;
    }
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains("meta")) db.createObjectStore("meta");
      if (!db.objectStoreNames.contains("libraries")) db.createObjectStore("libraries", { keyPath: "id" });
      if (!db.objectStoreNames.contains("blobs")) db.createObjectStore("blobs", { keyPath: "id" });
      if (!db.objectStoreNames.contains("entries")) {
        const entries = db.createObjectStore("entries", { keyPath: "id" });
        entries.createIndex("by_library", "library_id");
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => {
      if (request.error?.name === "SecurityError") storageBlocked = true;
      reject(request.error);
    };
  });
}

function db() {
  if (!dbPromise) dbPromise = openDb();
  return dbPromise;
}

async function resetDb() {
  if (dbPromise) {
    const connection = await dbPromise;
    connection.close();
  }
  dbPromise = null;
}

async function getAll(store) {
  const connection = await db();
  return new Promise((resolve, reject) => {
    const transaction = connection.transaction(store, "readonly");
    const request = transaction.objectStore(store).getAll();
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function getOne(store, key) {
  const connection = await db();
  return new Promise((resolve, reject) => {
    const transaction = connection.transaction(store, "readonly");
    const request = transaction.objectStore(store).get(key);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function putOne(store, value, key) {
  const connection = await db();
  return new Promise((resolve, reject) => {
    const transaction = connection.transaction(store, "readwrite");
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    if (key === undefined) transaction.objectStore(store).put(value);
    else transaction.objectStore(store).put(value, key);
  });
}

async function loadState() {
  state.libraries = (await getAll("libraries")).map(withTitleField);
  state.entries = await getAll("entries");
}

function visibleLibraries() {
  return state.libraries
    .filter((library) => !library.deleted && canSeeLibrary(library))
    .sort((a, b) => a.name.localeCompare(b.name));
}

function libraryById(id) {
  return state.libraries.find((library) => library.id === id);
}

function entriesFor(libraryId) {
  const query = state.query.trim().toLowerCase();
  return state.entries
    .filter((entry) => entry.library_id === libraryId && !entry.deleted && canSeeEntry(libraryById(libraryId), entry))
    .filter((entry) => {
      if (!query) return true;
      return JSON.stringify(entry.values).toLowerCase().includes(query);
    })
    .sort((a, b) => (b.updated_at || "").localeCompare(a.updated_at || ""));
}

function titleFields(fields) {
  const list = (fields || []).map((field) => ({ ...field }));
  let index = list.findIndex((field) => field.title);
  if (index < 0) index = list.findIndex((field) => field.type === "text");
  const title = index >= 0 ? list.splice(index, 1)[0] : { id: "title" };
  title.name = "Title";
  title.type = "text";
  title.title = true;
  delete title.role;
  delete title.options;
  delete title.optionsText;
  return [title, ...list.filter((field) => !field.title)];
}

function withTitleField(library) {
  return { ...library, fields: titleFields(library.fields) };
}

function entryTitle(library, entry) {
  const field = titleFields(library?.fields)[0];
  if (!field) return "Entry";
  const value = entry?.values?.[field.id]?.v;
  if (value === null || value === undefined || value === "") return "Untitled";
  return String(value);
}

function pendingCount() {
  return state.libraries.filter((row) => row.dirty).length + state.entries.filter((row) => row.dirty).length;
}

function conflictRows() {
  return [
    ...state.libraries.filter((row) => row.conflict && !row.deleted).map((row) => ({ kind: "library", row })),
    ...state.entries.filter((row) => row.conflict).map((row) => ({ kind: "entry", row })),
  ];
}

function selectedList(value) {
  const list = Array.isArray(value) ? value : value === null || value === undefined || value === "" ? [] : [value];
  return list.map((item) => {
    if (item && typeof item === "object") return String(item.id || item.name || "");
    return String(item);
  }).filter((item) => item !== "");
}

function isSelected(selected, id, name) {
  return selected.includes(id) || (!!name && selected.includes(name));
}

function dateInputValue(value) {
  const match = String(value ?? "").match(/^(\d{4}-\d{2}-\d{2})/);
  return match ? match[1] : "";
}

function timeInputValue(value) {
  const match = String(value ?? "").match(/^(\d{2}:\d{2})/);
  return match ? match[1] : "";
}

function cellValue(cell) {
  if (!cell || cell.v === undefined || cell.v === "") return null;
  return cell.v;
}

function sameVal(a, b) {
  return JSON.stringify(cellValue(a)) === JSON.stringify(cellValue(b));
}

function mergeEntry(local, remote) {
  const ancestor = local.ancestor || {};
  const localValues = local.values || {};
  const remoteValues = remote.values || {};
  const ids = new Set([...Object.keys(ancestor), ...Object.keys(localValues), ...Object.keys(remoteValues)]);
  const merged = {};
  const contested = [];
  let localChanged = false;
  let remoteChanged = false;
  ids.forEach((id) => {
    const base = ancestor[id];
    const mine = localValues[id];
    const theirs = remoteValues[id];
    const mineChanged = !sameVal(base, mine);
    const theirsChanged = !sameVal(base, theirs);
    if (mineChanged) localChanged = true;
    if (theirsChanged) remoteChanged = true;
    if (mineChanged && theirsChanged && !sameVal(mine, theirs)) {
      contested.push(id);
      merged[id] = mine !== undefined ? mine : theirs;
    } else if (theirsChanged) {
      merged[id] = theirs;
    } else if (mine !== undefined) {
      merged[id] = mine;
    } else if (theirs !== undefined) {
      merged[id] = theirs;
    }
  });
  const deleteContested = !!local.deleted !== !!remote.deleted && (local.deleted ? remoteChanged : localChanged);
  let deleted = !!local.deleted;
  if (!deleteContested) {
    if (local.deleted !== remote.deleted) deleted = !!(local.deleted || remote.deleted);
  }
  return { merged, contested, deleteContested, deleted };
}

function displayValue(field, cell) {
  const value = cellValue(cell);
  if (value === null || value === undefined || value === "") return "Empty";
  if (field?.type === "boolean") return value ? "Yes" : "No";
  return String(value);
}

function fieldName(library, fieldId) {
  return library?.fields?.find((field) => field.id === fieldId)?.name || "Field";
}

function notice(message, warn, sticky) {
  const el = document.getElementById("notice");
  el.hidden = !message;
  el.className = warn ? "warn" : "";
  el.textContent = message || "";
  clearTimeout(notice.timer);
  if (message && !sticky) {
    notice.timer = setTimeout(() => {
      el.hidden = true;
    }, 2800);
  }
}

function storageNotice() {
  if (!storageBlocked) return;
  notice("This phone is blocking saved site data. Allow cookies for this site, or open it in Chrome or Safari.", true, true);
}

function render() {
  renderHeader();
  renderMain();
}

function renderHeader() {
  const online = isOnline();
  const pending = pendingCount();
  const conflicts = conflictRows().length;
  const status = online
    ? state.syncing
      ? "Syncing..."
      : pending
        ? `${pending} waiting to sync`
        : "Online"
    : pending
      ? `Offline - ${pending} saved here`
      : "Offline - saved on this device";
  document.getElementById("top").innerHTML = `
    <div>
      <h1 class="brand"><button id="home" type="button">Cafineuos</button></h1>
      <div class="device-line">
        <button id="open-devices" type="button">${esc(device().name)}</button>
        - ${esc(state.session?.user?.name || "")}
        - ${esc(status)}${conflicts ? ` - ${conflicts} conflict${conflicts === 1 ? "" : "s"}` : ""}
      </div>
    </div>
    <div class="header-actions">
      <button id="sync" class="sync-btn" type="button" ${online && !state.syncing ? "" : "disabled"}>Sync</button>
      <label class="offline-toggle">
        <input id="offline" type="checkbox" ${online ? "" : "checked"} />
        Offline
      </label>
      ${state.access?.is_admin ? '<button id="open-people" class="btn ghost" type="button">People</button>' : ""}
      <button id="open-account" class="btn ghost" type="button">Account</button>
      <button id="sign-out" class="btn ghost" type="button">Sign out</button>
    </div>
  `;
  document.getElementById("home").onclick = () => go("libraries");
  document.getElementById("open-devices").onclick = () => go("devices");
  document.getElementById("sync").onclick = () => sync();
  document.getElementById("offline").onchange = (event) => {
    storeSet("cafinewo.offline", event.target.checked ? "1" : "0");
    renderHeader();
    if (isOnline()) sync();
  };
  const people = document.getElementById("open-people");
  if (people) people.onclick = () => openPeople();
  document.getElementById("open-account").onclick = () => go("account");
  document.getElementById("sign-out").onclick = () => signOut(true);
}

function renderMain() {
  const main = document.getElementById("main");
  const conflicts = conflictRows().length;
  const banner = conflicts
    ? `<div class="banner"><span>${conflicts} conflict${conflicts === 1 ? "" : "s"} need a choice</span><button id="open-conflicts" type="button">Resolve</button></div>`
    : "";
  if (state.screen === "libraries") main.innerHTML = banner + librariesHtml();
  else if (state.screen === "library") main.innerHTML = banner + libraryHtml();
  else if (state.screen === "entry") main.innerHTML = entryHtml();
  else if (state.screen === "edit-library") main.innerHTML = libraryFormHtml();
  else if (state.screen === "conflicts") main.innerHTML = conflictsHtml();
  else if (state.screen === "devices") main.innerHTML = devicesHtml();
  else if (state.screen === "people") main.innerHTML = peopleHtml();
  else if (state.screen === "account") main.innerHTML = accountHtml();
  else if (state.screen === "access") main.innerHTML = accessHtml();
  bindMain();
}

function librariesEmptyText() {
  if (!isOnline()) {
    return "Offline is on, so this device is not syncing. Turn it off and sync. A library shared with this account stays on the device that saved it until then.";
  }
  if (canCreateLibrary()) return "No libraries yet. Create one, or start from the sample.";
  return "No libraries shared with this account yet. Sync while online.";
}

function librariesHtml() {
  const libraries = visibleLibraries();
  const cards = libraries.length
    ? `<div class="list">${libraries
        .map((library) => {
          const count = state.entries.filter((entry) => entry.library_id === library.id && !entry.deleted && canSeeEntry(library, entry)).length;
          const waiting = library.dirty || state.entries.some((entry) => entry.library_id === library.id && entry.dirty);
          const edit = state.access?.is_admin ? `<button class="btn ghost" data-edit-library="${library.id}" type="button">Edit</button>` : "";
          return `<div class="row-actions"><button class="row" data-open-library="${library.id}" type="button">
            <span><strong>${esc(library.name)}</strong><span>${count} entr${count === 1 ? "y" : "ies"}</span></span>
            ${waiting ? '<i class="dot" title="Waiting to sync"></i>' : ""}
          </button>${edit}</div>`;
        })
        .join("")}</div>`
    : `<div class="empty">${librariesEmptyText()}</div>`;
  return `
    <div class="screen-head"><h2>Libraries</h2>${canCreateLibrary() ? '<button id="new-library" class="btn primary" type="button">New</button>' : ""}</div>
    <p class="lede">Entries are stored on this device immediately. They sync when you are online. What you can see and change depends on your account.</p>
    ${cards}
    <div class="actions">${canCreateLibrary() ? '<button id="sample" class="btn ghost" type="button">Add a sample library</button>' : ""}</div>
  `;
}

function groupStorageKey(libraryId) {
  const userId = state.session?.user?.id || "local";
  return "cafinewo.groups." + userId + "." + libraryId;
}

function selectedGroupFields(library) {
  let ids = [];
  try {
    const raw = JSON.parse(stored(groupStorageKey(library.id)) || "[]");
    if (Array.isArray(raw)) ids = raw.map(String);
  } catch (error) {
    ids = [];
  }
  return ids
    .map((id) => (library.fields || []).find((field) => field.id === id))
    .filter(Boolean);
}

function saveGroupFields(libraryId, ids) {
  storeSet(groupStorageKey(libraryId), JSON.stringify(ids));
}

function groupLabel(field, entry) {
  const value = entry?.values?.[field.id]?.v;
  if (value === null || value === undefined || value === "" || (Array.isArray(value) && value.length === 0)) return "Empty";
  if (field.type === "boolean") return value ? "Yes" : "No";
  if (field.type === "users") {
    const ids = Array.isArray(value) ? value.map(String) : [String(value)];
    return ids.map((id) => (state.access?.people || []).find((person) => person.id === id)?.name || id).join(", ");
  }
  if (field.type === "image" || field.type === "file") {
    const names = fileList(value).map((item) => item.name || "File");
    return names.length ? names.join(", ") : "Empty";
  }
  if (Array.isArray(value)) return value.map(String).join(", ");
  if (value && typeof value === "object") return value.name || "File";
  return String(value);
}

function fileList(value) {
  if (Array.isArray(value)) return value.filter((item) => item && typeof item === "object" && item.id);
  if (value && typeof value === "object" && value.id) return [value];
  return [];
}

function entryRowHtml(library, entry) {
  return `<button class="row" data-open-entry="${entry.id}" type="button">
    <span><strong>${esc(entryTitle(library, entry))}</strong><span>${entry.dirty ? "Waiting to sync" : "Synced"}</span></span>
    ${entry.dirty ? '<i class="dot"></i>' : ""}
  </button>`;
}

function groupSectionsHtml(library, entries, fields, depth) {
  const field = fields[depth];
  if (!field) return entries.map((entry) => entryRowHtml(library, entry)).join("");
  const buckets = new Map();
  entries.forEach((entry) => {
    const label = groupLabel(field, entry);
    if (!buckets.has(label)) buckets.set(label, []);
    buckets.get(label).push(entry);
  });
  return [...buckets.keys()].sort((a, b) => a.localeCompare(b)).map((label) => {
    const items = buckets.get(label);
    return `<section class="group">
      <h3>${esc(field.name)}: ${esc(label)} <span class="meta">${items.length}</span></h3>
      <div class="list">${groupSectionsHtml(library, items, fields, depth + 1)}</div>
    </section>`;
  }).join("");
}

function entriesBlockHtml(library, entries) {
  if (!entries.length) {
    return `<div class="empty">${state.query.trim() ? "No matching entries." : "No entries you can see yet."}</div>`;
  }
  const fields = selectedGroupFields(library);
  if (!fields.length) return entries.map((entry) => entryRowHtml(library, entry)).join("");
  return groupSectionsHtml(library, entries, fields, 0);
}

function paintEntries(library) {
  const list = document.getElementById("entry-list");
  if (!list || !library) return;
  list.innerHTML = entriesBlockHtml(library, entriesFor(library.id));
}

function groupPickerHtml(library) {
  const selected = new Set(selectedGroupFields(library).map((field) => field.id));
  const boxes = (library.fields || [])
    .map((field) => `<label class="field check"><input data-group-field="${esc(field.id)}" type="checkbox" ${selected.has(field.id) ? "checked" : ""} /> ${esc(field.name)}</label>`)
    .join("");
  return `<div class="group-picker"><span class="meta">Group by</span><div class="group-fields">${boxes}</div></div>`;
}

function libraryHtml() {
  const library = libraryById(state.libraryId);
  if (!library) return `<p>That library is gone.</p>`;
  const entries = entriesFor(library.id);
  return `
    <div class="screen-head">
      <div>
        <button class="back" id="back" type="button">Libraries</button>
        <h2>${esc(library.name)}</h2>
      </div>
      <div class="actions">
        ${state.access?.is_admin ? '<button id="edit-fields" class="btn ghost" type="button">Edit</button><button id="open-access" class="btn ghost" type="button">Access</button>' : ""}
      </div>
    </div>
    <input id="q" class="search" placeholder="Search entries" value="${esc(state.query)}" />
    ${groupPickerHtml(library)}
    <div class="list" id="entry-list">${entriesBlockHtml(library, entries)}</div>
    <div class="actions">${canCreateEntry(library) ? '<button id="new-entry" class="btn primary" type="button">New entry</button>' : ""}</div>
  `;
}

function libraryFormHtml() {
  const draft = state.draft;
  draft.fields = titleFields(draft.fields);
  const fields = draft.fields
    .map((field, index) => {
      if (field.title) {
        return `<div class="card field-editor">
          <div class="line">
            <input value="Title" disabled />
            <span class="meta">text</span>
          </div>
          <p class="lede">Entry title. Text, always first.</p>
        </div>`;
      }
      const optionsText = field.optionsText != null ? field.optionsText : (field.options || []).join(", ");
      const options = field.type === "choice" || field.type === "multi"
        ? `<input data-options="${index}" placeholder="Options, comma separated" value="${esc(optionsText)}" />`
        : "";
      const role = field.type === "users"
        ? `<select data-role="${index}"><option value="" ${field.role ? "" : "selected"}>People list</option><option value="viewers" ${field.role === "viewers" ? "selected" : ""}>Who can see the entry</option><option value="editors" ${field.role === "editors" ? "selected" : ""}>Who can modify the entry</option></select>`
        : `<label class="field check"><input data-viewer-edit="${index}" type="checkbox" ${field.viewer_edit ? "checked" : ""} /> People who can see the entry may edit this field</label>`;
      return `<div class="card field-editor">
        <div class="line">
          <input data-fname="${index}" placeholder="Field name" value="${esc(field.name)}" />
          <select data-ftype="${index}">
            ${[["text", "text"], ["longtext", "long text"], ["number", "number"], ["date", "date"], ["time", "time"], ["boolean", "yes or no"], ["choice", "single choice"], ["multi", "multiple choice"], ["users", "people"], ["image", "image"], ["file", "file"]]
              .map(([type, label]) => `<option value="${type}" ${field.type === type ? "selected" : ""}>${label}</option>`)
              .join("")}
          </select>
          <button class="btn ghost" data-move-field="${index}" data-move="-1" type="button">Up</button>
          <button class="btn ghost" data-move-field="${index}" data-move="1" type="button">Down</button>
          <button class="btn ghost" data-remove-field="${index}" type="button">Remove</button>
        </div>
        ${options}
        ${role}
      </div>`;
    })
    .join("");
  return `
    <div class="screen-head">
      <div>
        <button class="back" id="back" type="button">Back</button>
        <h2>${draft.id ? "Edit library" : "New library"}</h2>
      </div>
    </div>
    <div class="stack">
      <label class="field">Library name
        <input id="lib-name" value="${esc(draft.name)}" />
      </label>
      <h2>Fields</h2>
      <p class="lede">This is the structure of every entry. Add a field, change its type, move it, or remove it. Title stays first.</p>
      ${fields}
      <h2>Who can use entries</h2>
      <p class="lede">None, All, Own, or a list of users. Own means the person who created the entry. Admins can always do this.</p>
      ${accessBlock(draft)}
      <div class="actions">
        <button id="add-field" class="btn ghost" type="button">Add field</button>
        <button id="save-library" class="btn primary" type="button">Save</button>
        ${draft.id && state.access?.is_admin ? '<button id="delete-library" class="btn danger" type="button">Delete library</button>' : ""}
      </div>
    </div>
  `;
}

function accessBlock(draft) {
  const access = draft.access || {
    create: { mode: "all", users: [] },
    edit: { mode: "all", users: [] },
    erase: { mode: "all", users: [] },
  };
  const people = state.access?.people || [];
  return ["create", "edit", "erase"].map((key) => {
    const rule = access[key] || { mode: "none", users: [] };
    const modes = key === "create"
      ? [["none", "None"], ["all", "All"], ["list", "These users"]]
      : [["none", "None"], ["all", "All"], ["own", "Own"], ["list", "These users"]];
    const boxes = rule.mode === "list"
      ? people.map((person) => `<label class="field check"><input data-access-user="${key}" value="${esc(person.id)}" type="checkbox" ${(rule.users || []).includes(person.id) ? "checked" : ""} /> ${esc(person.name)}</label>`).join("")
      : "";
    const title = key === "create" ? "Create entries" : key === "edit" ? "Edit entries" : "Delete entries";
    return `<div class="card"><strong>${title}</strong><select data-access-mode="${key}">${modes.map(([value, label]) => `<option value="${value}" ${rule.mode === value ? "selected" : ""}>${label}</option>`).join("")}</select>${boxes}</div>`;
  }).join("");
}

function readOnlyText(field, value) {
  if (field.type === "boolean") {
    const on = value === true || value === 1 || value === "1" || value === "true" || value === "yes" || value === "Yes";
    return on ? "Yes" : "No";
  }
  if (field.type === "users") {
    const people = state.access?.people || [];
    return selectedList(value).map((id) => people.find((person) => person.id === id || person.name === id)?.name || id).join(", ");
  }
  if (field.type === "multi" || Array.isArray(value)) return selectedList(value).join(", ");
  if (value === null || value === undefined || value === "") return "";
  return String(value);
}

function readOnlyHtml(field, value) {
  const text = readOnlyText(field, value);
  return `<div class="field"><span>${esc(field.name)}</span><p class="readonly">${text ? esc(text) : "Empty"}</p></div>`;
}

function fileFieldHtml(field, value, editable) {
  const files = fileList(value);
  const rows = files.map((meta) => {
    const preview = meta.id && state.previews?.[meta.id] && field.type === "image" ? `<img class="preview" alt="" src="${esc(state.previews[meta.id])}" />` : "";
    const download = meta.id ? `<button class="btn ghost" type="button" data-download="${esc(meta.id)}" data-download-name="${esc(meta.name || "file")}">Download</button>` : "";
    const remove = editable && meta.id ? `<button class="btn ghost" type="button" data-remove-file="${esc(field.id)}" data-blob="${esc(meta.id)}">Remove</button>` : "";
    return `<div class="file-row">${preview}<span>${esc(meta.name || "File")}</span><div class="actions">${download}${remove}</div></div>`;
  }).join("");
  const empty = files.length ? "" : `<span>No file yet</span>`;
  const add = editable
    ? `<button class="btn ghost" type="button" data-add-file="${esc(field.id)}" data-kind="${esc(field.type)}">${field.type === "image" ? "Add image" : "Add file"}</button>`
    : "";
  return `<div class="field"><span>${esc(field.name)}</span>${empty}${rows}${add}</div>`;
}

function entryHtml() {
  const library = libraryById(state.libraryId);
  const draft = state.draft;
  if (!library || !draft) return `<p>Missing entry.</p>`;
  const createdBy = draft.created_by || state.session?.user?.id;
  const fields = titleFields(library.fields)
    .filter((field) => draft.isNew ? true : canSeeEntry(library, draft))
    .map((field) => {
      const editable = fieldIsEditable(library, draft, field);
      const value = draft.values?.[field.id]?.v ?? "";
      const locked = editable ? "" : "disabled";
      if (!editable && field.type !== "image" && field.type !== "file") return readOnlyHtml(field, value);
      if (field.type === "users") {
        const selected = selectedList(value);
        const people = state.access?.people || [];
        const boxes = people.length
          ? people.map((person) => `<label class="field check"><input data-users="${field.id}" value="${esc(person.id)}" type="checkbox" ${isSelected(selected, person.id, person.name) ? "checked" : ""} ${locked} /> ${esc(person.name)}</label>`).join("")
          : `<p class="lede">Sync while online once so names are available offline.</p>`;
        return `<div class="field"><span>${esc(field.name)}</span>${boxes}</div>`;
      }
      if (field.type === "multi") {
        const selected = selectedList(value);
        const boxes = (field.options || []).map((option) => `<label class="field check"><input data-multi="${field.id}" value="${esc(option)}" type="checkbox" ${isSelected(selected, option) ? "checked" : ""} ${locked} /> ${esc(option)}</label>`).join("");
        return `<div class="field"><span>${esc(field.name)}</span>${boxes}</div>`;
      }
      if (field.type === "image" || field.type === "file") return fileFieldHtml(field, value, editable);
      if (field.type === "longtext") {
        return `<label class="field">${esc(field.name)}<textarea data-field="${field.id}" ${locked}>${esc(value)}</textarea></label>`;
      }
      if (field.type === "boolean") {
        const on = value === true || value === 1 || value === "1" || value === "true" || value === "yes" || value === "Yes";
        return `<label class="field check"><input data-field="${field.id}" type="checkbox" ${on ? "checked" : ""} ${locked} /> ${esc(field.name)}</label>`;
      }
      if (field.type === "time") {
        return `<label class="field">${esc(field.name)}<input data-field="${field.id}" type="time" value="${esc(timeInputValue(value))}" ${locked} /></label>`;
      }
      if (field.type === "date") {
        return `<label class="field">${esc(field.name)}<input data-field="${field.id}" type="date" value="${esc(dateInputValue(value))}" ${locked} /></label>`;
      }
      if (field.type === "choice") {
        const options = (field.options || [])
          .map((option) => `<option value="${esc(option)}" ${option === value ? "selected" : ""}>${esc(option)}</option>`)
          .join("");
        return `<label class="field">${esc(field.name)}<select data-field="${field.id}" ${locked}><option value="">Choose</option>${options}</select></label>`;
      }
      const type = field.type === "number" ? "number" : field.type === "date" ? "date" : "text";
      return `<label class="field">${esc(field.name)}<input data-field="${field.id}" type="${type}" value="${esc(value)}" ${locked} /></label>`;
    })
    .join("");
  const canErase = !draft.isNew && canEraseEntry(library, draft);
  return `
    <div class="screen-head">
      <div>
        <button class="back" id="back" type="button">Back</button>
        <h2>${draft.isNew ? "New entry" : esc(entryTitle(library, draft))}</h2>
      </div>
    </div>
    <div class="stack">
      ${fields || '<p class="lede">This library has no fields yet.</p>'}
      <div class="actions">
        <button id="save-entry" class="btn primary" type="button">Save</button>
        ${canErase ? '<button id="delete-entry" class="btn danger" type="button">Delete</button>' : ""}
      </div>
    </div>
  `;
}

function conflictsHtml() {
  const rows = conflictRows();
  if (!rows.length) {
    return `<div class="screen-head"><div><button class="back" id="back" type="button">Libraries</button><h2>Conflicts</h2></div></div><div class="empty">Nothing to resolve.</div>`;
  }
  const cards = rows
    .map(({ kind, row }) => {
      if (kind === "library") return libraryConflictHtml(row);
      return entryConflictHtml(row);
    })
    .join("");
  return `
    <div class="screen-head"><div><button class="back" id="back" type="button">Libraries</button><h2>Conflicts</h2></div></div>
    <p class="lede">These records changed on two devices. Pick a value for each contested field. Other fields are already merged.</p>
    <div class="stack">${cards}</div>
  `;
}

function libraryConflictHtml(row) {
  const remote = row.conflict.remote;
  return `<article class="card conflict">
    <strong>${esc(row.name)}</strong>
    <span class="meta">Library fields differ from ${esc(remote.updated_by_name || "another device")}</span>
    <div class="pair">
      <div class="choice"><small>This device</small>${esc(row.name)} - ${(row.fields || []).map((field) => esc(field.name)).join(", ")}</div>
      <div class="choice"><small>${esc(remote.updated_by_name || "Other")}</small>${esc(remote.name)} - ${(remote.fields || []).map((field) => esc(field.name)).join(", ")}</div>
    </div>
    <div class="actions">
      <button class="btn primary" data-keep-library="mine" data-id="${row.id}" type="button">Keep mine</button>
      <button class="btn ghost" data-keep-library="theirs" data-id="${row.id}" type="button">Keep theirs</button>
    </div>
  </article>`;
}

function entryConflictHtml(row) {
  const library = libraryById(row.library_id);
  const remote = row.conflict.remote;
  const who = remote.updated_by_name || "Other device";
  let body = "";
  if (row.conflict.deleteContested) {
    body += `<div class="pair">
      <button class="choice ${state.picks[row.id + ':deleted'] === "mine" ? "on" : ""}" data-pick="${row.id}:deleted" data-side="mine" type="button"><small>This device</small>${row.deleted ? "Deleted" : "Kept"}</button>
      <button class="choice ${state.picks[row.id + ':deleted'] === "theirs" ? "on" : ""}" data-pick="${row.id}:deleted" data-side="theirs" type="button"><small>${esc(who)}</small>${remote.deleted ? "Deleted" : "Kept"}</button>
    </div>`;
  }
  const contested = new Set(row.conflict.contested || []);
  (row.conflict.contested || []).forEach((fieldId) => {
    const field = library?.fields?.find((item) => item.id === fieldId);
    const mine = displayValue(field, row.values?.[fieldId]);
    const theirs = displayValue(field, remote.values?.[fieldId]);
    const pick = state.picks[`${row.id}:${fieldId}`];
    body += `<div><strong>${esc(fieldName(library, fieldId))}</strong><div class="pair">
      <button class="choice ${pick === "mine" ? "on" : ""}" data-pick="${row.id}:${fieldId}" data-side="mine" type="button"><small>This device</small>${esc(mine)}</button>
      <button class="choice ${pick === "theirs" ? "on" : ""}" data-pick="${row.id}:${fieldId}" data-side="theirs" type="button"><small>${esc(who)}</small>${esc(theirs)}</button>
    </div></div>`;
  });
  const kept = Object.keys(row.conflict.merged || {}).filter((id) => !contested.has(id));
  if (kept.length) {
    body += `<div class="kept">Merged already: ${kept.map((id) => esc(fieldName(library, id))).join(", ")}</div>`;
  }
  return `<article class="card conflict">
    <strong>${esc(entryTitle(library, row))}</strong>
    <span class="meta">${esc(library?.name || "Entry")}</span>
    ${body}
    <button class="btn primary" data-resolve-entry="${row.id}" type="button">Save resolution</button>
  </article>`;
}

function devicesHtml() {
  const current = device().id;
  const list = devices()
    .map((item) => {
      const here = item.id === current ? "This device" : "Switch";
      return `<button class="row" data-use-device="${item.id}" type="button"><span><strong>${esc(item.name)}</strong><span>${here}</span></span></button>`;
    })
    .join("");
  return `
    <div class="screen-head"><div><button class="back" id="back" type="button">Libraries</button><h2>Devices</h2></div></div>
    <p class="lede">Each device has its own copy. Use a second one to see how conflicts work.</p>
    <div class="list">${list}</div>
    <div class="stack" style="margin-top:16px">
      <label class="field">Rename this device<input id="rename-device" value="${esc(device().name)}" /></label>
      <label class="field">New device name<input id="new-device-name" placeholder="Office" /></label>
      <div class="actions"><button id="add-device" class="btn primary" type="button">Add device</button></div>
    </div>
  `;
}

function beginLibraryEdit(library) {
  if (!library) return;
  state.draft = {
    id: library.id,
    name: library.name,
    base: library,
    access: clone(library.access) || {
      create: { mode: "all", users: [] },
      edit: { mode: "all", users: [] },
      erase: { mode: "all", users: [] },
    },
    fields: titleFields(library.fields).map((field) => ({
      id: field.id,
      name: field.name,
      type: field.type,
      title: !!field.title,
      role: field.role || "",
      viewer_edit: !!field.viewer_edit,
      optionsText: (field.options || []).join(", "),
    })),
  };
  go("edit-library");
}

function bindMain() {
  const q = document.getElementById("q");
  if (q) {
    q.addEventListener("input", () => {
      state.query = q.value;
      const library = libraryById(state.libraryId);
      if (library) paintEntries(library);
    });
  }
  document.querySelectorAll("[data-group-field]").forEach((el) => {
    el.addEventListener("change", () => {
      const library = libraryById(state.libraryId);
      if (!library) return;
      const current = selectedGroupFields(library).map((field) => field.id);
      const id = el.dataset.groupField;
      const next = el.checked ? current.concat([id]) : current.filter((item) => item !== id);
      saveGroupFields(library.id, next);
      paintEntries(library);
    });
  });
  byId("back", () => {
    if (state.screen === "entry") {
      saveEntry(false, { leaveIfEmpty: true, skipIfUnchanged: true });
      return;
    }
    if (state.screen === "access") {
      go("library");
      return;
    }
    if (state.screen === "edit-library" && state.libraryId && state.draft?.id) go("library");
    else go("libraries");
  });
  byId("new-library", () => {
    state.draft = {
      name: "",
      access: {
        create: { mode: "all", users: [] },
        edit: { mode: "all", users: [] },
        erase: { mode: "all", users: [] },
      },
      fields: [
        { id: uuid(), name: "Title", type: "text", title: true, optionsText: "", role: "", viewer_edit: false },
        { id: uuid(), name: "Who can see", type: "users", optionsText: "", role: "viewers", viewer_edit: false },
        { id: uuid(), name: "Who can modify", type: "users", optionsText: "", role: "editors", viewer_edit: false },
      ],
    };
    go("edit-library");
  });
  byId("sample", addSample);
  byId("open-conflicts", () => go("conflicts"));
  byId("edit-fields", () => beginLibraryEdit(libraryById(state.libraryId)));
  document.querySelectorAll("[data-edit-library]").forEach((el) => {
    el.onclick = () => beginLibraryEdit(libraryById(el.dataset.editLibrary));
  });
  byId("open-access", () => openAccess());
  byId("new-entry", () => {
    state.draft = {
      isNew: true,
      id: uuid(),
      library_id: state.libraryId,
      values: {},
      deleted: false,
    };
    go("entry");
  });
  byId("add-field", () => {
    readLibraryDraft();
    state.draft.fields.push({ id: uuid(), name: "", type: "text", optionsText: "" });
    renderMain();
  });
  byId("save-library", saveLibrary);
  byId("delete-library", deleteLibrary);
  byId("save-entry", () => saveEntry(false));
  byId("delete-entry", () => saveEntry(true));
  byId("add-device", addDevice);
  const rename = document.getElementById("rename-device");
  if (rename) {
    rename.addEventListener("change", () => {
      const name = rename.value.trim();
      if (!name) return;
      const list = devices();
      const current = device();
      current.name = name;
      saveDevices(list.map((item) => (item.id === current.id ? current : item)));
      renderHeader();
      notice("Device renamed");
    });
  }
  document.querySelectorAll("[data-open-library]").forEach((el) => {
    el.onclick = () => {
      state.libraryId = el.dataset.openLibrary;
      state.query = "";
      go("library");
    };
  });
  document.querySelectorAll("[data-fname]").forEach((el) => {
    el.addEventListener("input", () => {
      state.draft.fields[Number(el.dataset.fname)].name = el.value;
    });
  });
  document.querySelectorAll("[data-ftype]").forEach((el) => {
    el.addEventListener("change", () => {
      const index = Number(el.dataset.ftype);
      if (state.draft.fields[index]?.title) return;
      state.draft.fields[index].type = el.value;
      renderMain();
    });
  });
  document.querySelectorAll("[data-options]").forEach((el) => {
    el.addEventListener("input", () => {
      state.draft.fields[Number(el.dataset.options)].optionsText = el.value;
    });
  });
  document.querySelectorAll("[data-move-field]").forEach((el) => {
    el.onclick = () => moveField(Number(el.dataset.moveField), Number(el.dataset.move));
  });
  document.querySelectorAll("[data-remove-field]").forEach((el) => {
    el.onclick = () => {
      const index = Number(el.dataset.removeField);
      if (state.draft.fields[index]?.title) return;
      readLibraryDraft();
      state.draft.fields.splice(index, 1);
      state.draft.fields = titleFields(state.draft.fields);
      renderMain();
    };
  });
    document.querySelectorAll("[data-field]").forEach((el) => {
    const eventName = el.type === "checkbox" || el.tagName === "SELECT" ? "change" : "input";
    el.addEventListener(eventName, () => {
      const value = el.type === "checkbox" ? el.checked : el.type === "number" && el.value !== "" ? Number(el.value) : el.value;
      state.draft.values[el.dataset.field] = { v: value === "" ? null : value, t: now() };
    });
  });
  document.querySelectorAll("[data-users], [data-multi]").forEach((el) => {
    el.addEventListener("change", () => {
      if (!state.draft) return;
      const fieldId = el.dataset.users || el.dataset.multi;
      state.draft.values = state.draft.values || {};
      state.draft.values[fieldId] = { v: checkedChoice(fieldId, state.draft.values[fieldId]?.v), t: now() };
    });
  });
  document.querySelectorAll("[data-use-device]").forEach((el) => {
    el.onclick = () => switchDevice(el.dataset.useDevice);
  });
  document.querySelectorAll("[data-pick]").forEach((el) => {
    el.onclick = () => {
      state.picks[el.dataset.pick] = el.dataset.side;
      renderMain();
    };
  });
  document.querySelectorAll("[data-keep-library]").forEach((el) => {
    el.onclick = () => resolveLibrary(el.dataset.id, el.dataset.keepLibrary);
  });
  document.querySelectorAll("[data-resolve-entry]").forEach((el) => {
    el.onclick = () => resolveEntry(el.dataset.resolveEntry);
  });
  const libName = document.getElementById("lib-name");
  if (libName) libName.addEventListener("input", () => (state.draft.name = libName.value));
  document.querySelectorAll("[data-role]").forEach((el) => {
    el.addEventListener("change", () => {
      state.draft.fields[Number(el.dataset.role)].role = el.value;
    });
  });
  document.querySelectorAll("[data-viewer-edit]").forEach((el) => {
    el.addEventListener("change", () => {
      state.draft.fields[Number(el.dataset.viewerEdit)].viewer_edit = el.checked;
    });
  });
  document.querySelectorAll("[data-access-mode]").forEach((el) => {
    el.addEventListener("change", () => {
      state.draft.access = state.draft.access || {};
      state.draft.access[el.dataset.accessMode] = state.draft.access[el.dataset.accessMode] || { mode: "none", users: [] };
      state.draft.access[el.dataset.accessMode].mode = el.value;
      renderMain();
    });
  });
  document.querySelectorAll("[data-add-file]").forEach((el) => {
    el.onclick = () => pickFiles(el.dataset.addFile, el.dataset.kind);
  });
  document.querySelectorAll("[data-download]").forEach((el) => {
    el.onclick = () => downloadBlob({ id: el.dataset.download, name: el.dataset.downloadName || "file" });
  });
  document.querySelectorAll("[data-remove-file]").forEach((el) => {
    el.onclick = () => removeFile(el.dataset.removeFile, el.dataset.blob);
  });
  bindAccessControls();
}

function byId(id, fn) {
  const el = document.getElementById(id);
  if (el) el.onclick = fn;
}

function go(screen) {
  state.screen = screen;
  if (screen === "libraries") state.libraryId = state.libraryId;
  render();
}

function readFieldDraft() {
  if (!state.draft?.fields) return;
  document.querySelectorAll("[data-fname]").forEach((el) => {
    const field = state.draft.fields[Number(el.dataset.fname)];
    if (field) field.name = el.value;
  });
  document.querySelectorAll("[data-ftype]").forEach((el) => {
    const field = state.draft.fields[Number(el.dataset.ftype)];
    if (field && !field.title) field.type = el.value;
  });
  document.querySelectorAll("[data-options]").forEach((el) => {
    const field = state.draft.fields[Number(el.dataset.options)];
    if (field) field.optionsText = el.value;
  });
  document.querySelectorAll("[data-role]").forEach((el) => {
    const field = state.draft.fields[Number(el.dataset.role)];
    if (field) field.role = el.value;
  });
  document.querySelectorAll("[data-viewer-edit]").forEach((el) => {
    const field = state.draft.fields[Number(el.dataset.viewerEdit)];
    if (field) field.viewer_edit = el.checked;
  });
}

function moveField(index, direction) {
  readLibraryDraft();
  readFieldDraft();
  const next = index + direction;
  const fields = state.draft.fields;
  if (index <= 0 || next <= 0 || next >= fields.length) return;
  const [item] = fields.splice(index, 1);
  fields.splice(next, 0, item);
  renderMain();
}

function readLibraryDraft() {
  const name = document.getElementById("lib-name");
  if (name) state.draft.name = name.value;
  readFieldDraft();
  if (!state.draft.access) return;
  document.querySelectorAll("[data-access-mode]").forEach((el) => {
    state.draft.access[el.dataset.accessMode] = state.draft.access[el.dataset.accessMode] || { mode: "none", users: [] };
    state.draft.access[el.dataset.accessMode].mode = el.value;
  });
  for (const key of ["create", "edit", "erase"]) {
    const picked = [...document.querySelectorAll(`[data-access-user="${key}"]`)].filter((box) => box.checked).map((box) => box.value);
    if (state.draft.access[key]) state.draft.access[key].users = picked;
  }
}

async function saveLibrary() {
  readLibraryDraft();
  const draft = state.draft;
  const name = draft.name.trim();
  const fields = titleFields(draft.fields
    .map((field) => ({
      id: field.id,
      name: (field.name || "").trim(),
      type: field.type,
      role: field.role || "",
      title: !!field.title,
      viewer_edit: !!field.viewer_edit,
      options: field.type === "choice" || field.type === "multi"
        ? (field.optionsText != null ? field.optionsText : (field.options || []).join(", "))
          .split(",").map((part) => part.trim()).filter(Boolean)
        : undefined,
    }))
    .filter((field) => field.name || field.title));
  if (!name || !fields.length) {
    notice("Add a name and at least one field.", true);
    return;
  }
  fields.forEach((field) => {
    if (!field.options) delete field.options;
    if (field.type !== "users") delete field.role;
    if (!field.viewer_edit) delete field.viewer_edit;
    if (!field.title) delete field.title;
  });
  const existing = draft.id ? await getOne("libraries", draft.id) : null;
  if (!existing && !canCreateLibrary()) {
    notice("You cannot create libraries.", true);
    return;
  }
  if (existing && !can(existing.id, "library", "edit", existing.created_by)) {
    notice("You cannot edit this library.", true);
    return;
  }
  const record = existing || {
    id: uuid(),
    rev: 0,
    base_rev: 0,
    deleted: false,
    created_by: state.session.user.id,
  };
  record.name = name;
  record.fields = fields;
  record.access = draft.access;
  record.updated_at = now();
  record.dirty = true;
  record.conflict = null;
  await putOne("libraries", record);
  state.libraryId = record.id;
  notice(isOnline() ? "Saved. Syncing..." : "Saved on this device.");
  await loadState();
  go("library");
  sync();
}

async function deleteLibrary() {
  const existing = await getOne("libraries", state.draft.id);
  if (!existing) return;
  existing.deleted = true;
  existing.dirty = true;
  existing.updated_at = now();
  existing.conflict = null;
  await putOne("libraries", existing);
  notice("Library deleted on this device.");
  await loadState();
  go("libraries");
  sync();
}

async function openEntry(id) {
  const entry = state.entries.find((item) => item.id === id);
  if (!entry) return;
  if (entry.conflict) {
    go("conflicts");
    return;
  }
  state.entryId = id;
  state.draft = clone(entry);
  state.draft.values = state.draft.values || {};
  state.previews = {};
  const library = libraryById(entry.library_id);
  for (const field of library?.fields || []) {
    if (field.type !== "image" && field.type !== "file") continue;
    for (const meta of fileList(state.draft.values?.[field.id]?.v)) {
      const row = await getOne("blobs", meta.id);
      if (row?.blob) state.previews[meta.id] = URL.createObjectURL(row.blob);
    }
  }
  go("entry");
}

async function saveEntry(deleted, options = {}) {
  const draft = state.draft;
  const fromForm = readEntryFromDom({ ...(draft.values || {}) });
  const existing = await getOne("entries", draft.id);
  const record = existing || {
    id: draft.id,
    library_id: state.libraryId,
    rev: 0,
    base_rev: 0,
    ancestor: {},
    deleted: false,
    created_by: state.session.user.id,
  };
  if (deleted && !canEraseEntry(libraryById(state.libraryId), record)) {
    notice("You cannot erase this entry.", true);
    return;
  }
  if (!existing && !deleted && !canCreateEntry(libraryById(state.libraryId))) {
    notice("You cannot create entries here.", true);
    return;
  }
  if (deleted && draft.isNew) {
    go("library");
    return;
  }
  const typed = { ...(record.values || {}), ...fromForm };
  const empty = !Object.values(typed).some((cell) => cellValue(cell) !== null);
  if (!deleted && options.skipIfUnchanged && existing && !entryChanged(existing.values, typed)) {
    go("library");
    return;
  }
  if (deleted) {
    record.deleted = true;
  } else if (draft.isNew && empty) {
    if (options.leaveIfEmpty) {
      go("library");
      return;
    }
    notice("Enter something before saving.", true);
    return;
  } else {
    record.values = typed;
    record.deleted = false;
  }
  record.updated_at = now();
  record.dirty = true;
  record.conflict = null;
  await putOne("entries", record);
  notice(isOnline() ? "Saved. Syncing..." : "Saved on this device.");
  await loadState();
  go("library");
  sync();
}

function entryChanged(before, after) {
  const ids = new Set([...Object.keys(before || {}), ...Object.keys(after || {})]);
  for (const id of ids) {
    if (!sameVal(before?.[id], after?.[id])) return true;
  }
  return false;
}

function choiceBoxes(fieldId) {
  return [...document.querySelectorAll("[data-users], [data-multi]")].filter((box) => (box.dataset.users || box.dataset.multi) === fieldId);
}

function checkedChoice(fieldId, previousValue) {
  const boxes = choiceBoxes(fieldId);
  const shown = new Set(boxes.map((box) => box.value));
  const labels = new Set(boxes.map((box) => (box.parentElement?.textContent || "").trim()));
  const checked = boxes.filter((box) => box.checked).map((box) => box.value);
  const kept = selectedList(previousValue).filter((id) => !shown.has(id) && !labels.has(id));
  kept.forEach((id) => {
    if (!checked.includes(id)) checked.push(id);
  });
  return checked;
}

function readEntryFromDom(fallback) {
  const values = clone(fallback) || {};
  const seen = new Set();
  document.querySelectorAll("[data-users], [data-multi]").forEach((el) => {
    const fieldId = el.dataset.users || el.dataset.multi;
    if (seen.has(fieldId) || el.disabled) return;
    seen.add(fieldId);
    const ids = checkedChoice(fieldId, cellValue(values[fieldId]));
    const previous = values[fieldId];
    if (!sameVal(previous, { v: ids })) values[fieldId] = { v: ids, t: now() };
  });
  document.querySelectorAll("[data-field]").forEach((el) => {
    const value = el.type === "checkbox" ? el.checked : el.value;
    const normalized = value === "" ? null : el.type === "number" && value !== "" ? Number(value) : value;
    const previous = values[el.dataset.field];
    if (el.disabled) return;
    if (el.type === "checkbox" && normalized === false && cellValue(previous) === null) return;
    if (!sameVal(previous, { v: normalized })) {
      values[el.dataset.field] = { v: normalized, t: now() };
    }
  });
  return values;
}

async function addSample() {
  if (!canCreateLibrary()) {
    notice("You cannot create libraries.", true);
    return;
  }
  const libraryId = uuid();
  const fields = [
    { id: uuid(), name: "Title", type: "text", title: true },
    { id: uuid(), name: "Visited", type: "date" },
    { id: uuid(), name: "Status", type: "choice", options: ["Open", "Done", "Blocked"] },
    { id: uuid(), name: "Headcount", type: "number" },
    { id: uuid(), name: "Notes", type: "longtext" },
  ];
  await putOne("libraries", {
    id: libraryId,
    name: "Site visits",
    fields,
    rev: 0,
    base_rev: 0,
    updated_at: now(),
    deleted: false,
    dirty: true,
    conflict: null,
    created_by: state.session.user.id,
  });
  const values = {};
  values[fields[0].id] = { v: "Pier", t: now() };
  values[fields[1].id] = { v: "2026-09-28", t: now() };
  values[fields[2].id] = { v: "Open", t: now() };
  values[fields[3].id] = { v: 4, t: now() };
  values[fields[4].id] = { v: "Tide was low.", t: now() };
  await putOne("entries", {
    id: uuid(),
    library_id: libraryId,
    values,
    ancestor: {},
    rev: 0,
    base_rev: 0,
    updated_at: now(),
    deleted: false,
    dirty: true,
    conflict: null,
    created_by: state.session.user.id,
  });
  await loadState();
  notice("Sample library saved on this device.");
  render();
  sync();
}

async function addDevice() {
  const input = document.getElementById("new-device-name");
  const name = (input?.value || "").trim();
  if (!name) {
    notice("Name the new device.", true);
    return;
  }
  const list = devices();
  const created = { id: uuid(), name };
  list.push(created);
  saveDevices(list);
  await switchDevice(created.id);
}

async function switchDevice(id) {
  if (id === device().id && state.screen === "devices") {
    notice("Already on this device.");
    return;
  }
  storeSet("cafinewo.active", id);
  await resetDb();
  state.libraryId = null;
  state.query = "";
  state.picks = {};
  await loadState();
  notice(`Now using ${device().name}`);
  go("libraries");
  sync();
}

function slimLibrary(row) {
  return {
    id: row.id,
    name: row.name,
    fields: row.fields,
    base_rev: row.base_rev || 0,
    updated_at: row.updated_at,
    deleted: !!row.deleted,
    created_by: row.created_by || "",
    access: row.access,
  };
}

function slimEntry(row) {
  return {
    id: row.id,
    library_id: row.library_id,
    values: row.values || {},
    base_rev: row.base_rev || 0,
    updated_at: row.updated_at,
    deleted: !!row.deleted,
    created_by: row.created_by || "",
  };
}

async function sync() {
  if (!isOnline()) {
    notice("Offline. Changes stay on this device.");
    renderHeader();
    return;
  }
  if (syncing) {
    syncQueued = true;
    return;
  }
  syncing = true;
  state.syncing = true;
  renderHeader();
  try {
    let again = true;
    let rounds = 0;
    while (again && rounds < 4) {
      rounds += 1;
      again = await syncOnce();
    }
  } catch (error) {
    if (error.message !== "signed out") notice("No connection. Changes stay on this device.", true);
  } finally {
    syncing = false;
    state.syncing = false;
    await loadState();
    if (state.screen !== "entry" && state.screen !== "edit-library" && state.screen !== "people" && state.screen !== "account" && state.screen !== "access") render();
    else renderHeader();
    if (syncQueued) {
      syncQueued = false;
      sync();
    }
  }
}

function pickFiles(fieldId, kind) {
  if (!fieldId || !state.draft) return;
  const input = document.createElement("input");
  input.type = "file";
  input.multiple = true;
  input.dataset.file = fieldId;
  if (kind === "image") input.accept = "image/*";
  input.onchange = () => rememberFile(input);
  input.click();
}

const fileWrites = new Map();

async function rememberFile(input) {
  const files = [...(input.files || [])];
  if (!files.length || !state.draft) return;
  const fieldId = input.dataset.file;
  const previous = fileWrites.get(fieldId) || Promise.resolve();
  const run = previous.catch(() => {}).then(async () => {
    if (!state.draft) return;
    state.draft.values = state.draft.values || {};
    const added = [];
    for (const file of files) {
      const id = uuid();
      await putOne("blobs", {
        id,
        name: file.name,
        mime: file.type || "application/octet-stream",
        blob: file,
        dirty: true,
        entry_id: state.draft.id,
        field_id: fieldId,
      });
      state.previews[id] = URL.createObjectURL(file);
      added.push({ id, name: file.name, mime: file.type, size: file.size });
    }
    const kept = fileList(state.draft.values[fieldId]?.v);
    const seen = new Set(kept.map((item) => item.id));
    state.draft.values[fieldId] = { v: kept.concat(added.filter((item) => !seen.has(item.id))), t: now() };
    if (state.screen === "entry") renderMain();
  });
  fileWrites.set(fieldId, run);
  await run;
}

function removeFile(fieldId, blobId) {
  if (!state.draft || !fieldId || !blobId) return;
  state.draft.values = state.draft.values || {};
  const kept = fileList(state.draft.values[fieldId]?.v).filter((item) => item.id !== blobId);
  state.draft.values[fieldId] = { v: kept, t: now() };
  renderMain();
}

async function uploadBlobs() {
  const rows = await getAll("blobs");
  for (const row of rows.filter((item) => item.dirty)) {
    const body = new FormData();
    body.append("id", row.id);
    body.append("name", row.name || "file");
    body.append("entry_id", row.entry_id || "");
    body.append("field_id", row.field_id || "");
    body.append("file", row.blob, row.name || "file");
    const response = await fetch("/api/blobs", {
      method: "POST",
      headers: { Authorization: "Bearer " + (state.session?.token || "") },
      body,
    });
    if (!response.ok) throw new Error("Could not upload a file");
    row.dirty = false;
    await putOne("blobs", row);
  }
}

async function downloadBlob(meta) {
  if (!meta?.id) return;
  let row = await getOne("blobs", meta.id);
  if (!row?.blob) {
    if (!isOnline()) {
      notice("That file is not on this device yet. Sync while online.", true);
      return;
    }
    const response = await fetch("/api/blobs/" + encodeURIComponent(meta.id), {
      headers: { Authorization: "Bearer " + (state.session?.token || "") },
    });
    if (!response.ok) {
      notice("Could not download that file.", true);
      return;
    }
    const blob = await response.blob();
    row = { id: meta.id, name: meta.name || "file", mime: blob.type || "application/octet-stream", blob, dirty: false };
    await putOne("blobs", row);
  }
  const url = URL.createObjectURL(row.blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = row.name || meta.name || "file";
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

async function downloadMissingBlobs() {
  const wanted = [];
  for (const entry of state.entries) {
    const library = libraryById(entry.library_id);
    for (const field of library?.fields || []) {
      if (field.type !== "image" && field.type !== "file") continue;
      wanted.push(...fileList(entry.values?.[field.id]?.v));
    }
  }
  for (const meta of wanted) {
    if (await getOne("blobs", meta.id)) continue;
    const response = await fetch("/api/blobs/" + encodeURIComponent(meta.id), {
      headers: { Authorization: "Bearer " + (state.session?.token || "") },
    });
    if (!response.ok) continue;
    const blob = await response.blob();
    await putOne("blobs", { id: meta.id, name: meta.name || "file", mime: blob.type, blob, dirty: false });
  }
}

async function syncOnce() {
  await uploadBlobs();
  const libraries = (await getAll("libraries")).filter((row) => row.dirty && !row.conflict);
  const entries = (await getAll("entries")).filter((row) => row.dirty && !row.conflict);
  const cursor = (await getOne("meta", "cursor")) || 0;
  const response = await fetch("/api/sync", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + (state.session?.token || ""),
    },
    body: JSON.stringify({
      device_id: device().id,
      device_name: device().name,
      cursor,
      libraries: libraries.map(slimLibrary),
      entries: entries.map(slimEntry),
    }),
  });
  if (response.status === 401) {
    await signOut(false);
    throw new Error("signed out");
  }
  if (!response.ok) throw new Error("sync failed");
  const data = await response.json();
  if (data.access) {
    state.access = data.access;
    saveSession();
  }
  const accepted = new Set((data.accepted || []).map((item) => `${item.kind}:${item.id}`));
  for (const item of data.accepted || []) await markAccepted(item);
  for (const item of data.forbidden || []) await markForbidden(item);
  let merged = false;
  let fresh = false;
  for (const conflict of data.conflicts || []) {
    if (await handleConflict(conflict.kind, conflict.id, conflict.server)) merged = true;
  }
  for (const change of data.changes || []) {
    if (accepted.has(`${change.kind}:${change.id}`)) continue;
    const store = change.kind === "library" ? "libraries" : "entries";
    const before = await getOne(store, change.id);
    const unchanged = before && !before.dirty && !before.conflict && before.rev === change.rev && !!before.deleted === !!change.deleted;
    if (await applyRemote(change)) merged = true;
    if (!unchanged) fresh = true;
  }
  for (const item of data.hidden || []) {
    if (!accepted.has(`${item.kind}:${item.id}`)) await hideRemote(item);
  }
  await putOne("meta", data.cursor, "cursor");
  if ((data.forbidden || []).length) notice(data.forbidden[0].error, true);
  else if ((data.accepted || []).length || fresh || (data.conflicts || []).length) {
    const left = (await getAll("entries")).filter((row) => row.conflict).length
      + (await getAll("libraries")).filter((row) => row.conflict).length;
    if (left) notice(`${left} conflict${left === 1 ? "" : "s"} to resolve`, true);
    else if ((data.accepted || []).length) notice("Synced");
    else notice("Caught up");
  }
  await loadState();
  await downloadMissingBlobs();
  return merged;
}

async function markAccepted(item) {
  const store = item.kind === "library" ? "libraries" : "entries";
  const row = await getOne(store, item.id);
  if (!row) return;
  row.rev = item.rev;
  row.base_rev = item.rev;
  row.dirty = false;
  row.conflict = null;
  row.forbidden = "";
  if (item.kind === "entry") row.ancestor = clone(row.values || {});
  await putOne(store, row);
}

async function markForbidden(item) {
  const store = item.kind === "library" ? "libraries" : "entries";
  const row = await getOne(store, item.id);
  if (!row) return;
  row.dirty = false;
  row.forbidden = item.error || "Not allowed";
  await putOne(store, row);
}

async function hideRemote(item) {
  const store = item.kind === "library" ? "libraries" : "entries";
  const row = await getOne(store, item.id);
  if (!row || (row.dirty && !(row.base_rev || 0))) return;
  row.deleted = true;
  row.dirty = false;
  row.conflict = null;
  await putOne(store, row);
}

async function handleConflict(kind, id, remote) {
  if (kind === "library") {
    const local = await getOne("libraries", id);
    if (!local) return false;
    local.conflict = { remote };
    await putOne("libraries", local);
    return false;
  }
  const local = await getOne("entries", id);
  if (!local) {
    await putOne("entries", fromRemoteEntry(remote));
    return false;
  }
  const merged = mergeEntry(local, remote);
  if (!merged.contested.length && !merged.deleteContested) {
    local.values = merged.merged;
    local.deleted = merged.deleted;
    local.ancestor = clone(remote.values || {});
    local.base_rev = remote.rev;
    local.rev = remote.rev;
    local.dirty = true;
    local.conflict = null;
    local.updated_at = now();
    await putOne("entries", local);
    return true;
  }
  local.conflict = {
    remote,
    contested: merged.contested,
    deleteContested: merged.deleteContested,
    merged: merged.merged,
  };
  await putOne("entries", local);
  return false;
}

async function applyRemote(change) {
  const store = change.kind === "library" ? "libraries" : "entries";
  const local = await getOne(store, change.id);
  if (local && !local.dirty && !local.conflict && local.rev === change.rev && !!local.deleted === !!change.deleted) {
    return false;
  }
  if (!local) {
    await putOne(store, change.kind === "library" ? fromRemoteLibrary(change) : fromRemoteEntry(change));
    return false;
  }
  if (local.dirty || local.conflict) {
    if ((local.base_rev || 0) !== change.rev) return handleConflict(change.kind, change.id, change);
    return false;
  }
  await putOne(store, change.kind === "library" ? fromRemoteLibrary(change) : fromRemoteEntry(change));
  return false;
}

function fromRemoteLibrary(remote) {
  return {
    id: remote.id,
    name: remote.name,
    fields: remote.fields || [],
    rev: remote.rev,
    base_rev: remote.rev,
    updated_at: remote.updated_at,
    deleted: !!remote.deleted,
    dirty: false,
    conflict: null,
    created_by: remote.created_by || "",
    access: remote.access,
  };
}

function fromRemoteEntry(remote) {
  return {
    id: remote.id,
    library_id: remote.library_id,
    values: remote.values || {},
    ancestor: clone(remote.values || {}),
    rev: remote.rev,
    base_rev: remote.rev,
    updated_at: remote.updated_at,
    deleted: !!remote.deleted,
    dirty: false,
    conflict: null,
    updated_by_name: remote.updated_by_name || "",
    created_by: remote.created_by || "",
  };
}

async function resolveLibrary(id, side) {
  const local = await getOne("libraries", id);
  if (!local?.conflict) return;
  const remote = local.conflict.remote;
  if (side === "theirs") {
    const next = fromRemoteLibrary(remote);
    await putOne("libraries", next);
  } else {
    local.base_rev = remote.rev;
    local.rev = remote.rev;
    local.dirty = true;
    local.conflict = null;
    local.updated_at = now();
    await putOne("libraries", local);
  }
  await loadState();
  notice("Conflict resolved");
  render();
  sync();
}

async function resolveEntry(id) {
  const local = await getOne("entries", id);
  if (!local?.conflict) return;
  const remote = local.conflict.remote;
  const needed = [...(local.conflict.contested || [])];
  if (local.conflict.deleteContested) needed.push("deleted");
  if (needed.some((fieldId) => !state.picks[`${id}:${fieldId}`])) {
    notice("Choose a value for each contested field.", true);
    return;
  }
  if (local.conflict.deleteContested && state.picks[`${id}:deleted`] === "theirs" && needed.length === 1) {
    await putOne("entries", fromRemoteEntry(remote));
  } else {
    const values = clone(local.conflict.merged || {});
    (local.conflict.contested || []).forEach((fieldId) => {
      const side = state.picks[`${id}:${fieldId}`];
      values[fieldId] = side === "theirs" ? remote.values?.[fieldId] : local.values?.[fieldId];
      delete state.picks[`${id}:${fieldId}`];
    });
    let deleted = local.deleted;
    if (local.conflict.deleteContested) {
      deleted = state.picks[`${id}:deleted`] === "mine" ? !!local.deleted : !!remote.deleted;
      delete state.picks[`${id}:deleted`];
    }
    local.values = values;
    local.deleted = deleted;
    local.ancestor = clone(remote.values || {});
    local.base_rev = remote.rev;
    local.rev = remote.rev;
    local.dirty = true;
    local.conflict = null;
    local.updated_at = now();
    await putOne("entries", local);
  }
  await loadState();
  notice("Conflict resolved");
  go("libraries");
  sync();
}

async function start() {
  state.session = loadSession();
  try {
    const health = await fetch("/api/health").then((response) => response.json());
    state.needsSetup = !!health.needs_setup;
  } catch (error) {
    state.needsSetup = false;
  }
  if (!state.session) {
    renderAuth();
    storageNotice();
    return;
  }
  try {
    const me = await api("/api/me");
    state.session.user = me.user;
    state.access = me.access;
    saveSession();
  } catch (error) {
    if (error.message === "signed out") return;
    const cached = stored("cafinewo.access." + state.session.user.id);
    state.access = cached ? JSON.parse(cached) : { user_id: state.session.user.id, is_admin: !!state.session.user.is_admin, grants: [] };
  }
  try {
    await bootApp();
  } catch (error) {
    if (storageBlocked || error?.name === "SecurityError") {
      storageBlocked = true;
    } else {
      notice(error.message || "Could not open this device's saved data.", true, true);
    }
  }
  storageNotice();
}

function renderAuth() {
  document.getElementById("top").innerHTML = `
    <div>
      <h1 class="brand">Cafineuos</h1>
      <div class="device-line">${state.needsSetup ? "Create the first admin" : "Sign in"}</div>
    </div>
  `;
  document.getElementById("main").innerHTML = `
    <div class="screen-head"><h2>${state.needsSetup ? "First account" : "Sign in"}</h2></div>
    <p class="lede">${state.needsSetup ? "This account can add people, groups, and decide who can see or change each library." : "Use the name and password an admin gave you."}</p>
    <div class="stack">
      <label class="field">Name<input id="auth-name" autocomplete="username" /></label>
      <label class="field">Password<input id="auth-password" type="password" autocomplete="${state.needsSetup ? "new-password" : "current-password"}" /></label>
      <button id="auth-submit" class="btn primary" type="button">${state.needsSetup ? "Create admin" : "Sign in"}</button>
    </div>
  `;
  byId("auth-submit", submitAuth);
}

async function submitAuth() {
  const name = document.getElementById("auth-name").value.trim();
  const password = document.getElementById("auth-password").value;
  try {
    const data = await api(state.needsSetup ? "/api/setup" : "/api/login", { name, password });
    state.session = { token: data.token, user: data.user };
    state.access = data.access;
    state.needsSetup = false;
    saveSession();
    await resetDb();
    await bootApp();
  } catch (error) {
    if (error.message !== "signed out") notice(error.message, true);
  }
}

async function bootApp() {
  await loadState();
  render();
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  }
  if (!bootApp.bound) {
    bootApp.bound = true;
    window.addEventListener("online", () => {
      renderHeader();
      sync();
    });
    window.addEventListener("offline", () => renderHeader());
    document.getElementById("main").addEventListener("click", (event) => {
      const entryBtn = event.target.closest("[data-open-entry]");
      if (entryBtn) openEntry(entryBtn.dataset.openEntry);
    });
  }
  sync();
}

async function openPeople() {
  try {
    state.directory = await api("/api/directory");
    state.backup = await api("/api/backup");
    go("people");
  } catch (error) {
    if (error.message !== "signed out") notice(error.message, true);
  }
}

async function openAccess() {
  try {
    state.directory = await api("/api/directory");
    const data = await api("/api/grants?library_id=" + encodeURIComponent(state.libraryId));
    state.permRows = data.grants || [];
    go("access");
  } catch (error) {
    if (error.message !== "signed out") notice(error.message, true);
  }
}

function peopleHtml() {
  const dir = state.directory;
  if (!dir) return `<p class="lede">Loading people...</p>`;
  const users = dir.users
    .map((user) => `
      <article class="card conflict">
        <label class="field">Name<input data-name="${user.id}" value="${esc(user.name)}" /></label>
        <label class="field check"><input type="checkbox" data-admin="${user.id}" ${user.is_admin ? "checked" : ""} /> Admin</label>
        <label class="field">New password<input data-password="${user.id}" type="password" placeholder="Leave blank to keep" /></label>
        ${dir.groups.length ? `<span class="meta">Groups</span>${dir.groups.map((group) => `<label class="field check"><input data-user-group="${user.id}" value="${esc(group.id)}" type="checkbox" ${(user.group_ids || []).includes(group.id) ? "checked" : ""} /> ${esc(group.name)}</label>`).join("")}` : ""}
        <div class="actions">
          <button class="btn ghost" data-save-user="${user.id}" type="button">Save</button>
          <button class="btn danger" data-remove-user="${user.id}" type="button">Remove</button>
        </div>
      </article>`)
    .join("");
  const groups = dir.groups
    .map((group) => `
      <article class="card conflict">
        <label class="field">Name<input data-group-name="${group.id}" value="${esc(group.name)}" /></label>
        ${dir.users
          .map(
            (user) =>
              `<label class="field check"><input type="checkbox" data-member="${group.id}" value="${user.id}" ${group.user_ids.includes(user.id) ? "checked" : ""} /> ${esc(user.name)}</label>`
          )
          .join("")}
        <div class="actions">
          <button class="btn ghost" data-save-group="${group.id}" type="button">Save</button>
          <button class="btn danger" data-remove-group="${group.id}" type="button">Remove</button>
        </div>
      </article>`)
    .join("");
  const creatorBoxes = dir.users
    .map(
      (user) =>
        `<label class="field check"><input type="checkbox" data-creator="user" value="${user.id}" ${isCreator("user", user.id) ? "checked" : ""} /> ${esc(user.name)}</label>`
    )
    .join("");
  const groupBoxes = dir.groups
    .map(
      (group) =>
        `<label class="field check"><input type="checkbox" data-creator="group" value="${group.id}" ${isCreator("group", group.id) ? "checked" : ""} /> ${esc(group.name)}</label>`
    )
    .join("");
  return `
    <div class="screen-head"><div><button class="back" id="back" type="button">Libraries</button><h2>People</h2></div></div>
    <p class="lede">Change a name, which groups a person belongs to, or who is in a group. Admins can see and change everything.</p>
    <h2>Add a user</h2>
    <div class="stack">
      <label class="field">Name<input id="new-user-name" /></label>
      <label class="field">Password<input id="new-user-password" type="password" /></label>
      <label class="field check"><input id="new-user-admin" type="checkbox" /> Admin</label>
      <button id="add-user" class="btn primary" type="button">Add user</button>
    </div>
    <h2>Users</h2>
    <div class="stack">${users || '<p class="lede">No other accounts yet.</p>'}</div>
    <h2>Add a group</h2>
    <div class="stack">
      <label class="field">Name<input id="new-group-name" /></label>
      <button id="add-group" class="btn primary" type="button">Add group</button>
    </div>
    <div class="stack">${groups}</div>
    <h2>Who can create libraries</h2>
    <p class="lede">Admins always can. Tick anyone else who should be able to add a library. They get full access to libraries they create.</p>
    <div class="stack">${creatorBoxes}${groupBoxes}</div>
    <button id="save-creators" class="btn primary" type="button">Save</button>
    <h2>Backup</h2>
    <p class="lede">The server keeps a copy of the database and files. Pick a time interval or a number of syncs.</p>
    <div class="stack">
      <label class="field">When<select id="backup-mode">
        <option value="off" ${state.backup?.mode === "off" ? "selected" : ""}>Off</option>
        <option value="hours" ${state.backup?.mode === "hours" ? "selected" : ""}>Every number of hours</option>
        <option value="accesses" ${state.backup?.mode === "accesses" ? "selected" : ""}>Every number of syncs</option>
      </select></label>
      <label class="field">Every<input id="backup-every" type="number" min="1" value="${esc(state.backup?.every || 24)}" /></label>
      <button id="save-backup" class="btn primary" type="button">Save backup</button>
    </div>
  `;
}

function accountHtml() {
  const user = state.session?.user || {};
  return `
    <div class="screen-head"><div><button class="back" id="back" type="button">Libraries</button><h2>Account</h2></div></div>
    <p class="lede">Change the name you sign in with, or set a new password. Leave the password blank to keep the current one.</p>
    <div class="stack">
      <label class="field">Name<input id="account-name" value="${esc(user.name || "")}" /></label>
      <label class="field">New password<input id="account-password" type="password" placeholder="Leave blank to keep" /></label>
      <button id="save-account" class="btn primary" type="button">Save</button>
    </div>
  `;
}

function isCreator(type, id) {
  return (state.directory?.creators || []).some((item) => item.subject_type === type && item.subject_id === id);
}

function accessHtml() {
  const library = libraryById(state.libraryId);
  const dir = state.directory;
  if (!library || !dir) return `<p class="lede">Loading access...</p>`;
  const subjects = [
    ...dir.users.filter((user) => !user.is_admin).map((user) => ({ type: "user", id: user.id, name: user.name })),
    ...dir.groups.map((group) => ({ type: "group", id: group.id, name: group.name })),
  ];
  const cards = subjects
    .map((subject) => {
      const libraryGrant = findGrant(subject, "library", "");
      const entryGrant = findGrant(subject, "entry", "");
      const fields = (library.fields || [])
        .map((field) => {
          const grant = findGrant(subject, "field", field.id);
          return `<p class="kept">${esc(field.name)}</p>${permRow("See", subject, "field", field.id, "see", grant, true)}${permRow("Edit", subject, "field", field.id, "edit", grant, true)}`;
        })
        .join("");
      return `<article class="card conflict">
        <strong>${esc(subject.name)}${subject.type === "group" ? " (group)" : ""}</strong>
        <p class="kept">Own means only records that person created. For a group, each member sees the records they created.</p>
        <h3>Library</h3>
        ${permRow("See", subject, "library", "", "see", libraryGrant)}
        ${permRow("Edit", subject, "library", "", "edit", libraryGrant)}
        ${permRow("Erase", subject, "library", "", "erase", libraryGrant)}
        <h3>Entries</h3>
        ${permRow("See", subject, "entry", "", "see", entryGrant)}
        ${permRow("Edit", subject, "entry", "", "edit", entryGrant)}
        ${permRow("Create", subject, "entry", "", "create", entryGrant)}
        ${permRow("Erase", subject, "entry", "", "erase", entryGrant)}
        <h3>Fields</h3>
        ${fields}
      </article>`;
    })
    .join("");
  return `
    <div class="screen-head"><div><button class="back" id="back" type="button">Back</button><h2>Access</h2></div></div>
    <p class="lede">${esc(library.name)}. Leave a field on "Same as entries" unless that field should be hidden or locked.</p>
    <div class="stack">${cards || '<p class="lede">Add a user or group first.</p>'}</div>
    <button id="save-access" class="btn primary" type="button">Save access</button>
  `;
}

function permRow(label, subject, target, fieldId, action, grant, inherit) {
  return `<label class="perm-row"><span>${label}</span>${permSelect(subject, target, fieldId, action, grant, inherit)}</label>`;
}

function findGrant(subject, target, fieldId) {
  return state.permRows.find(
    (grant) =>
      grant.subject_type === subject.type &&
      grant.subject_id === subject.id &&
      grant.target === target &&
      (grant.field_id || "") === fieldId
  );
}

function permSelect(subject, target, fieldId, action, grant, inherit) {
  const current = grant ? grant[action] || "none" : inherit ? "inherit" : "none";
  const options = inherit
    ? [["inherit", "Same as entries"], ["none", "None"], ["own", "Own"], ["all", "All"]]
    : action === "create"
      ? [["none", "No"], ["all", "Yes"]]
      : [["none", "None"], ["own", "Own"], ["all", "All"]];
  return `<select data-perm="${subject.type}:${subject.id}:${target}:${fieldId}:${action}">${options
    .map(([value, label]) => `<option value="${value}" ${value === current ? "selected" : ""}>${label}</option>`)
    .join("")}</select>`;
}

function bindAccessControls() {
  byId("add-user", addUser);
  byId("add-group", addGroup);
  byId("save-creators", saveCreators);
  byId("save-backup", saveBackup);
  byId("save-access", saveAccess);
  byId("save-account", saveAccount);
  document.querySelectorAll("[data-save-user]").forEach((button) => {
    button.onclick = () => saveUser(button.dataset.saveUser);
  });
  document.querySelectorAll("[data-remove-user]").forEach((button) => {
    button.onclick = () => removeUser(button.dataset.removeUser);
  });
  document.querySelectorAll("[data-save-group]").forEach((button) => {
    button.onclick = () => saveGroup(button.dataset.saveGroup);
  });
  document.querySelectorAll("[data-remove-group]").forEach((button) => {
    button.onclick = () => removeGroup(button.dataset.removeGroup);
  });
}

async function addUser() {
  try {
    await api("/api/users", {
      name: document.getElementById("new-user-name").value,
      password: document.getElementById("new-user-password").value,
      is_admin: document.getElementById("new-user-admin").checked,
    });
    notice("User added");
    await openPeople();
  } catch (error) {
    if (error.message !== "signed out") notice(error.message, true);
  }
}

async function saveUser(id) {
  const password = document.querySelector(`[data-password="${id}"]`).value;
  const isAdmin = document.querySelector(`[data-admin="${id}"]`).checked;
  const name = document.querySelector(`[data-name="${id}"]`).value;
  const groupIds = [...document.querySelectorAll(`[data-user-group="${id}"]`)].filter((box) => box.checked).map((box) => box.value);
  try {
    await api("/api/users/update", { id, name, password, is_admin: isAdmin, group_ids: groupIds });
    if (state.session?.user?.id === id) {
      state.session.user.name = name.trim();
      saveSession();
    }
    notice("User saved");
    await openPeople();
  } catch (error) {
    if (error.message !== "signed out") notice(error.message, true);
  }
}

async function removeUser(id) {
  const name = document.querySelector(`[data-name="${id}"]`)?.value || "this user";
  if (!window.confirm(`Remove ${name}? They will no longer be able to sign in.`)) return;
  try {
    await api("/api/users/remove", { id });
    notice("User removed");
    await openPeople();
  } catch (error) {
    if (error.message !== "signed out") notice(error.message, true);
  }
}

async function saveAccount() {
  const name = document.getElementById("account-name").value;
  const password = document.getElementById("account-password").value;
  try {
    const data = await api("/api/account", { name, password });
    state.session.user = data.user;
    saveSession();
    notice("Account saved");
    renderHeader();
  } catch (error) {
    if (error.message !== "signed out") notice(error.message, true);
  }
}

async function addGroup() {
  try {
    await api("/api/groups", { name: document.getElementById("new-group-name").value });
    notice("Group added");
    await openPeople();
  } catch (error) {
    if (error.message !== "signed out") notice(error.message, true);
  }
}

async function saveGroup(groupId) {
  const userIds = [...document.querySelectorAll(`[data-member="${groupId}"]`)]
    .filter((box) => box.checked)
    .map((box) => box.value);
  const name = document.querySelector(`[data-group-name="${groupId}"]`).value;
  try {
    await api("/api/groups/members", { group_id: groupId, name, user_ids: userIds });
    notice("Group saved");
    await openPeople();
  } catch (error) {
    if (error.message !== "signed out") notice(error.message, true);
  }
}

async function removeGroup(groupId) {
  const name = document.querySelector(`[data-group-name="${groupId}"]`)?.value || "this group";
  if (!confirm(`Remove ${name}?`)) return;
  try {
    await api("/api/groups/remove", { group_id: groupId });
    notice("Group removed");
    await openPeople();
  } catch (error) {
    if (error.message !== "signed out") notice(error.message, true);
  }
}

async function saveBackup() {
  try {
    state.backup = await api("/api/backup", {
      mode: document.getElementById("backup-mode").value,
      every: Number(document.getElementById("backup-every").value || 1),
    });
    notice("Backup saved");
  } catch (error) {
    if (error.message !== "signed out") notice(error.message, true);
  }
}

async function saveCreators() {
  const subjects = [...document.querySelectorAll("[data-creator]")].filter((box) => box.checked).map((box) => ({
    subject_type: box.dataset.creator,
    subject_id: box.value,
  }));
  try {
    await api("/api/creators", { subjects });
    notice("Saved");
    await openPeople();
  } catch (error) {
    if (error.message !== "signed out") notice(error.message, true);
  }
}

async function saveAccess() {
  const grouped = new Map();
  document.querySelectorAll("[data-perm]").forEach((select) => {
    const [subjectType, subjectId, target, fieldId, action] = select.dataset.perm.split(":");
    const key = `${subjectType}:${subjectId}:${target}:${fieldId}`;
    if (!grouped.has(key)) {
      grouped.set(key, {
        subject_type: subjectType,
        subject_id: subjectId,
        target,
        field_id: fieldId,
        see: "none",
        edit: "none",
        create: "none",
        erase: "none",
      });
    }
    grouped.get(key)[action] = select.value;
  });
  const grants = [];
  for (const row of grouped.values()) {
    if (row.target === "field") {
      const entry = grouped.get(`${row.subject_type}:${row.subject_id}:entry:`);
      if (row.see === "inherit") row.see = entry?.see || "none";
      if (row.edit === "inherit") row.edit = entry?.edit || "none";
      if (row.see === (entry?.see || "none") && row.edit === (entry?.edit || "none")) continue;
    }
    grants.push(row);
  }
  try {
    await api("/api/grants", { library_id: state.libraryId, grants });
    notice("Access saved");
    await openAccess();
  } catch (error) {
    if (error.message !== "signed out") notice(error.message, true);
  }
}

start();
