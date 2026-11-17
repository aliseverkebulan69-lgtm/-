// ================= Тұрақтылар =================
const MAGIC = [0x4B, 0x56, 0x4C, 0x54];   // "KVLT" — файл белгісі
const VERSION = 1;
const SALT_LEN = 16;
const NONCE_LEN = 12;                      // AES-GCM үшін 96 бит
const ITERATIONS = 200000;                 // PBKDF2 итерациясы
const HEADER_LEN = 4 + 1 + 4 + SALT_LEN + NONCE_LEN;  // 37 байт

const enc = new TextEncoder();
const dec = new TextDecoder();

// ================= Күй =================
let vault = null;   // { key, salt, iter, records:[], nextId }
let dirty = false;
let editId = null;

// ================= Криптография =================
// Master-парольден кілт алу (PBKDF2 + salt)
async function deriveKey(password, salt, iter) {
  const base = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt, iterations: iter, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]);
}

function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

// Тақырыпты (header) жасау: magic + нұсқа + итерация + salt + nonce
function buildHeader(iter, salt, nonce) {
  const h = new Uint8Array(HEADER_LEN);
  h.set(MAGIC, 0);
  h[4] = VERSION;
  new DataView(h.buffer).setUint32(5, iter);
  h.set(salt, 9);
  h.set(nonce, 9 + SALT_LEN);
  return h;
}

// Жазбаларды шифрлап, файл байттарын жасау
async function encryptVault(v) {
  const nonce = randomBytes(NONCE_LEN);              // әр сақтауда жаңа nonce
  const header = buildHeader(v.iter, v.salt, nonce);
  const json = JSON.stringify({ nextId: v.nextId, records: v.records });
  const cipher = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: header, tagLength: 128 },
    v.key, enc.encode(json)));                       // cipher соңында 16 байт тег бар
  const out = new Uint8Array(header.length + cipher.length);
  out.set(header, 0);
  out.set(cipher, header.length);
  return out;
}

// Файлды парольмен ашу
async function decryptVault(bytes, password) {
  if (bytes.length < HEADER_LEN + 16) throw new Error("bad");
  for (let i = 0; i < 4; i++) if (bytes[i] !== MAGIC[i]) throw new Error("magic");
  if (bytes[4] !== VERSION) throw new Error("version");
  const iter = new DataView(bytes.buffer, bytes.byteOffset).getUint32(5);
  const salt = bytes.slice(9, 9 + SALT_LEN);
  const nonce = bytes.slice(9 + SALT_LEN, HEADER_LEN);
  const header = bytes.slice(0, HEADER_LEN);
  const cipher = bytes.slice(HEADER_LEN);
  const key = await deriveKey(password, salt, iter);
  // Тег сәйкес келмесе, decrypt қате шығарады
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce, additionalData: header, tagLength: 128 },
    key, cipher);
  const data = JSON.parse(dec.decode(plain));
  return { key, salt, iter, records: data.records, nextId: data.nextId };
}

// ================= Экран және хабарлар =================
function showMsg(id, text, ok) {
  const el = document.getElementById(id);
  el.innerHTML = "";
  const d = document.createElement("div");
  d.className = "msg " + (ok ? "ok" : "err");
  d.textContent = text;
  el.appendChild(d);
}

function showScreen(name) {
  document.getElementById("loginScreen").classList.toggle("hidden", name !== "login");
  document.getElementById("vaultScreen").classList.toggle("hidden", name !== "vault");
}

function setDirty(v) {
  dirty = v;
  document.getElementById("dirtyMark").textContent = v ? "⚠ Сақталмаған өзгерістер бар" : "";
}

// ================= Қойма операциялары =================
async function createVault() {
  const p1 = document.getElementById("newPass").value;
  const p2 = document.getElementById("newPass2").value;
  if (p1.length < 8) return showMsg("loginMsg", "Пароль кемінде 8 таңба болуы керек", false);
  if (p1 !== p2) return showMsg("loginMsg", "Парольдер сәйкес емес", false);
  const salt = randomBytes(SALT_LEN);
  const key = await deriveKey(p1, salt, ITERATIONS);
  vault = { key, salt, iter: ITERATIONS, records: [], nextId: 1 };
  document.getElementById("newPass").value = "";
  document.getElementById("newPass2").value = "";
  setDirty(true);
  enterVault();
  showMsg("vaultMsg", "Жаңа қойма жасалды. Жазба қосып, файлды сақтаңыз.", true);
}

async function openVault() {
  const f = document.getElementById("fileInput").files[0];
  const pass = document.getElementById("openPass").value;
  if (!f) return showMsg("loginMsg", "Файлды таңдаңыз", false);
  if (!pass) return showMsg("loginMsg", "Master-парольді енгізіңіз", false);
  try {
    const bytes = new Uint8Array(await f.arrayBuffer());
    vault = await decryptVault(bytes, pass);
    document.getElementById("openPass").value = "";
    setDirty(false);
    enterVault();
  } catch (e) {
    vault = null;
    showMsg("loginMsg", "Пароль қате немесе файл бүлінген", false);
  }
}

function enterVault() {
  document.getElementById("loginMsg").innerHTML = "";
  showScreen("vault");
  resetForm();
  renderList();
}

// Файлды сақтау (жүктеп алу)
async function saveVault() {
  const bytes = await encryptVault(vault);
  const blob = new Blob([bytes], { type: "application/octet-stream" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "records.vault";
  a.click();
  URL.revokeObjectURL(a.href);
  setDirty(false);
  showMsg("vaultMsg", "Шифрланған файл сақталды (records.vault)", true);
}

// Жабу: кілтті жадтан өшіру
function closeVault() {
  if (dirty && !confirm("Сақталмаған өзгерістер бар. Жабасыз ба?")) return;
  vault = null;               // кілт пен жазбалар жадтан өшеді
  setDirty(false);
  document.getElementById("fileInput").value = "";
  document.getElementById("vaultMsg").innerHTML = "";
  showScreen("login");
}

// ================= Жазбалар (RecordManager) =================
function submitRecord() {
  const title = document.getElementById("fTitle").value.trim();
  const login = document.getElementById("fLogin").value.trim();
  const secret = document.getElementById("fSecret").value;
  const note = document.getElementById("fNote").value.trim();
  if (!title) return showMsg("vaultMsg", "Атауын енгізіңіз", false);
  const now = new Date().toISOString();

  if (editId === null) {                        // add
    vault.records.push({ id: vault.nextId++, title, login, secret, note,
                         createdAt: now, updatedAt: now });
  } else {                                      // update
    const r = vault.records.find(x => x.id === editId);
    Object.assign(r, { title, login, secret, note, updatedAt: now });
  }
  setDirty(true);
  resetForm();
  renderList();
  document.getElementById("vaultMsg").innerHTML = "";
}

function startEdit(id) {
  const r = vault.records.find(x => x.id === id);
  editId = id;
  document.getElementById("fTitle").value = r.title;
  document.getElementById("fLogin").value = r.login;
  document.getElementById("fSecret").value = r.secret;
  document.getElementById("fNote").value = r.note;
  document.getElementById("formTitle").textContent = "Жазбаны өзгерту №" + id;
  document.getElementById("submitBtn").textContent = "Өзгерісті сақтау";
  document.getElementById("cancelBtn").classList.remove("hidden");
  window.scrollTo(0, 0);
}

function deleteRecord(id) {
  if (!confirm("Жазбаны жою керек пе?")) return;
  vault.records = vault.records.filter(x => x.id !== id);
  setDirty(true);
  renderList();
}

function resetForm() {
  editId = null;
  ["fTitle", "fLogin", "fSecret", "fNote"].forEach(i => document.getElementById(i).value = "");
  document.getElementById("formTitle").textContent = "Жазба қосу";
  document.getElementById("submitBtn").textContent = "Қосу";
  document.getElementById("cancelBtn").classList.add("hidden");
}

// Іздеу және тізімді көрсету
function renderList() {
  const box = document.getElementById("list");
  box.innerHTML = "";
  if (!vault) return;
  const q = document.getElementById("searchBox").value.toLowerCase();
  const found = vault.records.filter(r =>
    (r.title + " " + r.login + " " + r.note).toLowerCase().includes(q));

  if (found.length === 0) {
    box.textContent = "Жазба жоқ";
    return;
  }
  for (const r of found) {
    const div = document.createElement("div");
    div.className = "rec";

    const t = document.createElement("b");
    t.textContent = r.title;
    const l = document.createElement("div");
    l.textContent = "Логин: " + (r.login || "—");
    const s = document.createElement("div");
    s.textContent = "Құпия: ••••••••";
    const n = document.createElement("div");
    n.textContent = r.note ? "Ескертпе: " + r.note : "";
    const d = document.createElement("small");
    d.textContent = "Құрылған: " + new Date(r.createdAt).toLocaleString() +
                    " | Жаңартылған: " + new Date(r.updatedAt).toLocaleString();

    const showBtn = document.createElement("button");
    showBtn.className = "gray";
    showBtn.textContent = "Көрсету";
    let shown = false;
    showBtn.onclick = () => {
      shown = !shown;
      s.textContent = "Құпия: " + (shown ? r.secret : "••••••••");
      showBtn.textContent = shown ? "Жасыру" : "Көрсету";
    };
    const editBtn = document.createElement("button");
    editBtn.textContent = "Өзгерту";
    editBtn.onclick = () => startEdit(r.id);
    const delBtn = document.createElement("button");
    delBtn.className = "red";
    delBtn.textContent = "Жою";
    delBtn.onclick = () => deleteRecord(r.id);

    div.append(t, l, s, n, d, showBtn, editBtn, delBtn);
    box.appendChild(div);
  }
}

// Бет жабылар алдында ескерту
window.addEventListener("beforeunload", e => {
  if (dirty) { e.preventDefault(); e.returnValue = ""; }
});
