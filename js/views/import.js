// js/views/import.js — Import an nlogin via paste or QR scan
import { state, setState } from "../state.js";
import { decodeNlogin, isNlogin } from "../nlogin.js";
import { addKeyEntry } from "../keyring.js";
import { startScanner, stopScannerIfRunning } from "../qrcode.js";
import { toast, escapeHtml } from "../ui-utils.js";
import { shortHex } from "../crypto.js";
import { npubFromHex } from "../nip19.js";

export function renderImport() {
  renderPasteForm();
  renderScanPanel();
}

export async function leaveImport() {
  await stopScannerIfRunning();
}

function renderPasteForm() {
  const root = document.getElementById("importPanel");
  root.innerHTML = `
    <h3 class="card-title">Paste nlogin</h3>
    <p class="card-subtitle">From a login program that wants you to certify a new subkey.</p>
    <div class="field">
      <textarea id="loginStr" class="input mono" placeholder="nlogin1…" rows="4"></textarea>
    </div>
    <button class="btn-primary" id="decodeBtn" style="width:100%">Decode & review</button>
    <div id="decodedPreview"></div>`;
  root.querySelector("#decodeBtn").addEventListener("click", () => onDecode(root));
}

function renderScanPanel() {
  const root = document.getElementById("scanPanel");
  root.innerHTML = `
    <h3 class="card-title">Scan QR</h3>
    <p class="card-subtitle">Point your camera at the login program's QR code.</p>
    <div class="scanner-frame" id="qr-scanner-region">
      <div class="scanner-placeholder">
        <div class="placeholder-icon">⚆</div>
        <div>Press start to open the camera</div>
      </div>
    </div>
    <div style="display:flex; gap:var(--space-2); margin-top:var(--space-4);">
      <button class="btn-secondary" id="startScan" style="flex:1">Start camera</button>
      <button class="btn-ghost" id="stopScan" style="flex:1">Stop</button>
    </div>`;
  root.querySelector("#startScan").addEventListener("click", onStartScan);
  root.querySelector("#stopScan").addEventListener("click", async () => {
    await stopScannerIfRunning();
    document.querySelector("#qr-scanner-region").innerHTML =
      `<div class="scanner-placeholder"><div class="placeholder-icon">⚆</div><div>Camera stopped</div></div>`;
  });
}

async function onStartScan() {
  try {
    document.getElementById("qr-scanner-region").innerHTML = "";
    await startScanner("qr-scanner-region", async (decoded) => {
      await stopScannerIfRunning();
      const input = document.getElementById("loginStr");
      input.value = decoded;
      toast("QR captured", "success");
      onDecode(document.getElementById("importPanel"));
    });
  } catch (e) {
    toast("Camera error: " + e.message, "error");
    document.getElementById("qr-scanner-region").innerHTML =
      `<div class="scanner-placeholder"><div class="placeholder-icon">⚆</div><div>${escapeHtml(e.message)}</div></div>`;
  }
}

function onDecode(root) {
  const raw = root.querySelector("#loginStr").value.trim();
  if (!isNlogin(raw)) { toast("Not a valid nlogin string", "error"); return; }
  let decoded;
  try { decoded = decodeNlogin(raw); }
  catch (e) { toast(e.message, "error"); return; }
  showDecodedPreview(root, decoded);
}

function showDecodedPreview(root, d) {
  const targetSubPub = d.subkeyPub || (d.subkeySec ? "(derived from seckey)" : "");
  const masterMatches = d.masterPub === state.masterkey.pubkey;
  const warning = masterMatches ? ""
    : `<p style="color:var(--warning); font-size:0.85rem; margin-top:var(--space-2);">
       ⚠ This nlogin references a different masterkey: <code>${shortHex(d.masterPub)}</code>.
       </p>`;
  root.querySelector("#decodedPreview").innerHTML = `
    <div style="margin-top:var(--space-5); padding-top:var(--space-4); border-top:1px solid var(--border);">
      <h4 style="font-family:var(--font-mono); font-size:0.72rem; text-transform:uppercase; letter-spacing:0.14em; color:var(--text-faint); margin-bottom:var(--space-3);">Decoded</h4>
      <div class="field"><label>Subkey ${d.subkeySec ? "(seckey provided)" : "(pubkey only)"}</label>
        <div class="hex">${escapeHtml(targetSubPub || shortHex(d.subkeySec))}</div></div>
      <div class="field"><label>Masterkey reference</label><div class="hex">${escapeHtml(npubFromHex(d.masterPub))}</div></div>
      <div class="field"><label>Relays (${d.relays.length})</label>
        ${d.relays.map((r) => `<div class="hex">${escapeHtml(r)}</div>`).join("") || "<span class='hex'>—</span>"}</div>
      <div class="field"><label>Subkey name</label><input id="subName" class="input" placeholder="e.g. Damus client" /></div>
      <div class="field"><label>Description</label><input id="subDesc" class="input" placeholder="optional" /></div>
      <div class="field"><label>Functions</label>
        <div class="checkbox-row">
          ${["signing","certify","encryption","authentication"].map((f) =>
            `<label class="chip-check"><input type="checkbox" value="${f}"> ${f}</label>`).join("")}
        </div></div>
      ${warning}
      <button class="btn-primary" id="addToRing" style="width:100%; margin-top:var(--space-3);">
        Add as ${masterMatches ? '"S" subkey' : '"O" other key'} to my keyring
      </button>
    </div>`;
  root.querySelector("#addToRing").addEventListener("click", async () => {
    const name = root.querySelector("#subName").value.trim();
    const description = root.querySelector("#subDesc").value.trim();
    const functions = [...root.querySelectorAll(".chip-check input:checked")].map((i) => i.value);
    const pubkey = d.subkeyPub || (await derivePubkey(d.subkeySec));
    await addKeyEntry({
      relation: masterMatches ? "S" : "O",
      pubkey, seckey: d.subkeySec || null,
      name, description, functions, delegation: "",
    });
    toast("Key added to your keyring", "success");
    setState({ view: "dashboard" });
  });
}

async function derivePubkey(secHex) {
  const { getPublicKeyHex } = await import("../crypto.js");
  return getPublicKeyHex(secHex);
}
