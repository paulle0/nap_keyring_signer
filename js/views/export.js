// js/views/export.js — Export an nlogin: pick a subkey, show QR + copyable string
import { state } from "../state.js";
import { encodeNlogin } from "../nlogin.js";
import { renderQrSvg } from "../qrcode.js";
import { escapeHtml, attachCopy, toast } from "../ui-utils.js";
import { shortHex } from "../crypto.js";
import { npubFromHex } from "../nip19.js";

export async function renderExport() {
  const root = document.getElementById("exportCard");
  const keys = state.keyring;

  if (keys.length === 0) {
    root.innerHTML = `
      <div class="empty-state">
        <div class="empty-mark">⟁</div>
        <h3>No subkeys to export</h3>
        <p>Generate or import a subkey first, then come back here to export it as an <code>nlogin</code>.</p>
      </div>`;
    return;
  }

  root.innerHTML = `
    <h3 class="card-title">Export nlogin</h3>
    <p class="card-subtitle">Pick a subkey to generate a shareable <code>nlogin1…</code> string and QR code.</p>
    <div class="field">
      <label>Subkey</label>
      <select id="exportSelect" class="input">
        <option value="" disabled selected>— choose a key —</option>
        ${keys.map(optionHtml).join("")}
      </select>
    </div>
    <div id="exportResult"></div>`;

  root.querySelector("#exportSelect").addEventListener("change", (e) => {
    const pubkey = e.target.value;
    if (pubkey) showExportResult(root, pubkey);
  });

  if (state._exportKey) {
    const sel = root.querySelector("#exportSelect");
    sel.value = state._exportKey;
    showExportResult(root, state._exportKey);
  }
}

function optionHtml(k) {
  const label = k.name || "Untitled key";
  const hint = k.seckey ? "has nsec" : "pubkey only";
  return `<option value="${escapeHtml(k.pubkey)}">
    ${escapeHtml(label)} · subkey · ${shortHex(k.pubkey, 8, 6)} (${hint})
  </option>`;
}

async function showExportResult(root, pubkey) {
  const key = state.keyring.find((k) => k.pubkey === pubkey);
  if (!key) { toast("Key not found", "error"); return; }

  const includeSec = !!key.seckey;
  const nlogin = encodeNlogin({
    subkeySec: includeSec ? key.seckey : null,
    subkeyPub: includeSec ? null : key.pubkey,
    relays: state.masterkey.homeRelays,
    masterPub: state.masterkey.pubkey,
  });

  const npub = npubFromHex(key.pubkey);
  const result = root.querySelector("#exportResult");

  result.innerHTML = `
    <div style="margin-top:var(--space-5); padding-top:var(--space-4); border-top:1px solid var(--border);">
      <div class="field"><label>Key name</label>
        <div class="hex">${escapeHtml(key.name || "Untitled key")}</div></div>
      <div class="field"><label>npub</label>
        <div class="hex">${escapeHtml(npub)}</div></div>
      <div class="field">
        <label>Shares ${includeSec ? "secret key" : "public key only"}</label></div>
      <div class="field"><label>nlogin string</label>
        <div class="copy-row">
          <input class="input mono" value="${escapeHtml(nlogin)}" readonly />
          <button class="copy-btn" data-copy="${escapeHtml(nlogin)}">Copy</button>
        </div></div>
      <div class="qr-display" id="exportQr"></div>
    </div>`;

  attachCopy(result);
  await renderQrSvg(nlogin, result.querySelector("#exportQr"));
}
