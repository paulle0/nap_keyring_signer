// js/views/settings.js — Manage relays, change password, export nsec, wipe vault
import { state, setState } from "../state.js";
import { saveVault } from "../storage.js";
import { setSessionPassword, lockSession, persistVault } from "../keyring.js";
import { normalizeRelayUrl } from "../relays.js";
import { nsecFromHex } from "../nip19.js";
import { toast, escapeHtml, modal, copy, attachCopy } from "../ui-utils.js";

export function renderSettings() {
  const root = document.getElementById("settingsCard");
  root.innerHTML = `
    <div class="settings-section">
      <h4>Home relays</h4>
      <p>Nrv hidden relays that receive your kind 17991 / 17992 keyring events. Use <code>nostr+nrv://...</code> or nrvrelay1... format.</p>
      <div id="relaySettingsList">
        ${state.masterkey.homeRelays.map(relayRow).join("")}
      </div>
      <div style="display:flex; gap:var(--space-2); margin-top:var(--space-3);">
        <button class="relay-add" id="relayAdd" type="button">+ add relay</button>
        <button class="btn-primary" id="saveRelaysBtn" style="margin-left:auto;">Save relays</button>
      </div>
    </div>
    ${renderNsecSection()}
    <div class="settings-section">
      <h4>Vault password</h4>
      <p>Re-encrypts the local vault with a new password.</p>
      <div class="field"><input id="newPw" class="input" type="password" placeholder="New password" /></div>
      <button class="btn-secondary" id="changePwBtn">Change password</button>
    </div>
    <div class="settings-section">
      <h4>Log out</h4>
      <p>Erases the local vault. Published keyring events remain on relays.</p>
      <button class="btn-danger" id="wipeBtn">Wipe local vault</button>
    </div>`;
  wireRelays(root);
  wireNsecReveal(root);
  attachCopy(root);
  root.querySelector("#saveRelaysBtn").addEventListener("click", () => onSaveRelays(root));
  root.querySelector("#changePwBtn").addEventListener("click", () => onChangePw(root));
  root.querySelector("#wipeBtn").addEventListener("click", onWipe);
}

function renderNsecSection() {
  if (!state.masterkey || !state.masterkey.seckey) return "";
  return `
    <div class="settings-section">
      <h4>Masterkey secret</h4>
      <p>Copy your masterkey nsec to store it safely. Never share this.</p>
      <div id="nsecContainer">
        <button class="btn-secondary" id="revealNsecBtn">Reveal &amp; copy nsec</button>
      </div>
    </div>`;
}

function wireNsecReveal(root) {
  const btn = root.querySelector("#revealNsecBtn");
  if (!btn) return;
  btn.addEventListener("click", async () => {
    const ok = await modal({
      title: "Reveal masterkey nsec?",
      body: `<p>Your masterkey secret will be shown on screen.</p>`,
      confirmText: "Reveal", confirmKind: "primary",
    });
    if (!ok) return;
    const nsec = nsecFromHex(state.masterkey.seckey);
    const container = root.querySelector("#nsecContainer");
    container.innerHTML = `
      <div class="copy-row">
        <input class="input mono" type="password" value="${escapeHtml(nsec)}" readonly id="nsecInput" />
        <button class="copy-btn" data-copy="${escapeHtml(nsec)}">Copy</button>
        <button class="btn-ghost" id="toggleNsecVis" title="Show / hide" style="padding:0 12px;">👁</button>
      </div>
      <p class="field-hint">Handle with extreme care.</p>`;
    attachCopy(container);
    container.querySelector("#toggleNsecVis").addEventListener("click", () => {
      const inp = container.querySelector("#nsecInput");
      inp.type = inp.type === "password" ? "text" : "password";
    });
  });
}

function relayRow(value = "") {
  return `<div class="relay-row">
      <input class="input" value="${escapeHtml(value)}" placeholder="nns://nrvrelay1…" />
      <button class="relay-remove" type="button" title="Remove">×</button>
    </div>`;
}

function wireRelays(root) {
  root.querySelector("#relaySettingsList").addEventListener("click", (e) => {
    if (e.target.classList.contains("relay-remove")) e.target.closest(".relay-row").remove();
  });
  root.querySelector("#relayAdd").addEventListener("click", () => {
    root.querySelector("#relaySettingsList").insertAdjacentHTML("beforeend", relayRow());
  });
}

async function onSaveRelays(root) {
  const relays = [...root.querySelectorAll("#relaySettingsList .input")]
    .map((i) => normalizeRelayUrl(i.value)).filter(Boolean);
  if (relays.length === 0) { toast("Keep at least one relay", "error"); return; }
  state.masterkey = { ...state.masterkey, homeRelays: relays };
  await persistVault();
  setState({ masterkey: state.masterkey });
  toast("Home relays saved", "success");
}

async function onChangePw(root) {
  const pw = root.querySelector("#newPw").value;
  if (!pw || pw.length < 4) { toast("Choose a stronger password", "error"); return; }
  await saveVault({ masterkey: state.masterkey, keyring: state.keyring }, pw);
  setSessionPassword(pw);
  root.querySelector("#newPw").value = "";
  toast("Vault re-encrypted", "success");
}

async function onWipe() {
  const ok = await modal({
    title: "Wipe local vault?",
    body: `<p>This deletes your encrypted local vault. Published events remain on relays.</p>`,
    confirmText: "Wipe everything", confirmKind: "danger",
  });
  if (!ok) return;
  localStorage.clear();
  lockSession();
  toast("Vault wiped", "info");
  setTimeout(() => location.reload(), 800);
}
