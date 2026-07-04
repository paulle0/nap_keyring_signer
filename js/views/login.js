// js/views/login.js — Login / unlock flows (import-only, no generate)
import { state, setState } from "../state.js";
import { hasVault, loadVault, saveVault } from "../storage.js";
import { hexFromAny } from "../nip19.js";
import { getPublicKeyHex } from "../crypto.js";
import { setSessionPassword, persistVault } from "../keyring.js";
import { toast, escapeHtml } from "../ui-utils.js";
import { normalizeRelayUrl } from "../relays.js";
import { fetchExistingKeyring } from "../sync.js";

export function renderLogin() {
  const root = document.getElementById("loginCard");
  if (hasVault()) renderUnlock(root);
  else renderCreate(root);
}

function renderUnlock(root) {
  root.innerHTML = `
    <h2 class="card-title">Unlock your keyring</h2>
    <p class="card-subtitle">Enter your vault password to decrypt the local keyring.</p>
    <div class="field">
      <label for="pw">Password</label>
      <input id="pw" class="input" type="password" autofocus />
    </div>
    <button class="btn-primary" id="unlockBtn" style="width:100%">Unlock</button>
    <div style="margin-top:var(--space-4); text-align:center;">
      <button class="btn-back" id="resetBtn">Start fresh (deletes local vault)</button>
    </div>`;
  root.querySelector("#unlockBtn").addEventListener("click", () => doUnlock(root));
  root.querySelector("#pw").addEventListener("keydown", (e) => {
    if (e.key === "Enter") doUnlock(root);
  });
  root.querySelector("#resetBtn").addEventListener("click", async () => {
    if (!confirm("This will delete your local vault. Continue?")) return;
    localStorage.clear();
    location.reload();
  });
}

async function doUnlock(root) {
  const pw = root.querySelector("#pw").value;
  if (!pw) return;
  try {
    const data = await loadVault(pw);
    setSessionPassword(pw);
    setState({ masterkey: data.masterkey, keyring: data.keyring || [], view: "dashboard" });
    toast("Welcome back", "success");
  } catch (e) {
    toast(e.message, "error");
  }
}

function renderCreate(root) {
  root.innerHTML = `
    <h2 class="card-title">Set up your signer</h2>
    <p class="card-subtitle">Import your existing masterkey to get started.</p>
    <div id="loginPanel"></div>`;
  renderSetupForm(root.querySelector("#loginPanel"));
}

function renderSetupForm(panel) {
  const relaysHtml = relayRow("");
  panel.innerHTML = `
    <div class="field">
      <label>Masterkey nsec or hex secret key</label>
      <input id="importKey" class="input mono" placeholder="nsec1… or 64-char hex" autocomplete="off" />
      <p class="field-hint">Create a secret key e.g. <a href="https://nak.nostr.com/" target="_blank" rel="noopener">here</a> or in other nostr programs.</p>
    </div>
    <div class="field">
      <label>Home relays (nns hidden relays)</label>
      <div id="relayList">${relaysHtml}</div>
      <button class="relay-add" id="relayAdd" type="button">+ add relay</button>
      <p class="field-hint">Set up a hidden relay for testing e.g. <a href="https://paulle0.github.io/nns_hidden_relay/" target="_blank" rel="noopener">here</a> or in other implementations of nns hidden relays.</p>
    </div>
    <div class="field">
      <label>Vault password</label>
      <input id="vaultPw" class="input" type="password" placeholder="Encrypts your local vault" />
      <p class="field-hint">Choose a strong password.</p>
    </div>
    <button class="btn-primary" id="setupBtn" style="width:100%">Import & login</button>`;
  wireRelayList(panel);
  panel.querySelector("#setupBtn").addEventListener("click", () => doSetup(panel));
}

function relayRow(value = "") {
  return `<div class="relay-row">
      <input class="input" value="${escapeHtml(value)}" placeholder="nns://nrvrelay1…" />
      <button class="relay-remove" type="button" title="Remove">×</button>
    </div>`;
}

function wireRelayList(panel) {
  panel.querySelector("#relayList").addEventListener("click", (e) => {
    if (e.target.classList.contains("relay-remove")) e.target.closest(".relay-row").remove();
  });
  panel.querySelector("#relayAdd").addEventListener("click", () => {
    panel.querySelector("#relayList").insertAdjacentHTML("beforeend", relayRow());
  });
}

async function doSetup(panel) {
  const pw = panel.querySelector("#vaultPw").value;
  if (!pw || pw.length < 4) { toast("Choose a password (4+ chars)", "error"); return; }
  const relays = [...panel.querySelectorAll("#relayList .input")]
    .map((i) => normalizeRelayUrl(i.value)).filter(Boolean);
  if (relays.length === 0) { toast("Add at least one home relay", "error"); return; }
  let seckey, pubkey;
  try {
    const raw = panel.querySelector("#importKey").value;
    if (!raw) { toast("Enter your nsec or hex secret key", "error"); return; }
    seckey = hexFromAny(raw);
    pubkey = getPublicKeyHex(seckey);
  } catch (e) { toast(e.message, "error"); return; }

  const masterkey = { pubkey, seckey, homeRelays: relays };
  await saveVault({ masterkey, keyring: [] }, pw);
  setSessionPassword(pw);
  setState({ masterkey, keyring: [], view: "dashboard" });
  toast("Vault created", "success");
  await fetchAndMergeKeyring(masterkey);
}

async function fetchAndMergeKeyring(masterkey) {
  toast("Checking relays for existing keyring…");
  try {
    const existing = await fetchExistingKeyring(masterkey);
    if (existing.length > 0) {
      setState({ keyring: existing });
      await persistVault();
      toast(`Imported ${existing.length} key(s) from relays`, "success");
    } else {
      toast("No existing keyring found on relays", "info");
    }
  } catch (e) {
    console.warn("Keyring fetch failed:", e);
    toast("Could not fetch keyring from relays", "error");
  }
}
