// js/views/dashboard.js — Master card + keyring grid
import { state, setState } from "../state.js";
import { npubFromHex, nprofileFromHex } from "../nip19.js";
import { shortHex } from "../crypto.js";
import { escapeHtml, toast, copy } from "../ui-utils.js";
import { publishMasterPublicKeyring, publishMasterPrivateKeyring, persistVault } from "../keyring.js";
import { fetchExistingKeyring } from "../sync.js";

export function renderDashboard() {
  renderMasterCard();
  renderKeysGrid();
  wireActions();
}

function wireActions() {
  document.querySelectorAll("[data-action]").forEach((b) => {
    if (b.dataset.bound) return;
    b.dataset.bound = "1";
    b.addEventListener("click", () => handleAction(b.dataset.action));
  });
}

async function handleAction(action) {
  if (action === "new-related-key") return openNewRelatedKeyView();
  if (action === "import-related-key") return openImportRelatedKeyView();
  if (action === "back-to-dashboard") {
    return setState({ view: "dashboard", _newSubkey: false, _importKey: false });
  }
  if (action === "publish-keyring") return publishKeyring();
  if (action === "refresh-keyring") return refreshKeyring();
}

async function publishKeyring() {
  toast("Publishing keyring…");
  const [resPub, resPriv] = await Promise.all([
    publishMasterPublicKeyring().catch((e) => [{ ok: false, error: e.message }]),
    publishMasterPrivateKeyring().catch((e) => [{ ok: false, error: e.message }]),
  ]);
  summarizePublish(resPub, "Public 17991");
  summarizePublish(resPriv, "Private 17992");
}

async function refreshKeyring() {
  toast("Fetching keyring from relays…");
  try {
    const existing = await fetchExistingKeyring(state.masterkey);
    if (existing.length > 0) {
      setState({ keyring: existing });
      await persistVault();
      toast(`Refreshed — ${existing.length} key(s) from relays`, "success");
    } else {
      toast("No keyring found on relays", "info");
    }
  } catch (e) {
    console.warn("Keyring refresh failed:", e);
    toast("Could not fetch keyring from relays", "error");
  }
}

function summarizePublish(results, label) {
  const ok = results.filter((r) => r.ok).length;
  const total = results.length;
  if (ok === total) toast(`${label} published to ${ok}/${total} relays`, "success");
  else if (ok > 0) toast(`${label} published to ${ok}/${total} relays`, "info");
  else toast(`${label} publish failed — ${results[0]?.error || "all relays rejected"}`, "error");
}

function openNewRelatedKeyView() {
  setState({ view: "key", _newSubkey: true, _importKey: false });
}

function openImportRelatedKeyView() {
  setState({ view: "key", _importKey: true, _newSubkey: false });
}

function renderMasterCard() {
  const m = state.masterkey;
  const npub = npubFromHex(m.pubkey);
  const nprofile = nprofileFromHex(m.pubkey, m.homeRelays);
  const relays = m.homeRelays
    .map((r) => `<span class="relay-pill">${escapeHtml(r)}</span>`).join("");
  document.getElementById("masterCard").innerHTML = `
    <div class="key-master">
      <div class="key-master-label">Masterkey</div>
      <div class="key-master-name">Root</div>
      <div class="key-master-npub" title="${escapeHtml(npub)}">bech32: ${escapeHtml(npub)}</div>
      <div class="key-master-npub" title="${escapeHtml(m.pubkey)}">hex: ${escapeHtml(m.pubkey)}</div>
      <div class="key-master-relays">${relays || "<span class='relay-pill'>no relays</span>"}</div>
      <div class="key-master-actions">
        <button class="link-btn" data-action="refresh-keyring">Refresh keyring</button>
        <button class="link-btn" data-action="publish-keyring">Publish keyring</button>
        <button class="link-btn" id="copyNprofile">Copy nprofile</button>
      </div>
    </div>`;
  wireActions();
  document.getElementById("copyNprofile").addEventListener("click", (e) => copy(nprofile, e.target));
}

function renderKeysGrid() {
  const grid = document.getElementById("keysGrid");
  const empty = document.getElementById("keysEmpty");
  if (state.keyring.length === 0) {
    grid.innerHTML = ""; empty.hidden = false; return;
  }
  empty.hidden = true;
  grid.innerHTML = state.keyring.map(keyCardHtml).join("");
  grid.querySelectorAll(".key-card").forEach((card) => {
    card.addEventListener("click", () => {
      setState({
        view: "key",
        selectedKey: card.dataset.pubkey,
        _newSubkey: false,
        _importKey: false,
      });
    });
  });
}

function shortNpub(hex) {
  const npub = npubFromHex(hex);
  if (npub.length <= 24) return npub;
  return `${npub.slice(0, 14)}…${npub.slice(-8)}`;
}

function keyCardHtml(k) {
  const funcs = (k.functions || []).map((f) =>
    `<span class="func-tag">${escapeHtml(f)}</span>`).join("");
  const hasSec = k.seckey
    ? `<span class="key-has-seckey yes">● has nsec</span>`
    : `<span class="key-has-seckey">○ pubkey only</span>`;
  return `<div class="key-card" data-pubkey="${escapeHtml(k.pubkey)}">
      <div class="key-card-head">
        <span class="key-relation ${k.relation}">${k.relation === "S" ? "subkey" : k.relation === "M" ? "masterkey" : "other"}</span>
        ${hasSec}
      </div>
      <div class="key-name">${escapeHtml(k.name || "Untitled key")}</div>
      <div class="key-desc">${escapeHtml(k.description || "")}</div>
      <div class="key-functions">${funcs}</div>
      <div class="key-card-foot">
        <div>bech32: ${escapeHtml(shortNpub(k.pubkey))}</div>
        <div>hex: ${shortHex(k.pubkey, 10, 10)}</div>
      </div>
    </div>`;
}
