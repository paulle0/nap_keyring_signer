// js/views/keydetail.js — Inspect a subkey, or route to the new/import forms
import { state, setState, findKey } from "../state.js";
import { npubFromHex, nsecFromHex } from "../nip19.js";
import { addKeyEntry, publishSubkeyKeyring } from "../keyring.js";
import { toast, escapeHtml, attachCopy } from "../ui-utils.js";
import { renderImportSubkeyForm } from "./keyimport.js";
import { renderNewSubkeyForm } from "./keynew.js";
import { deleteKeyFlow } from "./revoke.js";
import { verifyBadgeHtml } from "./dashboard.js";
import { VERIFIED } from "../verify.js";

export async function renderKeyDetail() {
  const root = document.getElementById("keyDetailCard");
  if (state._importKey) { renderImportSubkeyForm(root); return; }
  if (state._newSubkey) { renderNewSubkeyForm(root); return; }
  const key = findKey(state.selectedKey);
  if (!key) { toast("Key not found"); setState({ view: "dashboard" }); return; }
  renderExistingKey(root, key);
}

function renderExistingKey(root, key) {
  const npub = npubFromHex(key.pubkey);

  root.innerHTML = `
    <div class="detail-head">
      <div id="detailTitle">
        <h2 class="detail-name">${escapeHtml(key.name || "Untitled key")}</h2>
        <p class="card-subtitle" style="margin:0;">
          <span class="key-relation">subkey</span>
          ${verifyBadgeHtml(key)}
          <span id="descDisplay">${key.description ? " · " + escapeHtml(key.description) : ""}</span>
        </p>
      </div>
      <div style="display:flex; gap:var(--space-2);">
        <button class="btn-edit" id="editBtn">Edit</button>
        <button class="btn-danger" id="deleteBtn">Delete</button>
      </div>
    </div>

    <div id="editPanel" hidden>
      <div class="field"><label>Name</label>
        <input id="editName" class="input" value="${escapeHtml(key.name || "")}" placeholder="e.g. Damus iOS" /></div>
      <div class="field"><label>Description</label>
        <input id="editDesc" class="input" value="${escapeHtml(key.description || "")}" placeholder="optional" /></div>
      <p class="field-hint">Name and description live in your kind 17992 event.
        Republish the keyring to push the change to relays.</p>
      <div style="display:flex; gap:var(--space-2); margin-bottom:var(--space-5);">
        <button class="btn-primary" id="saveEditBtn">Save</button>
        <button class="btn-ghost" id="cancelEditBtn">Cancel</button>
      </div>
    </div>

    ${relationshipBlock(key)}

    <div class="detail-section">
      <h4>Identifier</h4>
      <div class="field"><label>npub</label>
        <div class="copy-row">
          <input class="input mono" value="${escapeHtml(npub)}" readonly />
          <button class="copy-btn" data-copy="${escapeHtml(npub)}">Copy</button>
        </div></div>
      <div class="field"><label>hex pubkey</label>
        <div class="copy-row">
          <input class="input mono" value="${escapeHtml(key.pubkey)}" readonly />
          <button class="copy-btn" data-copy="${escapeHtml(key.pubkey)}">Copy</button>
        </div></div>
      ${key.seckey ? secretBlock(key.seckey) : ""}
    </div>`;

  attachCopy(root);
  root.querySelector("#deleteBtn").addEventListener("click", () => deleteKeyFlow(key));
  root.querySelector("#editBtn").addEventListener("click", () => toggleEdit(root, true));
  root.querySelector("#cancelEditBtn").addEventListener("click", () => toggleEdit(root, false));
  root.querySelector("#saveEditBtn").addEventListener("click", () => onSaveEdit(root, key));
  const backlinkBtn = root.querySelector("#publishBacklinkBtn");
  if (backlinkBtn) backlinkBtn.addEventListener("click", () => onPublishBacklink(key));
}

/**
 * The subkey's own kind 17991 is the half of the relationship the masterkey
 * cannot publish. When we hold the secret key we can fix an unconfirmed
 * relationship in one click; when we don't, only its holder can.
 */
function relationshipBlock(key) {
  if (key.verified === VERIFIED) return "";
  const action = key.seckey
    ? `<button class="btn-secondary" id="publishBacklinkBtn">Publish subkey backlink</button>`
    : `<p class="field-hint">You hold no secret key for this subkey, so its
        holder must publish a kind 17991 naming your masterkey. Send them an
        <code>nlogin</code> if they need the details.</p>`;
  return `
    <div class="detail-section">
      <h4>Relationship</h4>
      <p class="field-hint" style="margin-bottom:var(--space-3);">
        A relationship counts as valid only when this key's own kind 17991
        points back at your masterkey.</p>
      ${action}
    </div>`;
}

function toggleEdit(root, show) {
  root.querySelector("#editPanel").hidden = !show;
  root.querySelector("#editBtn").hidden = show;
}

async function onSaveEdit(root, key) {
  const name = root.querySelector("#editName").value.trim();
  const description = root.querySelector("#editDesc").value.trim();
  await addKeyEntry({ ...key, name, description });
  toast("Key updated", "success");
  setState({ view: "key", selectedKey: key.pubkey });
}

async function onPublishBacklink(key) {
  toast("Publishing subkey backlink…");
  try {
    const results = await publishSubkeyKeyring(key);
    const ok = results.filter((r) => r.ok).length;
    if (ok > 0) {
      await addKeyEntry({ ...key, verified: VERIFIED });
      toast(`Backlink published to ${ok}/${results.length} relays`, "success");
      setState({ view: "key", selectedKey: key.pubkey });
    } else {
      toast(`Backlink failed — ${results[0]?.error || "all relays rejected"}`, "error");
    }
  } catch (e) {
    toast(e.message, "error");
  }
}

function secretBlock(sec) {
  const nsec = nsecFromHex(sec);
  return `<div class="field">
      <label>nsec (handle with care)</label>
      <div class="copy-row">
        <input class="input mono" type="password" value="${escapeHtml(nsec)}" readonly />
        <button class="copy-btn" data-copy="${escapeHtml(nsec)}">Copy</button>
      </div>
    </div>`;
}
