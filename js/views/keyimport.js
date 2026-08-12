// js/views/keyimport.js — Import an existing key as a subkey
//
// The spec allows one relationship shape, so there is no relation choice: an
// imported key becomes a subkey. Before it is added, its own kind 17991 is
// checked — a key that already names a different masterkey, or that publishes
// its own subkeys, breaks the depth-one rule and is refused.
//
// With an nsec the signer can publish the backlink itself. With an npub only,
// the relationship stays unconfirmed until the key's holder publishes theirs.

import { state, setState } from "../state.js";
import { isValidHexKey, getPublicKeyHex } from "../crypto.js";
import { hexFromAny, isNsec, isNpub, npubFromHex } from "../nip19.js";
import { addSubkey } from "../keyring.js";
import { checkImportCandidate, UNCONFIRMED } from "../verify.js";
import { toast, escapeHtml } from "../ui-utils.js";

export function renderImportSubkeyForm(root) {
  root.innerHTML = `
    <div class="detail-head"><h2 class="detail-name">Import subkey</h2></div>
    <p class="card-subtitle">Add an existing key to your keyring as a subkey.</p>

    <div class="field"><label>Key type</label>
      <div class="checkbox-row" id="keyTypeRow">
        <label class="chip-check"><input type="radio" name="keyType" value="secret" checked /> Secret key</label>
        <label class="chip-check"><input type="radio" name="keyType" value="public" /> Public key</label>
      </div></div>

    <div class="field">
      <label id="keyInputLabel">Secret key</label>
      <input id="importKeyInput" class="input mono" placeholder="nsec1… or 64-char hex" autocomplete="off" />
      <p class="field-hint" id="keyInputHint">The public key will be derived automatically.</p></div>

    <div id="derivedInfo" hidden>
      <div class="field"><label>Derived public key (npub)</label>
        <div class="hex" id="derivedNpub"></div></div></div>

    <div class="field"><label>Name</label>
      <input id="impName" class="input" placeholder="e.g. Damus iOS" /></div>
    <div class="field"><label>Description</label>
      <input id="impDesc" class="input" placeholder="optional" /></div>

    <div class="field">
      <label class="chip-check" style="display:inline-flex;">
        <input type="checkbox" id="impPublish" checked /> Publish to relays now
      </label>
      <p class="field-hint" id="publishHint">Publishes your kind 17991 and 17992,
        plus the subkey's own kind 17991 naming your masterkey.</p>
    </div>

    <button class="btn-primary" id="importKeyBtn" style="width:100%">Check and import</button>
    <div id="importCheck"></div>`;

  wireKeyTypeToggle(root);
  wireKeyInputPreview(root);
  root.querySelector("#importKeyBtn").addEventListener("click", () => onImport(root));
}

function isSecretMode(root) {
  return root.querySelector('input[name="keyType"]:checked').value === "secret";
}

function wireKeyTypeToggle(root) {
  root.querySelector("#keyTypeRow").addEventListener("change", () => {
    const secret = isSecretMode(root);
    root.querySelector("#keyInputLabel").textContent = secret ? "Secret key" : "Public key";
    root.querySelector("#importKeyInput").placeholder = secret
      ? "nsec1… or 64-char hex" : "npub1… or 64-char hex";
    root.querySelector("#keyInputHint").textContent = secret
      ? "The public key will be derived automatically."
      : "Only the public key will be stored.";
    root.querySelector("#publishHint").textContent = secret
      ? "Publishes your kind 17991 and 17992, plus the subkey's own kind 17991 naming your masterkey."
      : "Publishes your kind 17991 and 17992. Without the secret key, the subkey's holder must publish the matching kind 17991 themselves.";
    root.querySelector("#derivedInfo").hidden = true;
    root.querySelector("#importKeyInput").value = "";
  });
}

function wireKeyInputPreview(root) {
  const input = root.querySelector("#importKeyInput");
  let debounce = null;
  input.addEventListener("input", () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => previewKey(root), 300);
  });
}

function previewKey(root) {
  const raw = root.querySelector("#importKeyInput").value.trim();
  const info = root.querySelector("#derivedInfo");
  if (!raw) { info.hidden = true; return; }
  try {
    const pubHex = isSecretMode(root)
      ? getPublicKeyHex(resolveSecretHex(raw))
      : resolvePublicHex(raw);
    root.querySelector("#derivedNpub").textContent = npubFromHex(pubHex);
    info.hidden = false;
  } catch { info.hidden = true; }
}

function resolveSecretHex(raw) {
  if (isNsec(raw)) return hexFromAny(raw);
  if (isValidHexKey(raw)) return raw.toLowerCase();
  throw new Error("Not a valid nsec or hex secret key");
}

function resolvePublicHex(raw) {
  if (isNpub(raw)) return hexFromAny(raw);
  if (isValidHexKey(raw)) return raw.toLowerCase();
  throw new Error("Not a valid npub or hex public key");
}

async function onImport(root) {
  const raw = root.querySelector("#importKeyInput").value.trim();
  if (!raw) { toast("Paste a key first", "error"); return; }

  let seckey = null, pubkey = null;
  try {
    if (isSecretMode(root)) {
      seckey = resolveSecretHex(raw);
      pubkey = getPublicKeyHex(seckey);
    } else {
      pubkey = resolvePublicHex(raw);
    }
  } catch (e) { toast(e.message, "error"); return; }

  if (state.keyring.some((k) => k.pubkey === pubkey)) {
    toast("That key is already in your keyring", "error");
    return;
  }

  const btn = root.querySelector("#importKeyBtn");
  btn.disabled = true;
  btn.textContent = "Checking relays…";
  const check = await checkImportCandidate(state.masterkey, pubkey);
  btn.disabled = false;
  btn.textContent = "Check and import";

  showCheck(root, check);
  if (!check.ok) { toast("Key refused — see the note below", "error"); return; }

  const publishNow = root.querySelector("#impPublish").checked;
  const entry = {
    pubkey,
    seckey,
    name: root.querySelector("#impName").value.trim(),
    description: root.querySelector("#impDesc").value.trim(),
    verified: publishNow && seckey ? undefined : check.status,
  };

  try {
    await addSubkey(entry, { publishNow });
  } catch (e) {
    toast(e.message, "error");
  }

  if (!publishNow) toast("Subkey added locally", "success");
  else if (!seckey) toast("Keyring published — awaiting the subkey's backlink", "info");
  else toast("Subkey imported and published", "success");

  setState({ view: "key", selectedKey: pubkey, _importKey: false });
}

function showCheck(root, check) {
  const cls = check.ok ? (check.status === UNCONFIRMED ? "warn" : "ok") : "bad";
  root.querySelector("#importCheck").innerHTML = `
    <p class="key-verify ${cls}" style="margin-top:var(--space-4); text-transform:none; letter-spacing:0;">
      ${escapeHtml(check.reason)}
    </p>`;
}
