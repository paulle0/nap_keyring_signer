// js/views/keynew.js — Generate a subkey and publish the relationship
//
// keyring_nip defines one relationship: rootkey → subkey, depth one. A new key
// is therefore always a subkey, and the only fields that survive to the wire
// are the ones kind 17992 carries: pubkey, seckey, name, description.
//
// Because the signer holds the fresh secret key, it can publish both halves at
// once — the masterkey's 17991 gains a p-tag, and the subkey publishes its own
// 17991 pointing back. That is what makes the relationship verify.

import { setState } from "../state.js";
import { generateKeyPair } from "../crypto.js";
import { addSubkey } from "../keyring.js";
import { toast } from "../ui-utils.js";
import { VERIFIED } from "../verify.js";

export function renderNewSubkeyForm(root) {
  root.innerHTML = `
    <div class="detail-head"><h2 class="detail-name">New subkey</h2></div>
    <p class="card-subtitle">Generates a fresh keypair, adds it to your keyring,
      and publishes both sides of the relationship.</p>

    <div class="field"><label>Name</label>
      <input id="nName" class="input" placeholder="e.g. Damus iOS" /></div>
    <div class="field"><label>Description</label>
      <input id="nDesc" class="input" placeholder="optional" /></div>

    <div class="field">
      <label class="chip-check" style="display:inline-flex;">
        <input type="checkbox" id="nPublish" checked /> Publish to relays now
      </label>
      <p class="field-hint">Publishes your kind 17991 and 17992, plus the
        subkey's own kind 17991 naming your masterkey. Leave this off to add the
        key locally and publish later from the keyring.</p>
    </div>

    <button class="btn-primary" id="createSubkeyBtn" style="width:100%">Generate subkey</button>
    <div id="newKeyResult"></div>`;

  root.querySelector("#createSubkeyBtn").addEventListener("click", () => onCreate(root));
}

async function onCreate(root) {
  const btn = root.querySelector("#createSubkeyBtn");
  const name = root.querySelector("#nName").value.trim();
  const description = root.querySelector("#nDesc").value.trim();
  const publishNow = root.querySelector("#nPublish").checked;

  btn.disabled = true;
  btn.textContent = publishNow ? "Generating and publishing…" : "Generating…";

  const { seckey, pubkey } = generateKeyPair();
  const entry = {
    pubkey,
    seckey,
    name,
    description,
    verified: publishNow ? VERIFIED : undefined,
  };

  let results = null;
  try {
    results = await addSubkey(entry, { publishNow });
  } catch (e) {
    toast(e.message, "error");
  }

  if (!publishNow) {
    toast("Subkey added — publish the keyring when you're ready", "success");
  } else {
    report(results);
  }

  setState({ view: "key", selectedKey: pubkey, _newSubkey: false });
}

function report(results) {
  if (!results) { toast("Subkey added, but publishing failed", "error"); return; }
  const master = countOk(results.master && results.master.public);
  const backlink = countOk(results.backlink);

  if (master.ok === 0) {
    toast(`Keyring publish failed — ${master.error || "all relays rejected"}`, "error");
    return;
  }
  toast(`Keyring published to ${master.ok}/${master.total} relays`, "success");

  if (backlink.total === 0) return;
  if (backlink.ok > 0) {
    toast(`Subkey backlink published to ${backlink.ok}/${backlink.total} relays`, "success");
  } else {
    toast("Backlink publish failed — the relationship stays unconfirmed", "error");
  }
}

function countOk(results) {
  const list = Array.isArray(results) ? results : [];
  return {
    ok: list.filter((r) => r.ok).length,
    total: list.length,
    error: list[0]?.error || null,
  };
}
