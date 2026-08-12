// js/views/revoke.js — Delete a subkey, and publish the revocation
//
// Under keyring_nip, removing the p-tag from the replaceable kind 17991 event
// is the revocation. Deleting locally without republishing leaves the subkey
// valid on relays, so the second step is offered every time.

import { setState } from "../state.js";
import { removeKeyEntry } from "../keyring.js";
import { shortHex } from "../crypto.js";
import { toast, modal, escapeHtml } from "../ui-utils.js";

export async function deleteKeyFlow(key) {
  const name = escapeHtml(key.name || shortHex(key.pubkey));
  const ok = await modal({
    title: "Delete this subkey?",
    body: `<p>Removes <strong>${name}</strong> from your local keyring.</p>`,
    confirmText: "Delete",
    confirmKind: "danger",
  });
  if (!ok) return false;

  const revoke = await modal({
    title: "Publish the revocation?",
    body: `<p>Republishes your kind 17991 and 17992 events without
      <strong>${name}</strong>. Dropping the p-tag is what actually revokes the
      subkey — skip this and it stays valid on relays.</p>`,
    confirmText: "Revoke and publish",
    confirmKind: "danger",
  });

  const results = await removeKeyEntry(key.pubkey, { revoke });
  if (!revoke) toast("Subkey removed locally", "success");
  else if (results) summarize(results.public, "Revocation");
  else toast("Subkey removed", "info");

  setState({ view: "dashboard" });
  return true;
}

function summarize(results, label) {
  const list = Array.isArray(results) ? results : [];
  const ok = list.filter((r) => r.ok).length;
  if (ok === list.length && ok > 0) toast(`${label} published to ${ok}/${list.length} relays`, "success");
  else if (ok > 0) toast(`${label} published to ${ok}/${list.length} relays`, "info");
  else toast(`${label} failed — ${list[0]?.error || "all relays rejected"}`, "error");
}
