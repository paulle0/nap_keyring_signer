// js/keyring.js — Orchestrates building & publishing keyring events
//
// Every keyring entry is a subkey. Adding one means publishing both sides of
// the relationship: the masterkey's kind 17991 gains a p-tag, and — when we
// hold the subkey's secret — the subkey publishes its own kind 17991 pointing
// back. Removing one and republishing is the revocation.

import { state, upsertKey, removeKey, findKey } from "./state.js";
import {
  buildRootkeyPublicKeyring,
  buildSubkeyPublicKeyring,
  buildPrivateKeyring,
} from "./events.js";
import { publish } from "./relays.js";
import { saveVault } from "./storage.js";

let sessionPassword = null;

export function setSessionPassword(pw) {
  sessionPassword = pw;
}

export async function persistVault() {
  if (!sessionPassword) return;
  await saveVault({
    masterkey: state.masterkey,
    keyring: state.keyring,
  }, sessionPassword);
}

/** Store a key locally without touching relays (edits, drafts). */
export async function addKeyEntry(entry) {
  upsertKey(entry);
  await persistVault();
}

/**
 * Add a subkey and publish the relationship.
 * Returns { master, backlink } — backlink is null when we hold no secret key
 * for the subkey, in which case its holder must publish the backlink.
 */
export async function addSubkey(entry, { publishNow = true } = {}) {
  upsertKey(entry);
  await persistVault();
  if (!publishNow) return null;
  return publishRelationship(findKey(entry.pubkey));
}

export async function publishRelationship(entry) {
  const master = await republishKeyring();
  let backlink = null;
  if (entry && entry.seckey) {
    backlink = await publishSubkeyKeyring(entry)
      .catch((e) => [{ ok: false, error: e.message }]);
  }
  return { master, backlink };
}

/**
 * Remove a key from the local keyring.
 *
 * With { revoke: true } the keyring is republished immediately. Dropping the
 * p-tag from the replaceable kind 17991 event *is* the revocation — without
 * the republish the subkey stays valid on relays.
 */
export async function removeKeyEntry(pubkey, { revoke = false } = {}) {
  const entry = findKey(pubkey);
  removeKey(pubkey);
  await persistVault();
  if (!revoke || !entry) return null;
  return republishKeyring();
}

/** Republish both masterkey events — after adding or revoking a subkey. */
export async function republishKeyring() {
  const [pub, priv] = await Promise.all([
    publishMasterPublicKeyring().catch((e) => [{ ok: false, error: e.message }]),
    publishMasterPrivateKeyring().catch((e) => [{ ok: false, error: e.message }]),
  ]);
  return { public: pub, private: priv };
}

/**
 * Publish the masterkey's kind 17991 (public) event.
 * tags = [["l","rootkey"], ["p", subkey1], ["p", subkey2], …], content = ""
 */
export async function publishMasterPublicKeyring() {
  const m = state.masterkey;
  if (!m || !m.seckey) throw new Error("Masterkey secret key required");
  const evt = buildRootkeyPublicKeyring(m.seckey, state.keyring.map((k) => k.pubkey));
  return publish(evt, m.homeRelays, m);
}

/**
 * Publish the masterkey's kind 17992 (private) event.
 * content = encrypted([{ pubkey, seckey, name, description }, …]) — mirroring
 * the same keys as the 17991 event.
 */
export async function publishMasterPrivateKeyring() {
  const m = state.masterkey;
  if (!m || !m.seckey) throw new Error("Masterkey secret key required");
  const payload = state.keyring.map((k) => ({
    pubkey: k.pubkey,
    seckey: k.seckey || null,
    name: k.name || "",
    description: k.description || "",
  }));
  const evt = buildPrivateKeyring(m.seckey, m.pubkey, payload);
  return publish(evt, m.homeRelays, m);
}

/**
 * Publish a kind 17991 from the SUBKEY's side — the backlink the spec
 * requires for a relationship to verify bidirectionally.
 * tags = [["l","subkey"], ["p", masterkeyPub]], content = ""
 */
export async function publishSubkeyKeyring(subkey) {
  if (!subkey.seckey) throw new Error("Subkey secret key required");
  const m = state.masterkey;
  const evt = buildSubkeyPublicKeyring(subkey.seckey, m.pubkey);
  return publish(evt, m.homeRelays, m);
}

export function lockSession() {
  sessionPassword = null;
}
