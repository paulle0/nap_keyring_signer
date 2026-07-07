// js/keyring.js — Orchestrates building+publishing keyring events
import { state, upsertKey, removeKey } from "./state.js";
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

export async function addKeyEntry(entry) {
  upsertKey(entry);
  await persistVault();
}

export async function removeKeyEntry(pubkey) {
  removeKey(pubkey);
  await persistVault();
}

/**
 * Publish the masterkey's kind 17991 (public) event.
 * Spec: tags = [["l","rootkey"], ["p", subkey1], ["p", subkey2], ...]
 *        content = "" (empty)
 */
export async function publishMasterPublicKeyring() {
  const m = state.masterkey;
  if (!m || !m.seckey) throw new Error("Masterkey secret key required");

  // Collect all subkey pubkeys (relation "S")
  const subkeyPubkeys = state.keyring
    .filter((k) => k.relation === "S")
    .map((k) => k.pubkey);

  const evt = buildRootkeyPublicKeyring(m.seckey, subkeyPubkeys);
  return publish(evt, m.homeRelays, m);
}

/**
 * Publish the masterkey's kind 17992 (private) event.
 * Spec: content = encrypted([{pubkey, seckey, name, description}])
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
 * Publish a kind 17991 from the SUBKEY's perspective — the subkey
 * publishes a reference back to its masterkey.
 * Spec: tags = [["l","subkey"], ["p", masterkeyPub]]
 *        content = "" (empty)
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
