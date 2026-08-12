// js/state.js — Global app state with subscription
//
// Every entry in the keyring is a subkey of the masterkey. keyring_nip defines
// exactly one relationship (rootkey → subkey, depth one), so there is no
// relation field, and the kind 17992 payload schema fixes the stored fields to
// pubkey / seckey / name / description. `verified` is local only — it records
// the result of the bidirectional check and is never published.

import { UNKNOWN } from "./verify.js";

const listeners = new Set();

export const state = {
  masterkey: null,        // { pubkey, seckey, homeRelays }
  keyring: [],            // [{ pubkey, seckey|null, name, description, verified }]
  view: "login",
  theme: "dark",
};

/** Coerce anything (vault, relay, form) into the current entry shape. */
export function normalizeEntry(k) {
  return {
    pubkey: k.pubkey,
    seckey: k.seckey || null,
    name: k.name || "",
    description: k.description || "",
    verified: k.verified || UNKNOWN,
  };
}

export function normalizeKeyring(list) {
  return (list || []).filter((k) => k && k.pubkey).map(normalizeEntry);
}

export function setState(patch) {
  Object.assign(state, patch);
  emit();
}

export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function emit() {
  for (const fn of listeners) {
    try { fn(state); } catch (e) { console.error("listener error", e); }
  }
}

export function findKey(pubkey) {
  return state.keyring.find((k) => k.pubkey === pubkey) || null;
}

export function upsertKey(key) {
  const i = state.keyring.findIndex((k) => k.pubkey === key.pubkey);
  if (i >= 0) {
    state.keyring[i] = normalizeEntry({ ...state.keyring[i], ...key });
  } else {
    state.keyring.push(normalizeEntry(key));
  }
  emit();
}

export function removeKey(pubkey) {
  state.keyring = state.keyring.filter((k) => k.pubkey !== pubkey);
  emit();
}
