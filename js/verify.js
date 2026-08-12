// js/verify.js — Relationship verification (keyring_nip)
//
// The spec requires clients to verify a keyring relationship from both sides:
// the masterkey's kind 17991 lists the subkey, and the subkey's own kind 17991
// points back at the masterkey. A one-sided relationship is not a valid one.
//
// The same rules make some keys ineligible as subkeys altogether: depth is
// exactly one, so a key that already has a masterkey, or that publishes its
// own subkeys, cannot join this keyring.

import { fetchAll } from "./relays.js";
import { KIND_PUBLIC, parsePublicKeyring } from "./events.js";

export const VERIFIED = "verified";       // both sides agree
export const UNCONFIRMED = "unconfirmed"; // subkey has published no 17991 yet
export const MISMATCH = "mismatch";       // subkey points somewhere else
export const UNKNOWN = "unknown";         // could not be checked

export function verifyLabel(status) {
  if (status === VERIFIED) return "verified";
  if (status === UNCONFIRMED) return "unconfirmed";
  if (status === MISMATCH) return "mismatch";
  return "unchecked";
}

function latestPerAuthor(events) {
  const byAuthor = new Map();
  for (const ev of events) {
    const prev = byAuthor.get(ev.pubkey);
    if (!prev || ev.created_at > prev.created_at) byAuthor.set(ev.pubkey, ev);
  }
  return byAuthor;
}

async function fetchKeyringEvents(masterkey, authors) {
  return fetchAll(masterkey.homeRelays, { kinds: [KIND_PUBLIC], authors }, masterkey);
}

/**
 * Check that each subkey's own kind 17991 points back at the masterkey.
 * Returns Map<subkeyPubkey, status>.
 */
export async function verifySubkeyBacklinks(masterkey, subkeyPubkeys) {
  const result = new Map();
  if (!subkeyPubkeys || subkeyPubkeys.length === 0) return result;

  let events = [];
  try {
    events = await fetchKeyringEvents(masterkey, subkeyPubkeys);
  } catch (e) {
    console.warn("Backlink verification failed:", e.message);
    for (const pk of subkeyPubkeys) result.set(pk, UNKNOWN);
    return result;
  }

  const byAuthor = latestPerAuthor(events);
  for (const pk of subkeyPubkeys) {
    result.set(pk, statusFor(byAuthor.get(pk), masterkey.pubkey));
  }
  return result;
}

function statusFor(event, masterPubkey) {
  if (!event) return UNCONFIRMED;
  const { role, related } = parsePublicKeyring(event);
  if (role !== "subkey") return MISMATCH;
  return related[0] === masterPubkey ? VERIFIED : MISMATCH;
}

/**
 * Decide whether a key may be added to this keyring, before importing it.
 * Returns { ok, status, reason } — ok is false when the depth-one rule or an
 * existing relationship rules the key out.
 */
export async function checkImportCandidate(masterkey, pubkey) {
  if (pubkey === masterkey.pubkey) {
    return { ok: false, status: MISMATCH, reason: "This is your masterkey." };
  }

  let events = [];
  try {
    events = await fetchKeyringEvents(masterkey, [pubkey]);
  } catch {
    return {
      ok: true,
      status: UNKNOWN,
      reason: "Relays could not be reached — the relationship is unverified.",
    };
  }

  const event = latestPerAuthor(events).get(pubkey);
  if (!event) {
    return {
      ok: true,
      status: UNCONFIRMED,
      reason: "This key has published no keyring event yet.",
    };
  }

  const { role, related, extraPtags } = parsePublicKeyring(event);

  if (role === "rootkey") {
    return {
      ok: false,
      status: MISMATCH,
      reason: related.length
        ? "This key already publishes its own subkeys, so it cannot be one."
        : "This key publishes as a rootkey, so it cannot be a subkey.",
    };
  }

  if (role === "subkey" && related[0] && related[0] !== masterkey.pubkey) {
    return {
      ok: false,
      status: MISMATCH,
      reason: "This key already names a different masterkey. A subkey may have only one.",
    };
  }

  if (role === "subkey" && related[0] === masterkey.pubkey) {
    return {
      ok: true,
      status: VERIFIED,
      reason: extraPtags
        ? "Points back at your masterkey, but its event carries extra p-tags."
        : "Already points back at your masterkey.",
    };
  }

  return {
    ok: true,
    status: UNCONFIRMED,
    reason: "Its keyring event names no masterkey yet.",
  };
}
