// js/sync.js — Fetch existing keyring events from relays and merge
import { fetchLatest } from "./relays.js";
import {
  decryptPrivateKeyring,
  parsePublicKeyring,
  KIND_PUBLIC,
  KIND_PRIVATE,
} from "./events.js";
import { verifySubkeyBacklinks, UNKNOWN } from "./verify.js";

/**
 * Fetch the public (17991) and private (17992) keyrings, merge them by
 * pubkey, then verify each relationship from the other side.
 *   - 17991 provides: which keys are in the keyring
 *   - 17992 provides: seckey, name, description
 */
export async function fetchExistingKeyring(masterkey) {
  const { pubkey, seckey, homeRelays } = masterkey;
  if (!homeRelays || homeRelays.length === 0) return [];

  const [pubEntries, privEntries] = await Promise.all([
    fetchPublicKeyring(homeRelays, pubkey, masterkey),
    fetchPrivateKeyring(homeRelays, pubkey, seckey, masterkey),
  ]);

  const merged = mergeEntries(pubEntries || [], privEntries || []);
  return attachVerification(masterkey, merged);
}

async function attachVerification(masterkey, entries) {
  if (entries.length === 0) return entries;
  const status = await verifySubkeyBacklinks(masterkey, entries.map((e) => e.pubkey));
  for (const e of entries) e.verified = status.get(e.pubkey) || UNKNOWN;
  return entries;
}

function mergeEntries(pubEntries, privEntries) {
  const byPubkey = new Map();

  for (const e of pubEntries) {
    byPubkey.set(e.pubkey, { ...e });
  }

  for (const e of privEntries) {
    const existing = byPubkey.get(e.pubkey);
    if (existing) {
      existing.seckey = e.seckey || existing.seckey;
      existing.name = e.name || existing.name;
      existing.description = e.description || existing.description;
    } else {
      byPubkey.set(e.pubkey, { ...e });
    }
  }

  return [...byPubkey.values()];
}

async function fetchPrivateKeyring(relays, pubkey, seckey, masterkey) {
  try {
    const event = await fetchLatest(relays, {
      kinds: [KIND_PRIVATE],
      authors: [pubkey],
      limit: 1,
    }, masterkey);
    if (!event) return null;
    const payload = decryptPrivateKeyring(event, seckey, pubkey);
    if (!Array.isArray(payload)) return null;
    return payload.filter((e) => e && e.pubkey).map((e) => ({
      ...blankEntry(e.pubkey),
      seckey: e.seckey || null,
      name: e.name || "",
      description: e.description || "",
    }));
  } catch (e) {
    console.warn("Failed to fetch/decrypt private keyring:", e);
    return null;
  }
}

async function fetchPublicKeyring(relays, pubkey, masterkey) {
  try {
    const event = await fetchLatest(relays, {
      kinds: [KIND_PUBLIC],
      authors: [pubkey],
      limit: 1,
    }, masterkey);
    if (!event) return null;
    return parseOwnKeyring(event);
  } catch (e) {
    console.warn("Failed to fetch public keyring:", e);
    return null;
  }
}

/**
 * Turn our own kind 17991 into keyring entries. This signer publishes as a
 * rootkey, so every p-tag on that event is one of our subkeys. An event
 * labelled anything else is not ours to read as a keyring.
 */
function parseOwnKeyring(event) {
  const { role, related } = parsePublicKeyring(event);
  if (role !== "rootkey") {
    console.warn(`Own kind 17991 is labelled "${role}" — expected "rootkey"`);
    return [];
  }
  return related.map(blankEntry);
}

function blankEntry(pubkey) {
  return {
    pubkey,
    seckey: null,
    name: "",
    description: "",
    verified: UNKNOWN,
  };
}
