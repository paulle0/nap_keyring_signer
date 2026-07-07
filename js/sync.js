// js/sync.js — Fetch existing keyring events from relays and merge
import { fetchLatest } from "./relays.js";
import { decryptPrivateKeyring, KIND_PUBLIC, KIND_PRIVATE } from "./events.js";

/**
 * Fetch both public (17991) and private (17992) keyrings in parallel,
 * then merge them by pubkey.
 *   - 17991 provides: relation (from label + p-tags)
 *   - 17992 provides: seckey, name, description
 */
export async function fetchExistingKeyring(masterkey) {
  const { pubkey, seckey, homeRelays } = masterkey;
  if (!homeRelays || homeRelays.length === 0) return [];

  const [pubEntries, privEntries] = await Promise.all([
    fetchPublicKeyring(homeRelays, pubkey, masterkey),
    fetchPrivateKeyring(homeRelays, pubkey, seckey, masterkey),
  ]);

  return mergeEntries(pubEntries || [], privEntries || []);
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
    return payload.map(normalizePrivateEntry);
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
    return parsePublicEvent(event);
  } catch (e) {
    console.warn("Failed to fetch public keyring:", e);
    return null;
  }
}

/**
 * Parse a kind 17991 event using the current spec:
 *   tags: [["l", "rootkey"|"subkey"], ["p", pubkey], ...]
 *   content: "" (empty)
 *
 * The "l" tag determines the publisher's role. All "p" tags are related keys.
 * For a rootkey: all p-tags are subkeys → relation "S"
 * For a subkey: single p-tag is the masterkey → relation "M"
 */
function parsePublicEvent(event) {
  const labelTag = event.tags.find((t) => t[0] === "l");
  const label = labelTag ? labelTag[1] : null;
  const pTags = event.tags.filter((t) => t[0] === "p" && t[1]);

  if (label === "rootkey") {
    // Publisher is a rootkey; all p-tags are subkeys
    return pTags.map((t) => ({
      pubkey: t[1],
      relation: "S",
      seckey: null,
      name: "",
      description: "",
      functions: [],
      delegation: "",
    }));
  }

  if (label === "subkey") {
    // Publisher is a subkey; single p-tag is its masterkey
    return pTags.map((t) => ({
      pubkey: t[1],
      relation: "M",
      seckey: null,
      name: "",
      description: "",
      functions: [],
      delegation: "",
    }));
  }

  // Unknown label — treat p-tags as "other" keys
  return pTags.map((t) => ({
    pubkey: t[1],
    relation: "O",
    seckey: null,
    name: "",
    description: "",
    functions: [],
    delegation: "",
  }));
}

function normalizePrivateEntry(e) {
  return {
    relation: "S",
    pubkey: e.pubkey,
    seckey: e.seckey || null,
    name: e.name || "",
    description: e.description || "",
    functions: [],
    delegation: "",
  };
}
