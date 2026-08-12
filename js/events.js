// js/events.js — Build, sign & parse kind 17991 / 17992 keyring events
//
// Spec alignment (keyring_nip, current):
//   kind 17991 (public rootkey):
//     tags:    [["l", "rootkey"], ["p", subkeyPub], ...]
//     content: "" (empty, reserved for future)
//
//   kind 17991 (public subkey):
//     tags:    [["l", "subkey"], ["p", masterkeyPub]]   — exactly one p-tag
//     content: "" (empty)
//
//   kind 17992 (private, rootkey only):
//     tags:    [["encryption", "nip44_v2"]]
//     content: nip44_encrypted([{ pubkey, seckey, name, description }, ...])
//
// Both kinds are replaceable, which is what makes removing a p-tag a
// complete revocation.

import { finalizeEvent, getEventHash } from "../lib/nostr-tools-pure.js";
import { nip44 } from "../lib/nostr-tools.js";
import { hexToBytes } from "./crypto.js";

const KIND_PUBLIC = 17991;
const KIND_PRIVATE = 17992;

export { KIND_PUBLIC, KIND_PRIVATE };

/**
 * Build a kind 17991 event for a ROOTKEY.
 * Lists every subkey pubkey as a p-tag, labelled "rootkey".
 */
export function buildRootkeyPublicKeyring(rootkeySecHex, subkeyPubkeys) {
  const tags = [["l", "rootkey"]];
  for (const pk of subkeyPubkeys) tags.push(["p", pk]);
  const evt = {
    kind: KIND_PUBLIC,
    created_at: Math.floor(Date.now() / 1000),
    tags,
    content: "",
  };
  return finalizeEvent(evt, hexToBytes(rootkeySecHex));
}

/**
 * Build a kind 17991 event for a SUBKEY.
 * References its single masterkey via one p-tag, labelled "subkey".
 */
export function buildSubkeyPublicKeyring(subkeySecHex, masterkeyPubHex) {
  const evt = {
    kind: KIND_PUBLIC,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ["l", "subkey"],
      ["p", masterkeyPubHex],
    ],
    content: "",
  };
  return finalizeEvent(evt, hexToBytes(subkeySecHex));
}

/**
 * Build a kind 17992 event, encrypted to self via NIP-44 v2.
 * payload: array of { pubkey, seckey?, name, description }
 */
export function buildPrivateKeyring(publisherSecHex, publisherPubHex, payload) {
  const secBytes = hexToBytes(publisherSecHex);
  const conv = nip44.v2.utils.getConversationKey(secBytes, publisherPubHex);

  const cleanPayload = payload.map((e) => ({
    pubkey: e.pubkey,
    seckey: e.seckey || null,
    name: e.name || "",
    description: e.description || "",
  }));

  const cipher = nip44.v2.encrypt(JSON.stringify(cleanPayload), conv);
  const evt = {
    kind: KIND_PRIVATE,
    created_at: Math.floor(Date.now() / 1000),
    tags: [["encryption", "nip44_v2"]],
    content: cipher,
  };
  return finalizeEvent(evt, secBytes);
}

/** Decrypt the content of a kind 17992 event for a given reader. */
export function decryptPrivateKeyring(event, readerSecHex, counterpartyPubHex) {
  const secBytes = hexToBytes(readerSecHex);
  const conv = nip44.v2.utils.getConversationKey(secBytes, counterpartyPubHex);
  return JSON.parse(nip44.v2.decrypt(event.content, conv));
}

/**
 * Parse a kind 17991 event into { role, related[], extraPtags }.
 *
 * role       — "rootkey", "subkey", or null when the l-tag is missing/unknown
 * related    — p-tag pubkeys. For a subkey the spec allows exactly one, so
 *              only the first is returned.
 * extraPtags — true when a subkey event carried more than one p-tag, which
 *              breaks the depth-one rule and should be surfaced to the user.
 */
export function parsePublicKeyring(event) {
  const labelTag = event.tags.find((t) => t[0] === "l");
  const label = labelTag ? labelTag[1] : null;
  const pTags = event.tags.filter((t) => t[0] === "p" && t[1]).map((t) => t[1]);

  if (label === "subkey") {
    return {
      role: "subkey",
      related: pTags.slice(0, 1),
      extraPtags: pTags.length > 1,
    };
  }
  if (label === "rootkey") {
    return { role: "rootkey", related: pTags, extraPtags: false };
  }
  return { role: null, related: pTags, extraPtags: false };
}

export function eventId(evt) {
  return getEventHash(evt);
}
