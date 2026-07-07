// js/events.js — Build & sign kind 17991 / 17992 keyring events
//
// Spec alignment (keyring_nip, current):
//   kind 17991 (public rootkey):
//     tags:    [["l", "rootkey"], ["p", subkeyPub], ...]
//     content: "" (empty, reserved for future)
//
//   kind 17991 (public subkey):
//     tags:    [["l", "subkey"], ["p", masterkeyPub]]
//     content: "" (empty)
//
//   kind 17992 (private):
//     tags:    [["encryption", "nip44_v2"]]
//     content: nip44_encrypted([{ pubkey, seckey, name, description }, ...])

import { finalizeEvent, getEventHash } from "../lib/nostr-tools-pure.js";
import { nip44 } from "../lib/nostr-tools.js";
import { hexToBytes } from "./crypto.js";

const KIND_PUBLIC = 17991;
const KIND_PRIVATE = 17992;

export { KIND_PUBLIC, KIND_PRIVATE };

/**
 * Build a kind 17991 (public keyring) event for a ROOTKEY.
 * Lists all subkey pubkeys as p-tags, labeled "rootkey".
 * subkeyPubkeys: string[] — hex pubkeys of subkeys
 */
export function buildRootkeyPublicKeyring(rootkeySecHex, subkeyPubkeys) {
  const tags = [["l", "rootkey"]];
  for (const pk of subkeyPubkeys) {
    tags.push(["p", pk]);
  }
  const evt = {
    kind: KIND_PUBLIC,
    created_at: Math.floor(Date.now() / 1000),
    tags,
    content: "",
  };
  return finalizeEvent(evt, hexToBytes(rootkeySecHex));
}

/**
 * Build a kind 17991 (public keyring) event for a SUBKEY.
 * References its single masterkey via a p-tag, labeled "subkey".
 */
export function buildSubkeyPublicKeyring(subkeySecHex, masterkeyPubHex) {
  const tags = [
    ["l", "subkey"],
    ["p", masterkeyPubHex],
  ];
  const evt = {
    kind: KIND_PUBLIC,
    created_at: Math.floor(Date.now() / 1000),
    tags,
    content: "",
  };
  return finalizeEvent(evt, hexToBytes(subkeySecHex));
}

/**
 * Build a kind 17992 (private keyring) event, encrypted to self via NIP-44 v2.
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

/**
 * Decrypt the content of a kind 17992 event for a given reader.
 */
export function decryptPrivateKeyring(event, readerSecHex, counterpartyPubHex) {
  const secBytes = hexToBytes(readerSecHex);
  const conv = nip44.v2.utils.getConversationKey(secBytes, counterpartyPubHex);
  const json = nip44.v2.decrypt(event.content, conv);
  return JSON.parse(json);
}

export function eventId(evt) {
  return getEventHash(evt);
}
