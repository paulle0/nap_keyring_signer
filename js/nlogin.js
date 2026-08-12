// js/nlogin.js — Encode/decode the 'nlogin1…' bech32 TLV string
//
// TLV layout defined by keyring_nip:
//   0 → 32-byte subkey SECRET key
//   1 → home relay of the masterkey (ASCII bytes), repeatable — carries the
//       canonical nostr+nrv:// hidden relay address
//   2 → 32-byte masterkey public key
//
// TLV 3 (kind) was removed from the spec; kind 17991 is always implied.
//
// TLV 4 → 32-byte subkey PUBLIC key. NOT YET IN THE SPEC. It carries the
// pubkey-only flow, where the keyring shares a subkey it has no secret for.
// Decoding stays tolerant of unknown TLVs, so this is forward-compatible
// either way — but it needs adding to keyring_nip before other
// implementations will understand it.

import { bech32 } from "../lib/scure-base.js";
import { hexToBytes, bytesToHex } from "./crypto.js";

const PREFIX = "nlogin";
const enc = new TextEncoder();
const dec = new TextDecoder();

function writeTLV(type, value) {
  if (value.length > 255) throw new Error("TLV value too long");
  return Uint8Array.of(type, value.length, ...value);
}

function concatBytes(...arrs) {
  let total = 0;
  for (const a of arrs) total += a.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

export function encodeNlogin({ subkeySec, subkeyPub, relays = [], masterPub }) {
  if (!masterPub) throw new Error("masterPub required");
  if (!subkeySec && !subkeyPub) throw new Error("subkeySec or subkeyPub required");

  const parts = [];
  if (subkeySec) parts.push(writeTLV(0, hexToBytes(subkeySec)));
  for (const url of relays) parts.push(writeTLV(1, enc.encode(url)));
  parts.push(writeTLV(2, hexToBytes(masterPub)));
  if (!subkeySec && subkeyPub) parts.push(writeTLV(4, hexToBytes(subkeyPub)));

  const payload = concatBytes(...parts);
  return bech32.encode(PREFIX, bech32.toWords(payload), 5000);
}

export function decodeNlogin(str) {
  const { prefix, words } = bech32.decode(str, 5000);
  if (prefix !== PREFIX) throw new Error(`Wrong prefix: ${prefix}`);
  const bytes = bech32.fromWords(words);
  const out = { subkeySec: null, subkeyPub: null, relays: [], masterPub: null };
  let i = 0;
  while (i < bytes.length) {
    const t = bytes[i];
    const len = bytes[i + 1];
    const v = bytes.slice(i + 2, i + 2 + len);
    i += 2 + len;
    if (t === 0 && v.length === 32) out.subkeySec = bytesToHex(v);
    else if (t === 1) out.relays.push(dec.decode(v));
    else if (t === 2 && v.length === 32) out.masterPub = bytesToHex(v);
    else if (t === 4 && v.length === 32) out.subkeyPub = bytesToHex(v);
    // Unknown TLVs are silently ignored
  }
  if (!out.masterPub) throw new Error("nlogin is missing the masterkey pubkey");
  if (!out.subkeySec && !out.subkeyPub) throw new Error("nlogin carries no subkey material");
  return out;
}

export function isNlogin(s) {
  return typeof s === "string" && s.toLowerCase().startsWith("nlogin1");
}
