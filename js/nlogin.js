// js/nlogin.js — Encode/decode the 'nlogin1...' bech32 TLV string
//
// TLV layout (per keyring_nip spec):
//   0 → 32-byte subkey SECRET key (mutually exclusive with type 4)
//   1 → relay URL (ASCII bytes), repeatable
//   2 → 32-byte masterkey public key
//   4 → 32-byte subkey PUBLIC key (used when secret key not shared)
//
// TLV 3 (kind) has been removed — login-program assumes kind 17991.

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
  const words = bech32.toWords(payload);
  return bech32.encode(PREFIX, words, 5000);
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
  if (!out.masterPub) throw new Error("nlogin missing masterkey pubkey");
  if (!out.subkeySec && !out.subkeyPub) throw new Error("nlogin has no subkey material");
  return out;
}

export function isNlogin(s) {
  return typeof s === "string" && s.toLowerCase().startsWith("nlogin1");
}
