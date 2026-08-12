// js/nrv.js — Hidden relay addressing (hidden_relay_nip)
//
// Canonical URL form — what goes in r-tags, nlogin TLV 1, and the vault:
//   nostr+nrv://<64-char hex pubkey>?relay=<url>&relay=<url>
//
// Display / paste form — NIP-19 style bech32:
//   nrvrelay1…   TLV 0 = 32-byte hidden relay pubkey
//                TLV 1 = rendezvous relay URL (ASCII, repeatable)
//
// Legacy `nns://nrvrelay1…` strings are still accepted on input and
// normalised to the canonical URL form.

import { bech32 } from "../lib/scure-base.js";
import { hexToBytes, bytesToHex } from "./crypto.js";

export const BECH32_PREFIX = "nrvrelay";
export const URL_SCHEME = "nostr+nrv://";

const enc = new TextEncoder();
const dec = new TextDecoder();
const URL_RE = /^nostr\+nrv:\/\/([0-9a-f]{64})(?:\?(.*))?$/i;
const LEGACY_RE = /^nns:\/\//i;

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

/** Decode `nrvrelay1…` → { pubkey, relays[] } */
export function decodeNrvrelay(str) {
  const { prefix, words } = bech32.decode(str.trim().toLowerCase(), 5000);
  if (prefix !== BECH32_PREFIX) throw new Error(`Wrong prefix: ${prefix}`);
  const bytes = bech32.fromWords(words);
  const out = { pubkey: null, relays: [] };
  let i = 0;
  while (i < bytes.length) {
    const t = bytes[i];
    const len = bytes[i + 1];
    const v = bytes.slice(i + 2, i + 2 + len);
    i += 2 + len;
    if (t === 0 && v.length === 32) out.pubkey = bytesToHex(v);
    else if (t === 1) out.relays.push(dec.decode(v));
    // Unknown TLVs are ignored
  }
  if (!out.pubkey) throw new Error("nrvrelay is missing the relay pubkey");
  if (out.relays.length === 0) throw new Error("nrvrelay lists no rendezvous relays");
  return out;
}

/** Encode { pubkey, relays[] } → `nrvrelay1…` */
export function encodeNrvrelay({ pubkey, relays = [] }) {
  if (!/^[0-9a-f]{64}$/i.test(pubkey)) throw new Error("Invalid relay pubkey");
  const parts = [writeTLV(0, hexToBytes(pubkey.toLowerCase()))];
  for (const url of relays) parts.push(writeTLV(1, enc.encode(url)));
  return bech32.encode(BECH32_PREFIX, bech32.toWords(concatBytes(...parts)), 5000);
}

/** Parse `nostr+nrv://hexpubkey?relay=…&relay=…` → { pubkey, relays[] } */
export function parseNrvUrl(url) {
  const m = URL_RE.exec(url.trim());
  if (!m) throw new Error("Not a nostr+nrv:// address");
  const pubkey = m[1].toLowerCase();
  const relays = [];
  for (const pair of (m[2] || "").split("&")) {
    if (!pair) continue;
    const eq = pair.indexOf("=");
    if (eq < 0) continue;
    const k = pair.slice(0, eq);
    if (k !== "relay") continue;
    const v = decodeURIComponent(pair.slice(eq + 1));
    if (v) relays.push(v);
  }
  if (relays.length === 0) throw new Error("nostr+nrv:// address lists no rendezvous relays");
  return { pubkey, relays };
}

/** Build the canonical `nostr+nrv://…` URL from { pubkey, relays[] } */
export function buildNrvUrl({ pubkey, relays = [] }) {
  if (!/^[0-9a-f]{64}$/i.test(pubkey)) throw new Error("Invalid relay pubkey");
  const q = relays.map((r) => `relay=${encodeURIComponent(r)}`).join("&");
  return `${URL_SCHEME}${pubkey.toLowerCase()}${q ? "?" + q : ""}`;
}

/**
 * Parse any accepted input form → { pubkey, relays[] }.
 * Accepts: nostr+nrv:// URL, bare nrvrelay1…, legacy nns://nrvrelay1…
 */
export function parseNrvAddress(raw) {
  const s = String(raw || "").trim();
  if (!s) throw new Error("Empty relay address");
  if (URL_RE.test(s)) return parseNrvUrl(s);
  const stripped = s.replace(LEGACY_RE, "");
  if (/^nrvrelay1/i.test(stripped)) return decodeNrvrelay(stripped);
  throw new Error("Not a hidden relay address");
}

/** Normalise any accepted form to the canonical nostr+nrv:// URL. */
export function toNrvUrl(raw) {
  return buildNrvUrl(parseNrvAddress(raw));
}

/** Render any accepted form as an `nrvrelay1…` bech32 string. */
export function toNrvBech32(raw) {
  return encodeNrvrelay(parseNrvAddress(raw));
}

export function isNrvAddress(raw) {
  try { parseNrvAddress(raw); return true; } catch { return false; }
}

/** Short display label, e.g. `nrvrelay1qq…k7f3` */
export function shortNrv(raw) {
  try {
    const b = toNrvBech32(raw);
    return b.length <= 28 ? b : `${b.slice(0, 16)}…${b.slice(-6)}`;
  } catch {
    return String(raw);
  }
}
