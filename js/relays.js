// js/relays.js — Relay client for publishing/fetching keyring events
//
// Home relays are hidden relays (hidden_relay_nip). An address resolves to a
// relay pubkey plus rendezvous points; kind 10112/10113 discovery refreshes
// those points and negotiates encryption; all traffic then goes through a
// kind 27901 tunnel.

import { parseNrvAddress, buildNrvUrl, toNrvUrl } from "./nrv.js";
import { NrvTunnel } from "./nrv-tunnel.js";
import { discoverRendezvous, fetchRelayInfo, pickEncryption } from "./nrv-discovery.js";

let tunnel = null;
const discovery = new Map(); // relayPubkey -> { rendezvousUrls, encryption }

function getTunnel(secHex, pubHex) {
  if (!tunnel) tunnel = new NrvTunnel(secHex, pubHex);
  return tunnel;
}

export function disposeTunnel() {
  if (tunnel) {
    tunnel.disconnect();
    tunnel = null;
  }
  discovery.clear();
}

/** Resolve stored addresses into unique { pubkey, rendezvousUrls } descriptors. */
function resolveRelays(addresses) {
  const resolved = [];
  const seen = new Set();
  for (const addr of addresses) {
    try {
      const { pubkey, relays } = parseNrvAddress(addr);
      if (seen.has(pubkey)) continue;
      seen.add(pubkey);
      resolved.push({ pubkey, rendezvousUrls: relays });
    } catch (e) {
      console.warn(`Could not resolve relay ${addr}:`, e.message);
    }
  }
  return resolved;
}

/** Discover once per session: refresh rendezvous points, negotiate encryption. */
async function enrich(desc) {
  const cached = discovery.get(desc.pubkey);
  if (cached) return { ...desc, ...cached };
  let rendezvousUrls = desc.rendezvousUrls;
  let encryption = "nip44_v2";
  try {
    rendezvousUrls = await discoverRendezvous(desc.pubkey, desc.rendezvousUrls);
    const { encryption: advertised } = await fetchRelayInfo(desc.pubkey, rendezvousUrls);
    encryption = pickEncryption(advertised);
  } catch (e) {
    console.warn(`Discovery for ${desc.pubkey.slice(0, 8)} incomplete:`, e.message);
  }
  const entry = { rendezvousUrls, encryption };
  discovery.set(desc.pubkey, entry);
  return { ...desc, ...entry };
}

async function prepare(addresses, masterkey) {
  const base = resolveRelays(addresses);
  if (base.length === 0) return [];
  const enriched = await Promise.all(base.map(enrich));
  const t = getTunnel(masterkey.seckey, masterkey.pubkey);
  for (const desc of enriched) t.connect(desc.rendezvousUrls);
  await sleep(600);
  return enriched;
}

/** Publish a signed event to every configured hidden relay. */
export async function publish(event, addresses, masterkey) {
  if (!addresses || addresses.length === 0) {
    return [{ relay: null, ok: false, error: "No home relays configured" }];
  }
  if (!masterkey || !masterkey.seckey) {
    return [{ relay: null, ok: false, error: "Masterkey secret key required" }];
  }
  const descriptors = await prepare(addresses, masterkey);
  if (descriptors.length === 0) {
    return [{ relay: null, ok: false, error: "No home relay address could be resolved" }];
  }

  const t = getTunnel(masterkey.seckey, masterkey.pubkey);
  const results = [];
  for (const desc of descriptors) {
    try {
      const res = await t.publishEvent(desc.pubkey, event);
      results.push({ relay: desc.pubkey, ok: res.ok, error: res.ok ? null : res.message });
    } catch (e) {
      results.push({ relay: desc.pubkey, ok: false, error: e.message });
    }
  }
  return results;
}

/** Fetch every event matching a filter, deduplicated by id. */
export async function fetchAll(addresses, filter, masterkey) {
  if (!addresses || addresses.length === 0) return [];
  if (!masterkey || !masterkey.seckey) return [];
  const descriptors = await prepare(addresses, masterkey);
  if (descriptors.length === 0) return [];

  const t = getTunnel(masterkey.seckey, masterkey.pubkey);
  const byId = new Map();
  for (const desc of descriptors) {
    try {
      for (const ev of await t.query(desc.pubkey, filter)) {
        if (!byId.has(ev.id)) byId.set(ev.id, ev);
      }
    } catch (e) {
      console.warn("Hidden relay query failed:", e.message);
    }
  }
  return [...byId.values()];
}

/** Fetch the newest event matching a filter. */
export async function fetchLatest(addresses, filter, masterkey) {
  const events = await fetchAll(addresses, filter, masterkey);
  let latest = null;
  for (const ev of events) {
    if (!latest || ev.created_at > latest.created_at) latest = ev;
  }
  return latest;
}

/**
 * Normalise user input to the canonical nostr+nrv:// address.
 * Accepts nostr+nrv:// URLs, nrvrelay1… bech32, and legacy nns:// strings.
 * Returns null when the input is not a hidden relay address.
 */
export function normalizeRelayUrl(url) {
  const u = String(url || "").trim();
  if (!u) return null;
  try { return toNrvUrl(u); } catch { return null; }
}

/** True when a stored string is a usable hidden relay address. */
export function isHiddenRelay(url) {
  try { parseNrvAddress(url); return true; } catch { return false; }
}

/** Split an address into its parts, or null when unparseable. */
export function relayParts(url) {
  try { return parseNrvAddress(url); } catch { return null; }
}

export { buildNrvUrl };

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
