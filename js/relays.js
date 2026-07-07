// js/relays.js — Relay client for publishing/fetching keyring events
//
// NNS relay resolution: nns://nrvrelay1… URLs are decoded to get the
// hidden relay's operator pubkey + rendezvous relay URLs, then
// communication happens via NIP-44-encrypted kind 27901 tunnel events.

import { NnsTunnel, resolveNns } from "./nns.js";

let tunnel = null;

/**
 * Get or create the NNS tunnel for the current session.
 * Requires masterkey seckey/pubkey to encrypt tunnel messages.
 */
function getTunnel(secHex, pubHex) {
  if (!tunnel) tunnel = new NnsTunnel(secHex, pubHex);
  return tunnel;
}

export function disposeTunnel() {
  if (tunnel) {
    tunnel.disconnect();
    tunnel = null;
  }
}

/**
 * Resolve an array of nns:// relay URLs into relay descriptors.
 * Returns [{ pubkey, rendezvousUrls }] for each unique hidden relay.
 */
function resolveRelays(nnsRelays) {
  const resolved = [];
  const seen = new Set();
  for (const url of nnsRelays) {
    try {
      const { pubkey, relays } = resolveNns(url);
      if (!seen.has(pubkey)) {
        seen.add(pubkey);
        resolved.push({ pubkey, rendezvousUrls: relays });
      }
    } catch (e) {
      console.warn(`Failed to resolve ${url}:`, e.message);
    }
  }
  return resolved;
}

/**
 * Publish a signed event to NNS hidden relays.
 */
export async function publish(event, nnsRelays, masterkey) {
  if (!nnsRelays || nnsRelays.length === 0) {
    return [{ relay: null, ok: false, error: "No relays configured" }];
  }
  if (!masterkey || !masterkey.seckey) {
    return [{ relay: null, ok: false, error: "Masterkey required for NNS" }];
  }

  const descriptors = resolveRelays(nnsRelays);
  if (descriptors.length === 0) {
    return [{ relay: null, ok: false, error: "Could not resolve any NNS relays" }];
  }

  const t = getTunnel(masterkey.seckey, masterkey.pubkey);
  const results = [];

  for (const desc of descriptors) {
    t.connect(desc.rendezvousUrls);
    // Brief delay to allow WebSocket connections to open
    await sleep(600);
    try {
      const res = await t.publishEvent(desc.pubkey, event);
      results.push({ relay: desc.pubkey, ok: res.ok, error: res.ok ? null : res.message });
    } catch (e) {
      results.push({ relay: desc.pubkey, ok: false, error: e.message });
    }
  }
  return results;
}

/**
 * Fetch the latest event matching a filter from NNS hidden relays.
 */
export async function fetchLatest(nnsRelays, filter, masterkey) {
  if (!nnsRelays || nnsRelays.length === 0) return null;
  if (!masterkey || !masterkey.seckey) return null;

  const descriptors = resolveRelays(nnsRelays);
  if (descriptors.length === 0) return null;

  const t = getTunnel(masterkey.seckey, masterkey.pubkey);
  let latest = null;

  for (const desc of descriptors) {
    t.connect(desc.rendezvousUrls);
    await sleep(600);
    try {
      const events = await t.query(desc.pubkey, filter);
      for (const ev of events) {
        if (!latest || ev.created_at > latest.created_at) latest = ev;
      }
    } catch (e) {
      console.warn("NNS query failed:", e.message);
    }
  }
  return latest;
}

/**
 * Normalize a relay URL.
 * Accepts NNS hidden relay format: nns://nrvrelay1…
 */
export function normalizeRelayUrl(url) {
  const u = url.trim();
  if (!u) return null;
  if (/^nns:\/\//i.test(u)) return u;
  if (/^nrvrelay1/i.test(u)) return `nns://${u}`;
  return null;
}

/** Check if a relay string is an NNS hidden relay. */
export function isNnsRelay(url) {
  return typeof url === "string" && /^nns:\/\//i.test(url);
}

/** Extract the nrvrelay1… bech32 identifier from an nns:// URL. */
export function nnsRelayId(url) {
  if (!isNnsRelay(url)) return null;
  return url.replace(/^nns:\/\//i, "");
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
