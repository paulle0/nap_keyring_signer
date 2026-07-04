// js/relays.js — Simple relay client for publishing keyring events
import { SimplePool, useWebSocketImplementation } from "../lib/nostr-tools-pool.js";

try { useWebSocketImplementation(WebSocket); } catch {}

let pool = null;
function getPool() {
  if (!pool) pool = new SimplePool();
  return pool;
}

export function disposePool() {
  if (pool) {
    try { pool.close([]); } catch {}
    pool = null;
  }
}

/**
 * Publish a signed event to a set of relays.
 */
export async function publish(event, relays) {
  if (!relays || relays.length === 0) {
    return [{ relay: null, ok: false, error: "No relays configured" }];
  }
  const p = getPool();
  const results = await Promise.allSettled(p.publish(relays, event));
  return results.map((r, i) => ({
    relay: relays[i],
    ok: r.status === "fulfilled",
    error: r.status === "rejected" ? String(r.reason) : null,
  }));
}

/**
 * Fetch the latest event matching a filter from relays.
 */
export async function fetchLatest(relays, filter) {
  if (!relays || relays.length === 0) return null;
  const p = getPool();
  return new Promise((resolve) => {
    let latest = null;
    let timeout;
    const sub = p.subscribeMany(relays, [filter], {
      onevent(ev) {
        if (!latest || ev.created_at > latest.created_at) latest = ev;
      },
      oneose() {
        clearTimeout(timeout);
        try { sub.close(); } catch {}
        resolve(latest);
      },
    });
    timeout = setTimeout(() => {
      try { sub.close(); } catch {}
      resolve(latest);
    }, 6000);
  });
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

/**
 * Check if a relay string is an NNS hidden relay.
 */
export function isNnsRelay(url) {
  return typeof url === "string" && /^nns:\/\//i.test(url);
}

/**
 * Extract the nrvrelay1… bech32 identifier from an nns:// URL.
 */
export function nnsRelayId(url) {
  if (!isNnsRelay(url)) return null;
  return url.replace(/^nns:\/\//i, "");
}
