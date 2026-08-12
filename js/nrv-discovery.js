// js/nrv-discovery.js — Hidden relay discovery (hidden_relay_nip)
//
// kind 10112 — the hidden relay announces its rendezvous points as r-tags.
// kind 10113 — the hidden relay's info event: an ["encryption", …] tag plus
//              a NIP-11 relay information document in content.
//
// Both are published on the rendezvous relays themselves, so they are read
// with a plain WebSocket REQ — no tunnel needed, and no key material either.

import { SUPPORTED_ENCRYPTION } from "./nrv-tunnel.js";

export const KIND_NRV_ANNOUNCE = 10112;
export const KIND_NRV_INFO = 10113;

/** Plain (untunnelled) REQ against a single relay, resolving on EOSE or timeout */
export function queryPlain(url, filter, timeoutMs = 5000) {
  return new Promise((resolve) => {
    const events = [];
    let ws;
    let settled = false;
    const subId = "d-" + Math.random().toString(36).slice(2, 10);
    const done = () => {
      if (settled) return;
      settled = true;
      try {
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify(["CLOSE", subId]));
          ws.close();
        }
      } catch { /* ignore */ }
      resolve(events);
    };
    try { ws = new WebSocket(url); } catch { resolve(events); return; }
    ws.onopen = () => ws.send(JSON.stringify(["REQ", subId, filter]));
    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg[0] === "EVENT" && msg[2]) events.push(msg[2]);
        else if (msg[0] === "EOSE" && msg[1] === subId) done();
      } catch { /* ignore */ }
    };
    ws.onerror = done;
    ws.onclose = done;
    setTimeout(done, timeoutMs);
  });
}

function latest(events) {
  let best = null;
  for (const ev of events) {
    if (!best || ev.created_at > best.created_at) best = ev;
  }
  return best;
}

/**
 * Refresh a hidden relay's rendezvous points from its kind 10112 event.
 * Returns the union of the seed relays and any announced r-tags, so a stale
 * nrvrelay address keeps working while newer points get picked up.
 */
export async function discoverRendezvous(pubkey, seedRelays) {
  const merged = [...seedRelays];
  const filter = { kinds: [KIND_NRV_ANNOUNCE], authors: [pubkey], limit: 1 };
  const batches = await Promise.all(seedRelays.map((u) => queryPlain(u, filter)));
  const event = latest(batches.flat());
  if (!event) return merged;
  for (const t of event.tags) {
    if (t[0] === "r" && t[1] && !merged.includes(t[1])) merged.push(t[1]);
  }
  return merged;
}

/**
 * Read a hidden relay's kind 10113 info event.
 * Returns { encryption: string[], info: object|null } — encryption is empty
 * when the relay publishes no info event, which callers treat as "unknown".
 */
export async function fetchRelayInfo(pubkey, rendezvousUrls) {
  const filter = { kinds: [KIND_NRV_INFO], authors: [pubkey], limit: 1 };
  const batches = await Promise.all(rendezvousUrls.map((u) => queryPlain(u, filter)));
  const event = latest(batches.flat());
  if (!event) return { encryption: [], info: null };

  const encryption = event.tags
    .filter((t) => t[0] === "encryption")
    .flatMap((t) => t.slice(1))
    .filter(Boolean);

  let info = null;
  try { info = event.content ? JSON.parse(event.content) : null; } catch { info = null; }
  return { encryption, info };
}

/**
 * Pick an encryption scheme we can actually speak.
 * An empty advertised list means the relay published no info event — we fall
 * back to nip44_v2 rather than refusing to talk to it.
 */
export function pickEncryption(advertised) {
  if (!advertised || advertised.length === 0) return SUPPORTED_ENCRYPTION[0];
  const match = advertised.find((e) => SUPPORTED_ENCRYPTION.includes(e));
  if (!match) {
    throw new Error(`Relay supports ${advertised.join(", ")} — this signer speaks nip44_v2`);
  }
  return match;
}
