// js/nns.js — NNS bech32 decode + tunnel client (kind 27901 via rendezvous relays)
//
// nrvrelay1 TLV:
//   0 → 32-byte relay operator pubkey
//   1 → rendezvous relay URL (ASCII, repeatable)
//   3 → kind number (4-byte BE uint32, informational)
//
// NNS tunnel: client sends/receives kind 27901 events encrypted via NIP-44
// through standard wss:// rendezvous relays. Inner payload is Nostr wire JSON.

import { bech32 } from "../lib/scure-base.js";
import { nip44 } from "../lib/nostr-tools.js";
import { finalizeEvent } from "../lib/nostr-tools-pure.js";
import { hexToBytes, bytesToHex } from "./crypto.js";

const KIND_NNS_MESSAGE = 27901;
const dec = new TextDecoder();

/** Decode an nrvrelay1… bech32 string → { pubkey, relays[] } */
export function decodeNrvrelay(str) {
  const { prefix, words } = bech32.decode(str, 5000);
  if (prefix !== "nrvrelay") throw new Error(`Wrong prefix: ${prefix}`);
  const bytes = bech32.fromWords(words);
  const out = { pubkey: null, relays: [] };
  let i = 0;
  while (i < bytes.length) {
    const t = bytes[i], len = bytes[i + 1];
    const v = bytes.slice(i + 2, i + 2 + len);
    i += 2 + len;
    if (t === 0 && v.length === 32) out.pubkey = bytesToHex(v);
    else if (t === 1) out.relays.push(dec.decode(v));
    // TLV 3 (kind) is informational, ignored
  }
  if (!out.pubkey) throw new Error("nrvrelay missing operator pubkey");
  if (out.relays.length === 0) throw new Error("nrvrelay has no rendezvous relays");
  return out;
}

/** Resolve nns://nrvrelay1… → { pubkey, relays } */
export function resolveNns(nnsUrl) {
  const id = nnsUrl.replace(/^nns:\/\//i, "");
  return decodeNrvrelay(id);
}

/**
 * NNS tunnel client: communicates with a hidden relay through rendezvous relays.
 * Wraps inner Nostr wire messages in kind 27901 NIP-44-encrypted events.
 */
export class NnsTunnel {
  constructor(clientSecHex, clientPubHex) {
    this.secHex = clientSecHex;
    this.pubHex = clientPubHex;
    this._sockets = new Map();
  }

  /** Connect to rendezvous relays and subscribe for responses */
  connect(rendezvousUrls) {
    for (const url of rendezvousUrls) {
      if (this._sockets.has(url)) continue;
      const ws = new WebSocket(url);
      const ctx = { ws, ready: false, subId: null, onEvent: null };
      ws.onopen = () => {
        ctx.ready = true;
        ctx.subId = "nns-" + Math.random().toString(36).slice(2, 10);
        const filter = { kinds: [KIND_NNS_MESSAGE], "#p": [this.pubHex] };
        ws.send(JSON.stringify(["REQ", ctx.subId, filter]));
      };
      ws.onmessage = (e) => this._onMessage(ctx, e);
      ws.onerror = () => {};
      ws.onclose = () => { ctx.ready = false; };
      this._sockets.set(url, ctx);
    }
  }

  _onMessage(ctx, msgEvt) {
    try {
      const msg = JSON.parse(msgEvt.data);
      if (msg[0] === "EVENT" && msg[2]) {
        const event = msg[2];
        if (event.kind !== KIND_NNS_MESSAGE) return;
        if (ctx.onEvent) ctx.onEvent(event);
      }
    } catch { /* ignore parse errors */ }
  }

  /** Send an inner Nostr wire message to the hidden relay */
  sendInner(relayPubHex, innerMsg) {
    const plaintext = JSON.stringify(innerMsg);
    const secBytes = hexToBytes(this.secHex);
    const conv = nip44.v2.utils.getConversationKey(secBytes, relayPubHex);
    const cipher = nip44.v2.encrypt(plaintext, conv);
    const evt = finalizeEvent({
      kind: KIND_NNS_MESSAGE,
      created_at: Math.floor(Date.now() / 1000),
      tags: [["p", relayPubHex], ["encryption", "nip44_v2"]],
      content: cipher,
    }, secBytes);
    for (const ctx of this._sockets.values()) {
      if (ctx.ready && ctx.ws.readyState === WebSocket.OPEN) {
        ctx.ws.send(JSON.stringify(["EVENT", evt]));
      }
    }
  }

  /** Decrypt an incoming kind 27901 response from the hidden relay */
  decryptResponse(event) {
    const secBytes = hexToBytes(this.secHex);
    const conv = nip44.v2.utils.getConversationKey(secBytes, event.pubkey);
    const json = nip44.v2.decrypt(event.content, conv);
    return JSON.parse(json);
  }

  /**
   * Perform a REQ through the tunnel and collect results until EOSE.
   * Returns a promise that resolves to an array of matched events.
   */
  query(relayPubHex, filter, timeoutMs = 8000) {
    return new Promise((resolve) => {
      const subId = "q-" + Math.random().toString(36).slice(2, 10);
      const events = [];
      let settled = false;
      const done = () => {
        if (settled) return;
        settled = true;
        for (const ctx of this._sockets.values()) ctx.onEvent = null;
        this.sendInner(relayPubHex, ["CLOSE", subId]);
        resolve(events);
      };
      for (const ctx of this._sockets.values()) {
        ctx.onEvent = (event) => {
          try {
            const inner = this.decryptResponse(event);
            if (!Array.isArray(inner)) return;
            if (inner[0] === "EVENT" && inner[1] === subId && inner[2]) {
              events.push(inner[2]);
            } else if (inner[0] === "EOSE" && inner[1] === subId) {
              done();
            }
          } catch { /* decrypt/parse errors ignored */ }
        };
      }
      this.sendInner(relayPubHex, ["REQ", subId, filter]);
      setTimeout(done, timeoutMs);
    });
  }

  /** Publish an event through the tunnel and wait for OK */
  publishEvent(relayPubHex, signedEvent, timeoutMs = 6000) {
    return new Promise((resolve) => {
      let settled = false;
      const done = (ok, msg) => {
        if (settled) return;
        settled = true;
        for (const ctx of this._sockets.values()) ctx.onEvent = null;
        resolve({ ok, message: msg });
      };
      for (const ctx of this._sockets.values()) {
        ctx.onEvent = (event) => {
          try {
            const inner = this.decryptResponse(event);
            if (inner[0] === "OK" && inner[1] === signedEvent.id) {
              done(inner[2], inner[3] || "");
            }
          } catch { /* ignore */ }
        };
      }
      this.sendInner(relayPubHex, ["EVENT", signedEvent]);
      setTimeout(() => done(false, "timeout"), timeoutMs);
    });
  }

  disconnect() {
    for (const ctx of this._sockets.values()) {
      ctx.ws.onopen = null;
      ctx.ws.onmessage = null;
      ctx.ws.onerror = null;
      ctx.ws.onclose = null;
      if (ctx.ws.readyState === WebSocket.OPEN) ctx.ws.close();
    }
    this._sockets.clear();
  }
}
