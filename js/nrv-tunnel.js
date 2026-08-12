// js/nrv-tunnel.js — Hidden relay transport (hidden_relay_nip)
//
// Inner Nostr wire messages (["REQ",…], ["EVENT",…], ["CLOSE",…]) are
// encrypted to the hidden relay and carried in kind 27901 events through
// ordinary wss:// rendezvous relays. Kind 27901 is ephemeral.

import { nip44 } from "../lib/nostr-tools.js";
import { finalizeEvent } from "../lib/nostr-tools-pure.js";
import { hexToBytes } from "./crypto.js";

export const KIND_NRV_MESSAGE = 27901;
export const SUPPORTED_ENCRYPTION = ["nip44_v2"];

export class NrvTunnel {
  constructor(clientSecHex, clientPubHex, { encryption = "nip44_v2" } = {}) {
    if (!SUPPORTED_ENCRYPTION.includes(encryption)) {
      throw new Error(`Unsupported encryption: ${encryption}`);
    }
    this.secHex = clientSecHex;
    this.pubHex = clientPubHex;
    this.encryption = encryption;
    this._sockets = new Map();
  }

  /** Open sockets to rendezvous relays and subscribe for replies addressed to us */
  connect(rendezvousUrls) {
    for (const url of rendezvousUrls) {
      if (this._sockets.has(url)) continue;
      const ws = new WebSocket(url);
      const ctx = { ws, ready: false, subId: null, onEvent: null };
      ws.onopen = () => {
        ctx.ready = true;
        ctx.subId = "nrv-" + Math.random().toString(36).slice(2, 10);
        const filter = { kinds: [KIND_NRV_MESSAGE], "#p": [this.pubHex] };
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
        if (event.kind !== KIND_NRV_MESSAGE) return;
        if (ctx.onEvent) ctx.onEvent(event);
      }
    } catch { /* ignore parse errors */ }
  }

  /** Wrap and send an inner Nostr wire message to the hidden relay */
  sendInner(relayPubHex, innerMsg) {
    const secBytes = hexToBytes(this.secHex);
    const conv = nip44.v2.utils.getConversationKey(secBytes, relayPubHex);
    const cipher = nip44.v2.encrypt(JSON.stringify(innerMsg), conv);
    const evt = finalizeEvent({
      kind: KIND_NRV_MESSAGE,
      created_at: Math.floor(Date.now() / 1000),
      tags: [["p", relayPubHex], ["encryption", this.encryption]],
      content: cipher,
    }, secBytes);
    for (const ctx of this._sockets.values()) {
      if (ctx.ready && ctx.ws.readyState === WebSocket.OPEN) {
        ctx.ws.send(JSON.stringify(["EVENT", evt]));
      }
    }
  }

  /** Decrypt an incoming kind 27901 reply from the hidden relay */
  decryptResponse(event) {
    const secBytes = hexToBytes(this.secHex);
    const conv = nip44.v2.utils.getConversationKey(secBytes, event.pubkey);
    return JSON.parse(nip44.v2.decrypt(event.content, conv));
  }

  /** REQ through the tunnel, collecting events until EOSE or timeout */
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
