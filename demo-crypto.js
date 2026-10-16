/* Fair Sky Network — interactive demo crypto (browser-only, no backend).
 * Real ECDSA P-256 signatures over a canonical JSON form of the credential.
 * DEMO ONLY: the issuing key is embedded in the issuer page so anyone can try it.
 * In production the key lives in the supplier's own HSM and never leaves it.      */
(function (global) {
  'use strict';

  // ---- issuer registry (what a verifier trusts) -------------------------------
  // In production this is a *published* company -> public-key table (see approach analysis §6).
  var REGISTRY = {
    'did:fsn:precision-alloy-mill': {
      name: 'Precision Alloy Mill Co., Ltd.',
      short: 'Precision Alloy Mill',
      role: 'Melt & bar mill',
      accreditation: 'AS9100 · Nadcap MTL',
      pub: { kty: 'EC', crv: 'P-256', x: 'WjMrRGc_3af-p-grgVAO5JFTGlBLH30HsGyf8el9mpI', y: 'KzjTDMPHt58A5kJUbmr1Zcjb9PEdDQkT8tDVXxTfb8Q' }
    },
    'did:fsn:eastern-forge-works': {
      name: 'Eastern Forge Works Co., Ltd.',
      short: 'Eastern Forge Works',
      role: 'Forge',
      accreditation: 'AS9100',
      pub: null // synthetic demo issuer; its credential is scripted, not signed live
    }
  };

  // DEMO signing key for Precision Alloy Mill (pairs with the registry entry above).
  var DEMO_PRIVATE_JWK = {
    kty: 'EC', crv: 'P-256',
    x: 'WjMrRGc_3af-p-grgVAO5JFTGlBLH30HsGyf8el9mpI',
    y: 'KzjTDMPHt58A5kJUbmr1Zcjb9PEdDQkT8tDVXxTfb8Q',
    d: 'iroKTCI2DnGRTBEz3cBe4fC7mLqRxuRkQmt76LshMTI'
  };

  // ---- encoding helpers -------------------------------------------------------
  var enc = new TextEncoder();
  function b64u(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function unb64u(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    var bin = atob(str), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function utf8ToB64u(s) { return b64u(enc.encode(s)); }
  function b64uToUtf8(s) { return new TextDecoder().decode(unb64u(s)); }
  function hex(bytes) {
    var h = '';
    for (var i = 0; i < bytes.length; i++) h += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    return h;
  }

  // Canonical JSON: sorted keys, no whitespace — the exact bytes that get signed.
  function canonicalize(v) {
    if (v === null || typeof v !== 'object') return JSON.stringify(v);
    if (Array.isArray(v)) return '[' + v.map(canonicalize).join(',') + ']';
    return '{' + Object.keys(v).sort().map(function (k) {
      return JSON.stringify(k) + ':' + canonicalize(v[k]);
    }).join(',') + '}';
  }

  function sha256hex(str) {
    return crypto.subtle.digest('SHA-256', enc.encode(str)).then(function (buf) { return hex(new Uint8Array(buf)); });
  }
  function credentialHash(cred) { return sha256hex(canonicalize(cred)); }

  // ---- sign / verify ----------------------------------------------------------
  function sign(cred, privJwk) {
    return crypto.subtle.importKey('jwk', privJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
      .then(function (key) {
        return crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(canonicalize(cred)));
      })
      .then(function (sig) { return b64u(new Uint8Array(sig)); });
  }
  function verify(cred, sigB64u, pubJwk) {
    if (!pubJwk) return Promise.resolve(false);
    return crypto.subtle.importKey('jwk', pubJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
      .then(function (key) {
        return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, unb64u(sigB64u), enc.encode(canonicalize(cred)));
      })
      .catch(function () { return false; });
  }

  // ---- URL payload: the QR carries the signed credential itself ---------------
  // { c: credential, s: signature, p: {c, s} (previous version, when corrected) }
  function encodePayload(obj) { return utf8ToB64u(JSON.stringify(obj)); }
  function decodePayload(str) {
    try { return JSON.parse(b64uToUtf8(str)); } catch (e) { return null; }
  }
  function verifierUrl(payload) {
    var base = location.origin + location.pathname.replace(/[^\/]*$/, '') + 'buyer-verify.html';
    return base + '#c=' + encodePayload(payload);
  }
  function readPayloadFromHash() {
    var m = /[#&]c=([A-Za-z0-9_-]+)/.exec(location.hash);
    return m ? decodePayload(m[1]) : null;
  }

  // ---- simulated daily anchor -------------------------------------------------
  // Production: all credential hashes issued that day -> Merkle root -> one Ethereum tx (from HK).
  // Demo: a deterministic stand-in so the "verify against the public record" panel has real math to show.
  var DEMO_DAY_SALT = 'fsn-demo-day-root';
  function dayRoot(credHashHex) {
    return sha256hex(DEMO_DAY_SALT + '|' + credHashHex).then(function (h) { return '0x' + h; });
  }

  // ---- local "recent credentials" store (this browser only) ------------------
  var STORE_KEY = 'fsn.demo.issued';
  function loadIssued() { try { return JSON.parse(localStorage.getItem(STORE_KEY) || '[]'); } catch (e) { return []; } }
  function saveIssued(list) { try { localStorage.setItem(STORE_KEY, JSON.stringify(list.slice(0, 12))); } catch (e) {} }

  global.FSN = {
    REGISTRY: REGISTRY, DEMO_PRIVATE_JWK: DEMO_PRIVATE_JWK,
    canonicalize: canonicalize, sha256hex: sha256hex, credentialHash: credentialHash,
    sign: sign, verify: verify,
    encodePayload: encodePayload, decodePayload: decodePayload, verifierUrl: verifierUrl, readPayloadFromHash: readPayloadFromHash,
    dayRoot: dayRoot, loadIssued: loadIssued, saveIssued: saveIssued, b64u: b64u, unb64u: unb64u
  };
})(window);
