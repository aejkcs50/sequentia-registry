#!/usr/bin/env node
'use strict';
/*
 * Sequentia Asset Registry
 * ------------------------
 * Our equivalent of the Blockstream Liquid Asset Registry. It maps an asset id to
 * verified, human-readable metadata (name, ticker, precision, issuer domain) and
 * serves it over a small HTTP API that every Sequentia surface (node, node GUI,
 * block explorer, SWK wallet) can consume.
 *
 * Trust model:
 *   1. CONTRACT BINDING. An asset's metadata lives in a "contract" JSON. The
 *      contract_hash = SHA256(canonical-JSON(contract)) is committed *on-chain*
 *      at issuance (it is the issuance input's contract_hash / asset_entropy, and
 *      the asset id is derived from it). On submission we look the asset up on the
 *      chain (via electrs) and require the on-chain contract_hash to equal
 *      SHA256(submitted contract). This cryptographically binds the metadata to
 *      the asset id — no one can register false metadata for someone else's asset.
 *   2. DOMAIN PROOF. The issuer must publish, at
 *        https://<domain>/.well-known/sequentia-asset-proof-<assetid>
 *      the line:
 *        "Authorize linking the domain name <domain> to the Sequentia asset <assetid>"
 *      proving they control the entity domain in the contract.
 *
 * Zero npm dependencies — runs anywhere Node is installed: `node server.js`.
 *
 * Config (env):
 *   PORT                 listen port (default 3005)
 *   DB_DIR               per-asset JSON store (default <dir>/db)
 *   SEED_FILE            legacy/pre-approved assets to load on first run (default <dir>/seed/legacy-assets.json)
 *   SEQ_ELECTRS_URL      explorer API base for on-chain lookups (default http://127.0.0.1:3003)
 *   REQUIRE_DOMAIN_PROOF "1" (default) to require the .well-known proof; "0" to skip (testing)
 *   PROOF_FETCH_TIMEOUT  ms for the domain-proof fetch (default 8000)
 *   ADMIN_TOKEN          if set, enables POST /admin/seed (bearer) to add legacy entries
 */

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const DIR = __dirname;
const PORT = parseInt(process.env.PORT || '3005', 10);
const DB_DIR = process.env.DB_DIR || path.join(DIR, 'db');
const SEED_FILE = process.env.SEED_FILE || path.join(DIR, 'seed', 'legacy-assets.json');
const ELECTRS = (process.env.SEQ_ELECTRS_URL || 'http://127.0.0.1:3003').replace(/\/$/, '');
const REQUIRE_DOMAIN_PROOF = (process.env.REQUIRE_DOMAIN_PROOF || '1') !== '0';
const PROOF_TIMEOUT = parseInt(process.env.PROOF_FETCH_TIMEOUT || '8000', 10);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';

const ASSET_RE = /^[0-9a-f]{64}$/;
const PUBKEY_RE = /^[0-9a-f]{66}$/; // 33-byte compressed pubkey
const XONLY_RE = /^[0-9a-f]{64}$/;  // 32-byte x-only pubkey (OpenAMP enclave keys)
const TICKER_RE = /^[A-Za-z0-9.\-]{1,12}$/; // allow mixed case (e.g. tSEQ, tBTC)
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$/i;

fs.mkdirSync(DB_DIR, { recursive: true });

// ---------- contract hashing (canonical JSON; issuers must match this) ----------
// Canonical JSON: object keys sorted lexicographically, no insignificant
// whitespace. contract_hash = SHA256(UTF-8(canonical-JSON(contract))).
function canonicalize(v) {
  if (Array.isArray(v)) return '[' + v.map(canonicalize).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}
function contractHash(contract) {
  return crypto.createHash('sha256').update(canonicalize(contract), 'utf8').digest('hex');
}

// ---------- asset-id derivation (MED-3) ----------
// Elements/Sequentia derive the asset id from (issuance prevout, contract_hash)
// via a "fast" merkle tree whose node hash is the *SHA256 midstate* of the two
// 32-byte children (one 64-byte block, no length padding / no finalisation).
// This is NOT a plain SHA256, so we implement the raw compression function here.
// References: src/issuance.cpp (GenerateAssetEntropy / CalculateAsset) and
// src/primitives/txwitness.cpp (MerkleHash_Sha256Midstate / ComputeFastMerkleRoot).
const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
// Compress one 64-byte block into the 8-word state and return the raw midstate
// (the chaining variables) as a 32-byte big-endian Buffer. No padding, no finalise.
function sha256Midstate(block64 /* Buffer length 64 */) {
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Uint32Array(64);
  for (let i = 0; i < 16; i++) w[i] = block64.readUInt32BE(i * 4);
  const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;
  for (let i = 16; i < 64; i++) {
    const s0 = (rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)) >>> 0;
    const s1 = (rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)) >>> 0;
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
  }
  let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
  for (let i = 0; i < 64; i++) {
    const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
    const ch = ((e & f) ^ (~e & g)) >>> 0;
    const t1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
    const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
    const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
    const t2 = (S0 + maj) >>> 0;
    h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
  }
  const out = Buffer.alloc(32);
  out.writeUInt32BE((h0 + a) >>> 0, 0); out.writeUInt32BE((h1 + b) >>> 0, 4);
  out.writeUInt32BE((h2 + c) >>> 0, 8); out.writeUInt32BE((h3 + d) >>> 0, 12);
  out.writeUInt32BE((h4 + e) >>> 0, 16); out.writeUInt32BE((h5 + f) >>> 0, 20);
  out.writeUInt32BE((h6 + g) >>> 0, 24); out.writeUInt32BE((h7 + h) >>> 0, 28);
  return out;
}
// fast-merkle node hash of exactly two 32-byte leaves.
function merkleNode(left /* Buffer32 */, right /* Buffer32 */) {
  return sha256Midstate(Buffer.concat([left, right]));
}
// Derive the asset id from the issuance prevout (txid hex, vout) and the on-chain
// contract_hash (hex). Returns a 64-hex string, or null if inputs are malformed.
//   leafPrevout = SHA256(COutPoint) where COutPoint = txid(32, internal byte
//                 order) || vout(uint32 LE)  -- this is SerializeHash(prevout).
//   entropy = merkleNode( leafPrevout, contract_hash )
//   asset   = merkleNode( entropy, 0^32 )
function deriveAssetId(prevoutTxid, prevoutVout, contractHashHex, descriptorHashHex) {
  if (!/^[0-9a-f]{64}$/.test(prevoutTxid || '')) return null;
  if (!/^[0-9a-f]{64}$/.test(contractHashHex || '')) return null;
  if (descriptorHashHex != null && !/^[0-9a-f]{64}$/.test(descriptorHashHex)) return null;
  if (!Number.isInteger(prevoutVout) || prevoutVout < 0 || prevoutVout > 0xffffffff) return null;
  // electrs reports txids in display (reversed) order; COutPoint serialises the
  // internal (little-endian) byte order, so reverse the displayed txid.
  const txidInternal = Buffer.from(prevoutTxid, 'hex').reverse();
  const vout = Buffer.alloc(4); vout.writeUInt32LE(prevoutVout, 0);
  const outpoint = Buffer.concat([txidInternal, vout]);
  // SerializeHash() is a DOUBLE SHA256 (CHashWriter::GetHash), not a single one.
  const sha = (b) => crypto.createHash('sha256').update(b).digest();
  const leafPrevout = sha(sha(outpoint));
  // contractHashHex is the NATURAL-order contract_hash (onChainContract reverses
  // electrs's display-order value back to natural), which equals Node's
  // SHA256(canonical-JSON(contract)) byte-for-byte, so its raw bytes are the merkle
  // leaf in internal uint256 order.
  // A SUPERVISED asset commits a third leaf, the hash of its supervision
  // descriptor, so its issuer's freeze keys are part of the asset's identity and
  // cannot be added, removed or altered afterwards. Without this branch a
  // supervised asset derives to a different id here and never verifies, which
  // for the bridged stablecoin would mean it could never be registered at all.
  //
  // Three leaves under ComputeFastMerkleRoot reduce to H(H(a,b),c). Checked
  // against the node's own pinned vector, not assumed: see
  // Sequentia src/test/supervision_tests.cpp, derivation_vectors_are_pinned.
  let entropy = merkleNode(leafPrevout, Buffer.from(contractHashHex, 'hex'));
  if (descriptorHashHex != null) {
    entropy = merkleNode(entropy, Buffer.from(descriptorHashHex, 'hex'));
  }
  const assetInternal = merkleNode(entropy, Buffer.alloc(32));
  // CAsset is printed via uint256::GetHex(), which reverses the internal bytes,
  // so reverse to match the displayed asset_id that electrs/RPC/the registry use.
  return Buffer.from(assetInternal).reverse().toString('hex');
}

// ---------- contract validation ----------
// Liquid-compatible contract shape: { name, ticker, precision, entity:{domain}, issuer_pubkey, version }
function validateContract(c) {
  const errs = [];
  if (!c || typeof c !== 'object') return ['contract must be an object'];
  if (typeof c.name !== 'string' || !c.name.length || c.name.length > 255) errs.push('name: 1..255 chars');
  if (typeof c.ticker !== 'string' || !TICKER_RE.test(c.ticker)) errs.push('ticker: 1..12 of [A-Z0-9.-]');
  if (!Number.isInteger(c.precision) || c.precision < 0 || c.precision > 8) errs.push('precision: integer 0..8');
  if (!c.entity || typeof c.entity !== 'object' || typeof c.entity.domain !== 'string' || !DOMAIN_RE.test(c.entity.domain))
    errs.push('entity.domain: valid domain');
  // issuer_pubkey may be a 33-byte compressed key or, for OpenAMP restricted
  // assets whose enclave keys are BIP340 x-only, a 32-byte x-only key.
  if (typeof c.issuer_pubkey !== 'string' || !(PUBKEY_RE.test(c.issuer_pubkey) || XONLY_RE.test(c.issuer_pubkey)))
    errs.push('issuer_pubkey: 33-byte compressed or 32-byte x-only hex');
  else if (/^(?:[0-9a-f]{2})?0{64}$/i.test(c.issuer_pubkey)) errs.push('issuer_pubkey: must not have an all-zeros X coordinate (placeholder)');
  if (c.version !== 0) errs.push('version: must be 0');
  // Optional OpenAMP block: marks the asset as issuer-governed (restricted)
  // and points wallets at the policy server that verifies the binding and
  // co-signs transfers. See the openamp repo's spec/contract-v1.md.
  if (c.openamp !== undefined) errs.push(...validateOpenAmp(c.openamp));
  // Reject unknown top-level keys so the canonical hash is well-defined. An
  // OpenAMP issuer may commit its operator identity in the contract (the
  // registrar/transfer-agent operating the policy server); the contract_hash
  // commits to the whole document, so the registry must accept those exact bytes
  // to verify the on-chain binding rather than strip them post-hoc.
  const allowed = new Set(['name', 'ticker', 'precision', 'entity', 'issuer_pubkey', 'version', 'openamp', 'operator']);
  for (const k of Object.keys(c)) if (!allowed.has(k)) errs.push(`unexpected field: ${k}`);
  if (c.entity) for (const k of Object.keys(c.entity)) if (k !== 'domain' && k !== 'issuer') errs.push(`unexpected entity field: ${k}`);
  if (c.entity && c.entity.issuer !== undefined && typeof c.entity.issuer !== 'string') errs.push('entity.issuer: string');
  if (c.operator !== undefined) errs.push(...validateOperator(c.operator));
  return errs;
}

function validateOperator(op) {
  const errs = [];
  if (!op || typeof op !== 'object') return ['operator: must be an object'];
  const allowed = new Set(['name', 'registration']);
  for (const k of Object.keys(op)) if (!allowed.has(k)) errs.push(`unexpected operator field: ${k}`);
  if (op.name !== undefined && typeof op.name !== 'string') errs.push('operator.name: string');
  if (op.registration !== undefined && typeof op.registration !== 'string') errs.push('operator.registration: string');
  return errs;
}

function validateOpenAmp(o) {
  const errs = [];
  if (!o || typeof o !== 'object') return ['openamp: must be an object'];
  if (!Number.isInteger(o.version) || o.version < 1) errs.push('openamp.version: integer >= 1');
  if (o.type !== 'restricted' && o.type !== 'tracked') errs.push('openamp.type: "restricted" | "tracked"');
  if (typeof o.policy_pubkey !== 'string' || !XONLY_RE.test(o.policy_pubkey)) errs.push('openamp.policy_pubkey: 32-byte x-only hex (FROST group key)');
  if (typeof o.clawback !== 'boolean') errs.push('openamp.clawback: boolean');
  if (o.burn_allowed !== undefined && typeof o.burn_allowed !== 'boolean') errs.push('openamp.burn_allowed: boolean');
  if (o.confidential !== undefined && typeof o.confidential !== 'boolean') errs.push('openamp.confidential: boolean');
  if (o.policy_endpoints !== undefined) {
    if (!Array.isArray(o.policy_endpoints) || !o.policy_endpoints.every(e => typeof e === 'string' && /^https:\/\//.test(e)))
      errs.push('openamp.policy_endpoints: array of https urls');
  }
  const allowed = new Set(['version', 'type', 'policy_pubkey', 'clawback', 'burn_allowed', 'confidential', 'policy_endpoints', 'terms_hash']);
  for (const k of Object.keys(o)) if (!allowed.has(k)) errs.push(`unexpected openamp field: ${k}`);
  return errs;
}

// ---------- SSRF guard (MED-2) ----------
const dns = require('dns');
const net = require('net');
// True if the literal IP is loopback / private / link-local / CGNAT / metadata /
// otherwise not a routable public address that an issuer domain should resolve to.
function isBlockedIp(ip) {
  if (net.isIPv4(ip)) {
    const o = ip.split('.').map(Number);
    if (o[0] === 0) return true;                              // 0.0.0.0/8
    if (o[0] === 10) return true;                             // 10/8 private
    if (o[0] === 127) return true;                            // loopback
    if (o[0] === 169 && o[1] === 254) return true;            // link-local + 169.254.169.254 metadata
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true; // 172.16/12 private
    if (o[0] === 192 && o[1] === 168) return true;            // 192.168/16 private
    if (o[0] === 192 && o[1] === 0 && o[2] === 0) return true; // 192.0.0/24
    if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return true; // 100.64/10 CGNAT
    if (o[0] >= 224) return true;                             // multicast/reserved/broadcast
    return false;
  }
  if (net.isIPv6(ip)) {
    const lc = ip.toLowerCase();
    if (lc === '::1' || lc === '::') return true;             // loopback / unspecified
    if (lc.startsWith('fe80')) return true;                   // link-local
    if (lc.startsWith('fc') || lc.startsWith('fd')) return true; // unique-local fc00::/7
    if (lc.startsWith('::ffff:')) {                           // IPv4-mapped
      const v4 = lc.slice(7);
      if (net.isIPv4(v4)) return isBlockedIp(v4);
    }
    return false;
  }
  return true; // unparseable -> block
}
function assertPublicHost(hostname) {
  return new Promise((resolve, reject) => {
    if (net.isIP(hostname)) {
      return isBlockedIp(hostname) ? reject(new Error('refusing to fetch a non-public address')) : resolve();
    }
    dns.lookup(hostname, { all: true }, (err, addrs) => {
      if (err) return reject(new Error('dns lookup failed'));
      if (!addrs || !addrs.length) return reject(new Error('dns lookup empty'));
      for (const a of addrs) if (isBlockedIp(a.address)) return reject(new Error('domain resolves to a non-public address'));
      resolve();
    });
  });
}

// ---------- tiny fetch (http/https GET -> {status, body, contentType}) ----------
// opts.trusted=true skips the SSRF guard (used only for the operator-configured
// electrs endpoint, which is expected to be loopback/private). Untrusted fetches
// (issuer domain proofs) always go through the guard.
async function fetchUrl(u, timeout = PROOF_TIMEOUT, opts = {}) {
  let url;
  try { url = new URL(u); } catch (e) { throw new Error('bad url'); }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error('unsupported url scheme');
  // SSRF guard: never fetch loopback/private/link-local/metadata addresses.
  if (!opts.trusted) await assertPublicHost(url.hostname);
  return new Promise((resolve, reject) => {
    const mod = url.protocol === 'https:' ? https : http;
    const req = mod.get(url, res => {
      let data = '';
      res.on('data', d => { data += d; if (data.length > 1_000_000) req.destroy(); });
      res.on('end', () => resolve({ status: res.statusCode, body: data, contentType: res.headers['content-type'] || '' }));
    });
    req.on('error', reject);
    req.setTimeout(timeout, () => req.destroy(new Error('timeout')));
  });
}

// ---------- on-chain verification (via electrs) ----------
// Returns { contract_hash, issuance_txid } for a NEW issuance, or throws.
async function onChainContract(assetId) {
  const a = await fetchUrl(`${ELECTRS}/asset/${assetId}`, PROOF_TIMEOUT, { trusted: true });
  if (a.status !== 200) throw httpErr(400, `asset ${assetId} not found on chain (electrs ${a.status})`);
  const asset = JSON.parse(a.body);
  const itx = asset.issuance_txin;
  if (!itx || !itx.txid) throw httpErr(400, 'asset has no issuance on chain');
  const t = await fetchUrl(`${ELECTRS}/tx/${itx.txid}`, PROOF_TIMEOUT, { trusted: true });
  if (t.status !== 200) throw httpErr(400, `issuance tx not found (electrs ${t.status})`);
  const tx = JSON.parse(t.body);
  const vin = (tx.vin || [])[itx.vin];
  const iss = vin && vin.issuance;
  if (!iss) throw httpErr(400, 'issuance input not found in issuance tx');
  if (iss.is_reissuance) throw httpErr(400, 'issuance input is a reissuance, not the initial issuance');
  // electrs reports the issuance contract_hash as a uint256 in DISPLAY (reversed)
  // byte order, like every other 256-bit hash it prints. The on-chain commitment is
  // SHA256(canonical-JSON(contract)) in NATURAL order (the value the node hashes and
  // the value deriveAssetId feeds to the merkle leaf), so reverse it back to natural
  // order here. Without this, a legitimately-issued OpenAMP asset never verifies.
  if (!/^[0-9a-f]{64}$/.test(iss.contract_hash || ''))
    throw httpErr(400, 'issuance input has no valid contract_hash on chain');
  // Is this a supervised asset? The declaration rides in an output of the very
  // transaction we already have, so this costs no extra fetch.
  let supervision = null;
  for (const out of (tx.vout || [])) {
    const parsed = parseSupervisionScript(out.scriptpubkey);
    if (parsed) { supervision = parsed; break; }
  }

  return {
    contract_hash: Buffer.from(iss.contract_hash, 'hex').reverse().toString('hex'),
    issuance_txid: itx.txid,
    prevout_txid: vin.txid,
    prevout_vout: vin.vout,
    supervision,
  };
}

// ---------- supervision ----------
// A supervised asset is one whose issuer can freeze holders by consensus rule
// (Sequentia src/supervision.h). The terms are declared in an output of the
// issuance transaction AND committed in the asset id, so what we read here is
// not a claim: deriveAssetId re-derives over it, and an issuance that misstates
// its own terms simply fails to verify.
//
// Script shape, from BuildSupervisionScript:
//   <"SEQSUP"> OP_DROP <asset:32> OP_DROP <descriptor:67> OP_DROP OP_RETURN
const SUPERVISION_SCRIPT_RE =
  /^06534551535550752[0]([0-9a-f]{64})7543([0-9a-f]{134})756a$/;

function parseSupervisionScript(scriptHex) {
  const m = SUPERVISION_SCRIPT_RE.exec((scriptHex || '').toLowerCase());
  if (!m) return null;
  const descriptorHex = m[2];
  const bytes = Buffer.from(descriptorHex, 'hex');
  // version(1) || feature_bits(2, LE) || operational(32) || recovery(32)
  const version = bytes[0];
  const featureBits = bytes.readUInt16LE(1);
  return {
    asset_id: Buffer.from(m[1], 'hex').reverse().toString('hex'),
    descriptor_hex: descriptorHex,
    version,
    feature_bits: featureBits,
    operational_key: bytes.slice(3, 35).toString('hex'),
    recovery_key: bytes.slice(35, 67).toString('hex'),
    // Bit 1 is the only implemented capability: an asset-wide pause.
    pause_allowed: (featureBits & 0x0002) !== 0,
  };
}

// The descriptor's hash as consensus computes it: SerializeHash over the 67
// canonical bytes, which is a DOUBLE SHA256 (CHashWriter::GetHash), like the
// prevout leaf above and unlike the contract hash.
function supervisionDescriptorHash(descriptorHex) {
  const sha = (b) => crypto.createHash('sha256').update(b).digest();
  return sha(sha(Buffer.from(descriptorHex, 'hex'))).toString('hex');
}

// ---------- domain proof ----------
function proofText(domain, assetId) {
  return `Authorize linking the domain name ${domain} to the Sequentia asset ${assetId}`;
}
async function verifyDomainProof(domain, assetId) {
  const url = `https://${domain}/.well-known/sequentia-asset-proof-${assetId}`;
  let r;
  try { r = await fetchUrl(url); } catch (e) { throw httpErr(400, `domain proof fetch failed: ${e.message}`); }
  if (r.status !== 200) throw httpErr(400, `domain proof not found at ${url} (HTTP ${r.status})`);
  // The exact-body match below is the real proof of control: the response must
  // BE the line, so a line smuggled into a page the claimant doesn't actually
  // control can never match. The content type therefore only needs to keep out
  // responses that declare themselves to be something else entirely (an HTML
  // page, say). Extensionless files are routinely served with no declared type
  // at all (Apache omits the header) or as application/octet-stream -- both
  // accepted, the body decides.
  const ct = (r.contentType || '').split(';')[0].trim().toLowerCase();
  if (ct && ct !== 'text/plain' && ct !== 'application/octet-stream')
    throw httpErr(400, `domain proof at ${url} must be plain text, not '${r.contentType}'`);
  // Require the body to EQUAL the authorization line (trimmed), not merely contain
  // it (MED-2): a substring match let unrelated/attacker-influenced content pass.
  if (r.body.trim() !== proofText(domain, assetId)) throw httpErr(400, `domain proof at ${url} must contain exactly the authorization line and nothing else`);
  return url;
}

// ---------- store ----------
function entryPath(id) { return path.join(DB_DIR, `${id}.json`); }
function listIds() { return fs.readdirSync(DB_DIR).filter(f => f.endsWith('.json')).map(f => f.slice(0, -5)).filter(id => ASSET_RE.test(id)); }
function readEntry(id) { try { return JSON.parse(fs.readFileSync(entryPath(id), 'utf8')); } catch (e) { return null; } }
function writeEntry(e) { fs.writeFileSync(entryPath(e.asset_id), JSON.stringify(e, null, 2)); }
function allEntries() { return listIds().map(readEntry).filter(Boolean); }

// ---------- succession ----------
// An asset's chain-committed contract is immutable: its hash is baked into the
// asset id, so the name and ticker an asset was issued under can never be
// rewritten on chain. That is right for provenance and wrong for display in one
// specific case: a bridged asset that its stablecoin issuer later adopts. The
// whole point of a bridged-to-native hand-off is that the SAME asset keeps
// every balance and integration while becoming the issuer's own, and an asset
// stuck advertising the bridge that minted it cannot do that.
//
// A successor record overlays display metadata (name, ticker, domain, issuer
// key) while preserving the original contract and its hash untouched, so the
// on-chain binding stays verifiable and the trail records who handed off to
// whom. It requires BOTH factors, which is what makes it unsquattable:
//   1. a signature by the CURRENT contract's issuer_pubkey, proving the party
//      holding the asset's issuing identity consents to the hand-off; and
//   2. a domain proof from the SUCCESSOR's domain, proving the recipient
//      controls the identity being claimed.
// Neither alone suffices: without (1) anyone could rename someone else's asset,
// and without (2) an issuer could hand its asset to a domain it does not own.
const SUCCESSION_PREFIX = 'sequentia-asset-succession:v1';

function successionMessage(assetId, newContract) {
  return `${SUCCESSION_PREFIX}:${assetId}:${contractHash(newContract)}`;
}

// Build an SPKI DER around a compressed secp256k1 point so Node's own crypto
// can verify with it; this repo has no dependencies to lean on.
function spkiFromCompressedPubkey(hex) {
  const pub = Buffer.from(hex, 'hex');
  if (pub.length !== 33) throw httpErr(400, 'issuer_pubkey must be a 33-byte compressed key to authorize a succession');
  const algo = Buffer.from('301006072a8648ce3d020106052b8104000a', 'hex'); // ecPublicKey + secp256k1
  const bits = Buffer.concat([Buffer.from([0x03, pub.length + 1, 0x00]), pub]);
  const inner = Buffer.concat([algo, bits]);
  return Buffer.concat([Buffer.from([0x30, inner.length]), inner]);
}

function verifySuccessionSignature(pubkeyHex, message, sigHex) {
  let key;
  try {
    key = crypto.createPublicKey({ key: spkiFromCompressedPubkey(pubkeyHex), format: 'der', type: 'spki' });
  } catch (e) {
    if (e.status) throw e;
    throw httpErr(400, `issuer_pubkey is not a usable secp256k1 key: ${e.message}`);
  }
  const sig = Buffer.from(String(sigHex), 'hex');
  if (!sig.length) throw httpErr(400, 'signature: DER hex expected');
  return crypto.verify('sha256', Buffer.from(message, 'utf8'), key, sig);
}

// Replace an entry's display metadata, keeping its chain-verified original.
async function succeed(assetId, newContract, signatureHex) {
  if (!ASSET_RE.test(assetId)) throw httpErr(400, 'asset_id: 64-hex');
  const entry = readEntry(assetId);
  if (!entry) throw httpErr(404, 'not found');
  const cerrs = validateContract(newContract);
  if (cerrs.length) throw httpErr(400, 'invalid contract: ' + cerrs.join('; '));

  // Precision is not display metadata: it is committed on chain in the
  // issuance's denomination and consumers convert amounts with it, so a
  // successor that changed it would silently misprice every balance.
  if (newContract.precision !== entry.contract.precision) {
    throw httpErr(400, `precision cannot change in a succession (asset is ${entry.contract.precision})`);
  }
  assertTickerAvailable(newContract.ticker, assetId);

  const current = entry.contract;
  if (typeof signatureHex !== 'string' || !signatureHex.length) throw httpErr(400, 'signature required');
  const message = successionMessage(assetId, newContract);
  if (!verifySuccessionSignature(current.issuer_pubkey, message, signatureHex)) {
    throw httpErr(403, 'signature does not verify against the current issuer_pubkey');
  }

  let proof_url = entry.proof_url;
  let verified_domain = entry.verified_domain;
  if (REQUIRE_DOMAIN_PROOF) {
    proof_url = await verifyDomainProof(newContract.entity.domain, assetId);
    verified_domain = true;
  }

  // The original contract and its hash stay exactly as issued: the chain
  // binding is to those bytes and must stay checkable forever.
  const succession = {
    at: new Date().toISOString(),
    from: { name: current.name, ticker: current.ticker, domain: current.entity.domain, issuer_pubkey: current.issuer_pubkey },
    to: { name: newContract.name, ticker: newContract.ticker, domain: newContract.entity.domain, issuer_pubkey: newContract.issuer_pubkey },
    message,
    signature: signatureHex,
  };
  entry.origin_contract = entry.origin_contract || current;
  entry.contract = newContract;
  entry.successions = (entry.successions || []).concat([succession]);
  entry.verified_domain = verified_domain;
  entry.proof_url = proof_url;
  entry.verified = entry.verified_chain && (verified_domain || !REQUIRE_DOMAIN_PROOF);
  writeEntry(entry);
  return entry;
}

// Liquid-style minimal index consumed by the explorer/wallet/GUI:
//   id -> [domain, ticker, name, precision, verified]
// The 5th element (verified: 1/0) is appended (HIGH-5) so consumers (the node's
// asset-registry client) can distinguish chain+domain-verified entries from
// unverified legacy/seed labels. Older consumers that only read v[0..3] are
// unaffected.
function minimalIndex() {
  const out = {};
  // v[5] is the supervision flag: 1 when the issuer of this asset can freeze
  // holders of it by consensus rule. It rides in the minimal index rather than
  // only the full entry because this is the file every wallet and the DEX load
  // at startup, and a holder has to be told BEFORE they accept the asset, not
  // when a transfer fails. Absent or 0 means not supervised, so older consumers
  // that read only v[0..4] are unaffected.
  for (const e of allEntries()) {
    out[e.asset_id] = [
      e.contract.entity.domain, e.contract.ticker, e.contract.name,
      e.contract.precision, e.verified ? 1 : 0,
      (e.supervision && e.supervision.supervised) ? 1 : 0,
    ];
  }
  return out;
}
function fullIndex() { const out = {}; for (const e of allEntries()) out[e.asset_id] = e; return out; }

function httpErr(status, message) { const e = new Error(message); e.status = status; return e; }

// ---------- ticker uniqueness (HIGH-4) ----------
// Tickers are claimed first-come; comparison is case-insensitive. These legacy
// demo tickers are reserved so no later registration can squat on them (their
// own seeded entries are the only holders).
const RESERVED_TICKERS = new Set(
  ['tSEQ', 'USDX', 'EURX', 'GOLD', 'WBTC', 'SILVR', 'OILX'].map(t => t.toLowerCase())
);
// Returns the asset_id currently holding `ticker` (case-insensitive), or null.
function tickerOwner(ticker) {
  const t = String(ticker).toLowerCase();
  for (const e of allEntries()) {
    if (e && e.contract && typeof e.contract.ticker === 'string' && e.contract.ticker.toLowerCase() === t) {
      return e.asset_id;
    }
  }
  return null;
}
// Throw HTTP 409 if `ticker` is already claimed by a DIFFERENT asset, or is a
// reserved legacy demo ticker not (yet) owned by this asset.
function assertTickerAvailable(ticker, assetId) {
  const t = String(ticker).toLowerCase();
  const owner = tickerOwner(ticker);
  if (owner && owner !== assetId) throw httpErr(409, `ticker '${ticker}' is already registered to a different asset`);
  if (!owner && RESERVED_TICKERS.has(t)) throw httpErr(409, `ticker '${ticker}' is reserved`);
}

// ---------- registration ----------
async function register(assetId, contract, opts = {}) {
  if (!ASSET_RE.test(assetId)) throw httpErr(400, 'asset_id: 64-hex');
  const cerrs = validateContract(contract);
  if (cerrs.length) throw httpErr(400, 'invalid contract: ' + cerrs.join('; '));
  const ch = contractHash(contract);

  // HIGH-4: tickers are unique (case-insensitive); reject squatting and reserved
  // legacy tickers. Re-registering the SAME asset (refresh) keeps its ticker.
  assertTickerAvailable(contract.ticker, assetId);

  let issuance_txid = null, verified_chain = false, supervision = null;

  // Supervision is read from the chain even for a LEGACY entry, and that is
  // deliberate. Whether an asset's issuer can freeze its holders is an
  // objective fact about the chain; whether the issuer proved control of a
  // domain is a different question entirely. Withholding the first because the
  // second failed would leave a holder of an unverified asset less informed
  // than a holder of a verified one, which is exactly backwards: the
  // unverified asset is the one to be careful with.
  //
  // Best effort, because a legacy entry must still register when electrs is
  // unreachable. Left null when it cannot be determined, which reads as
  // "unknown" rather than "no".
  if (opts.legacy) {
    try {
      const oc = await onChainContract(assetId);
      if (oc.supervision && oc.supervision.asset_id === assetId) supervision = oc.supervision;
    } catch (e) { /* unknown, not "no" */ }
  }

  if (!opts.legacy) {
    const oc = await onChainContract(assetId);
    issuance_txid = oc.issuance_txid;
    supervision = oc.supervision;
    if (oc.contract_hash !== ch)
      throw httpErr(400, `contract does not match on-chain commitment: on-chain contract_hash=${oc.contract_hash}, SHA256(contract)=${ch}. The asset must have been issued with this exact contract.`);
    // MED-3: in addition to the SHA256 contract_hash check, re-derive the asset
    // id from (issuance prevout, contract_hash) and require it equals the
    // submitted asset_id, so a forged electrs reply cannot decouple them.
    // A supervised asset commits its freeze terms as a third leaf, so the
    // derivation must include them or it will not reproduce the id. This is
    // also what makes the supervision fields below trustworthy: they are the
    // ones the id was derived over, not whatever the declaration output claims.
    const descriptorHash = supervision
      ? supervisionDescriptorHash(supervision.descriptor_hex)
      : null;
    const derived = deriveAssetId(oc.prevout_txid, oc.prevout_vout, oc.contract_hash, descriptorHash);
    if (derived === null) {
      throw httpErr(400, 'could not re-derive asset id from issuance prevout (incomplete on-chain data)');
    }
    if (supervision && supervision.asset_id !== assetId) {
      throw httpErr(400, `supervision declaration names a different asset (${supervision.asset_id})`);
    }
    if (derived !== assetId) {
      throw httpErr(400, `asset id does not match its on-chain derivation: derived=${derived}, submitted=${assetId}`);
    }
    verified_chain = true;
  }

  let proof_url = null, verified_domain = false;
  if (REQUIRE_DOMAIN_PROOF && !opts.skipDomain) {
    proof_url = await verifyDomainProof(contract.entity.domain, assetId);
    verified_domain = true;
  }

  const entry = {
    asset_id: assetId,
    contract,
    contract_hash: ch,
    issuance_txid,
    verified: verified_chain && (verified_domain || !REQUIRE_DOMAIN_PROOF),
    verified_chain,
    verified_domain,
    legacy: !!opts.legacy,
    proof_url,
    // Whether the issuer can freeze holders of this asset. Published because a
    // holder deciding whether to accept it needs to know BEFORE they do, and
    // because every wallet and the DEX read this registry rather than the chain.
    // Null for a legacy entry, where nothing was verified against the chain.
    supervision: supervision ? {
      supervised: true,
      version: supervision.version,
      operational_key: supervision.operational_key,
      recovery_key: supervision.recovery_key,
      pause_allowed: supervision.pause_allowed,
    } : (opts.legacy && !verified_chain ? null : { supervised: false }),
  };
  writeEntry(entry);
  return entry;
}

// ---------- seed legacy/pre-approved assets on first run ----------
function loadSeed() {
  if (!fs.existsSync(SEED_FILE)) return;
  let seed;
  try { seed = JSON.parse(fs.readFileSync(SEED_FILE, 'utf8')); } catch (e) { console.error('[registry] bad seed file:', e.message); return; }
  let n = 0, reconciled = 0;
  for (const s of seed) {
    if (!s.asset_id || !ASSET_RE.test(s.asset_id)) continue;
    // OPERATOR OVERRIDE. A seed entry may carry "operator_verified": true. These
    // are testnet demo assets issued with contract_hash = 0, so they can NEVER pass
    // the cryptographic chain+domain check; the registry OPERATOR vouches for them
    // by fiat instead. This is a deliberate TESTNET convenience and is NOT the model
    // for a public/mainnet network, where `verified` must be earned via POST /
    // (on-chain contract match + .well-known domain proof). The audit trail stays
    // honest: verified_chain and verified_domain remain false, and verified_by
    // records that a human operator (not the chain) vouched.
    const wantVerified = s.operator_verified === true;
    const existing = readEntry(s.asset_id);
    if (existing) {
      // Idempotently reconcile the override on restart (e.g. after a git pull that
      // toggled operator_verified). Only ever touch a LEGACY, non-chain-verified
      // entry, so a properly chain-verified registration can never be overridden.
      if (existing.legacy && !existing.verified_chain && !!existing.verified !== wantVerified) {
        existing.verified = wantVerified;
        existing.verified_by = wantVerified ? 'operator' : null;
        writeEntry(existing);
        reconciled++;
      }
      continue;
    }
    // Seed entries are exempt from validateContract's all-zeros-pubkey and other
    // strict checks (they predate the contract scheme), but we still enforce a
    // well-formed shape and ticker uniqueness (HIGH-4) so a seed can't squat a
    // ticker already owned by a different asset.
    if (!s.contract || typeof s.contract.ticker !== 'string') { console.error(`[registry] seed ${s.asset_id} invalid: missing ticker`); continue; }
    const owner = tickerOwner(s.contract.ticker);
    if (owner && owner !== s.asset_id) { console.error(`[registry] seed ${s.asset_id} skipped: ticker '${s.contract.ticker}' already held by ${owner}`); continue; }
    writeEntry({
      asset_id: s.asset_id, contract: s.contract, contract_hash: contractHash(s.contract),
      issuance_txid: s.issuance_txid || null, verified: wantVerified, verified_chain: false,
      verified_domain: false, legacy: true, proof_url: null,
      verified_by: wantVerified ? 'operator' : null,
    });
    n++;
  }
  if (n) console.log(`[registry] seeded ${n} legacy asset(s)`);
  if (reconciled) console.log(`[registry] reconciled operator_verified on ${reconciled} legacy entry(ies)`);
}

// ---------- HTTP ----------
function send(res, status, obj, type = 'application/json') {
  const body = type === 'application/json' ? JSON.stringify(obj, null, 2) : obj;
  res.writeHead(status, {
    'Content-Type': type,
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Cache-Control': 'public, max-age=30',
  });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let d = ''; req.on('data', c => { d += c; if (d.length > 256 * 1024) req.destroy(); });
    req.on('end', () => resolve(d)); req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, `http://localhost:${PORT}`);
    const p = u.pathname.replace(/\/+$/, '') || '/';
    if (req.method === 'OPTIONS') return send(res, 204, '');

    if (req.method === 'GET' && p === '/') return send(res, 200, allEntries());
    if (req.method === 'GET' && p === '/index.json') return send(res, 200, fullIndex());
    if (req.method === 'GET' && p === '/index.minimal.json') return send(res, 200, minimalIndex());
    if (req.method === 'GET' && p === '/health') return send(res, 200, { ok: true, count: listIds().length, electrs: ELECTRS });

    const m = p.match(/^\/([0-9a-f]{64})$/);
    if (req.method === 'GET' && m) {
      const e = readEntry(m[1]);
      return e ? send(res, 200, e) : send(res, 404, { error: 'not found' });
    }

    // POST /  { asset_id, contract }  -> verify (chain + domain) and register
    if (req.method === 'POST' && p === '/') {
      const body = JSON.parse((await readBody(req)) || '{}');
      const entry = await register(body.asset_id, body.contract, {});
      console.log(`[registry] registered ${entry.asset_id} (${entry.contract.ticker}) verified=${entry.verified}`);
      return send(res, 200, entry);
    }

    // POST /succeed  { asset_id, contract, signature }
    // Hand an asset's public identity to a successor: the current issuer signs
    // the new contract, the successor's domain serves the proof. The asset id,
    // its original contract and its on-chain binding are untouched.
    if (req.method === 'POST' && p === '/succeed') {
      const body = JSON.parse((await readBody(req)) || '{}');
      const entry = await succeed(body.asset_id, body.contract, body.signature);
      const last = entry.successions[entry.successions.length - 1];
      console.log(`[registry] succeeded ${entry.asset_id}: ${last.from.ticker} (${last.from.domain}) -> ${last.to.ticker} (${last.to.domain})`);
      return send(res, 200, entry);
    }

    // POST /admin/seed  (bearer ADMIN_TOKEN) { asset_id, contract, skipDomain? } -> legacy/no-chain entry
    if (req.method === 'POST' && p === '/admin/seed') {
      if (!ADMIN_TOKEN || req.headers.authorization !== `Bearer ${ADMIN_TOKEN}`) return send(res, 403, { error: 'forbidden' });
      const body = JSON.parse((await readBody(req)) || '{}');
      const entry = await register(body.asset_id, body.contract, { legacy: true, skipDomain: true });
      return send(res, 200, entry);
    }

    return send(res, 404, { error: 'not found' });
  } catch (e) {
    send(res, e.status || 500, { error: e.message });
  }
});

loadSeed();
server.listen(PORT, () => console.log(`[registry] Sequentia Asset Registry on :${PORT} (electrs ${ELECTRS}, db ${DB_DIR}, domain-proof=${REQUIRE_DOMAIN_PROOF})`));
