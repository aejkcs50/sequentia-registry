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
 * Trust model (full Liquid parity):
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
function deriveAssetId(prevoutTxid, prevoutVout, contractHashHex) {
  if (!/^[0-9a-f]{64}$/.test(prevoutTxid || '')) return null;
  if (!/^[0-9a-f]{64}$/.test(contractHashHex || '')) return null;
  if (!Number.isInteger(prevoutVout) || prevoutVout < 0 || prevoutVout > 0xffffffff) return null;
  // electrs reports txids in display (reversed) order; COutPoint serialises the
  // internal (little-endian) byte order, so reverse the displayed txid.
  const txidInternal = Buffer.from(prevoutTxid, 'hex').reverse();
  const vout = Buffer.alloc(4); vout.writeUInt32LE(prevoutVout, 0);
  const outpoint = Buffer.concat([txidInternal, vout]);
  // SerializeHash() is a DOUBLE SHA256 (CHashWriter::GetHash), not a single one.
  const sha = (b) => crypto.createHash('sha256').update(b).digest();
  const leafPrevout = sha(sha(outpoint));
  // The on-chain contract_hash matches Node's SHA256(canonical-JSON(contract))
  // byte-for-byte (the same value the existing check compares), so its raw bytes
  // are used directly as the merkle leaf (the internal uint256 order).
  const entropy = merkleNode(leafPrevout, Buffer.from(contractHashHex, 'hex'));
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
  if (typeof c.issuer_pubkey !== 'string' || !PUBKEY_RE.test(c.issuer_pubkey)) errs.push('issuer_pubkey: 33-byte hex');
  // Reject any pubkey whose 32-byte X coordinate is all zeros: that is not a
  // valid curve point and is the all-zeros placeholder used by the legacy demo
  // seed (HIGH-5). Also reject the trivially-invalid all-zeros 33 bytes.
  else if (/^[0-9a-f]{2}0{64}$/i.test(c.issuer_pubkey)) errs.push('issuer_pubkey: must not have an all-zeros X coordinate (placeholder)');
  if (c.version !== 0) errs.push('version: must be 0');
  // Reject unknown top-level keys so the canonical hash is well-defined.
  const allowed = new Set(['name', 'ticker', 'precision', 'entity', 'issuer_pubkey', 'version']);
  for (const k of Object.keys(c)) if (!allowed.has(k)) errs.push(`unexpected field: ${k}`);
  if (c.entity) for (const k of Object.keys(c.entity)) if (k !== 'domain') errs.push(`unexpected entity field: ${k}`);
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
  // The issuance input's prevout is what binds the asset id (MED-3).
  return {
    contract_hash: iss.contract_hash,
    issuance_txid: itx.txid,
    prevout_txid: vin.txid,
    prevout_vout: vin.vout,
  };
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
  // Require text/plain so an attacker can't smuggle the line inside an HTML page
  // (e.g. a user-content page) they don't actually control as the proof endpoint.
  const ct = (r.contentType || '').split(';')[0].trim().toLowerCase();
  if (ct !== 'text/plain') throw httpErr(400, `domain proof at ${url} must be served as text/plain (got '${r.contentType || 'none'}')`);
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
// Liquid-style minimal index consumed by the explorer/wallet/GUI:
//   id -> [domain, ticker, name, precision, verified]
// The 5th element (verified: 1/0) is appended (HIGH-5) so consumers (the node's
// asset-registry client) can distinguish chain+domain-verified entries from
// unverified legacy/seed labels. Older consumers that only read v[0..3] are
// unaffected.
function minimalIndex() {
  const out = {};
  for (const e of allEntries()) out[e.asset_id] = [e.contract.entity.domain, e.contract.ticker, e.contract.name, e.contract.precision, e.verified ? 1 : 0];
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

  let issuance_txid = null, verified_chain = false;
  if (!opts.legacy) {
    const oc = await onChainContract(assetId);
    issuance_txid = oc.issuance_txid;
    if (oc.contract_hash !== ch)
      throw httpErr(400, `contract does not match on-chain commitment: on-chain contract_hash=${oc.contract_hash}, SHA256(contract)=${ch}. The asset must have been issued with this exact contract.`);
    // MED-3: in addition to the SHA256 contract_hash check, re-derive the asset
    // id from (issuance prevout, contract_hash) and require it equals the
    // submitted asset_id, so a forged electrs reply cannot decouple them.
    const derived = deriveAssetId(oc.prevout_txid, oc.prevout_vout, oc.contract_hash);
    if (derived === null) {
      throw httpErr(400, 'could not re-derive asset id from issuance prevout (incomplete on-chain data)');
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
  };
  writeEntry(entry);
  return entry;
}

// ---------- seed legacy/pre-approved assets on first run ----------
function loadSeed() {
  if (!fs.existsSync(SEED_FILE)) return;
  let seed;
  try { seed = JSON.parse(fs.readFileSync(SEED_FILE, 'utf8')); } catch (e) { console.error('[registry] bad seed file:', e.message); return; }
  let n = 0;
  for (const s of seed) {
    if (!s.asset_id || !ASSET_RE.test(s.asset_id) || readEntry(s.asset_id)) continue;
    // Seed entries are exempt from validateContract's all-zeros-pubkey and other
    // strict checks (they predate the contract scheme), but we still enforce a
    // well-formed shape and ticker uniqueness (HIGH-4) so a seed can't squat a
    // ticker already owned by a different asset.
    if (!s.contract || typeof s.contract.ticker !== 'string') { console.error(`[registry] seed ${s.asset_id} invalid: missing ticker`); continue; }
    const owner = tickerOwner(s.contract.ticker);
    if (owner && owner !== s.asset_id) { console.error(`[registry] seed ${s.asset_id} skipped: ticker '${s.contract.ticker}' already held by ${owner}`); continue; }
    writeEntry({
      asset_id: s.asset_id, contract: s.contract, contract_hash: contractHash(s.contract),
      issuance_txid: s.issuance_txid || null, verified: false, verified_chain: false,
      verified_domain: false, legacy: true, proof_url: null,
    });
    n++;
  }
  if (n) console.log(`[registry] seeded ${n} legacy asset(s)`);
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
