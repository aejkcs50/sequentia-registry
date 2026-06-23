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
  if (c.version !== 0) errs.push('version: must be 0');
  // Reject unknown top-level keys so the canonical hash is well-defined.
  const allowed = new Set(['name', 'ticker', 'precision', 'entity', 'issuer_pubkey', 'version']);
  for (const k of Object.keys(c)) if (!allowed.has(k)) errs.push(`unexpected field: ${k}`);
  if (c.entity) for (const k of Object.keys(c.entity)) if (k !== 'domain') errs.push(`unexpected entity field: ${k}`);
  return errs;
}

// ---------- tiny fetch (http/https GET -> {status, body}) ----------
function fetchUrl(u, timeout = PROOF_TIMEOUT) {
  return new Promise((resolve, reject) => {
    let mod, opts;
    try { const url = new URL(u); mod = url.protocol === 'https:' ? https : http; opts = url; }
    catch (e) { return reject(new Error('bad url')); }
    const req = mod.get(opts, res => {
      let data = '';
      res.on('data', d => { data += d; if (data.length > 1_000_000) req.destroy(); });
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', reject);
    req.setTimeout(timeout, () => req.destroy(new Error('timeout')));
  });
}

// ---------- on-chain verification (via electrs) ----------
// Returns { contract_hash, issuance_txid } for a NEW issuance, or throws.
async function onChainContract(assetId) {
  const a = await fetchUrl(`${ELECTRS}/asset/${assetId}`);
  if (a.status !== 200) throw httpErr(400, `asset ${assetId} not found on chain (electrs ${a.status})`);
  const asset = JSON.parse(a.body);
  const itx = asset.issuance_txin;
  if (!itx || !itx.txid) throw httpErr(400, 'asset has no issuance on chain');
  const t = await fetchUrl(`${ELECTRS}/tx/${itx.txid}`);
  if (t.status !== 200) throw httpErr(400, `issuance tx not found (electrs ${t.status})`);
  const tx = JSON.parse(t.body);
  const vin = (tx.vin || [])[itx.vin];
  const iss = vin && vin.issuance;
  if (!iss) throw httpErr(400, 'issuance input not found in issuance tx');
  if (iss.is_reissuance) throw httpErr(400, 'issuance input is a reissuance, not the initial issuance');
  return { contract_hash: iss.contract_hash, issuance_txid: itx.txid };
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
  if (!r.body.includes(proofText(domain, assetId))) throw httpErr(400, `domain proof at ${url} does not contain the authorization line`);
  return url;
}

// ---------- store ----------
function entryPath(id) { return path.join(DB_DIR, `${id}.json`); }
function listIds() { return fs.readdirSync(DB_DIR).filter(f => f.endsWith('.json')).map(f => f.slice(0, -5)).filter(id => ASSET_RE.test(id)); }
function readEntry(id) { try { return JSON.parse(fs.readFileSync(entryPath(id), 'utf8')); } catch (e) { return null; } }
function writeEntry(e) { fs.writeFileSync(entryPath(e.asset_id), JSON.stringify(e, null, 2)); }
function allEntries() { return listIds().map(readEntry).filter(Boolean); }
// Liquid-style minimal index consumed by the explorer/wallet/GUI: id -> [domain, ticker, name, precision]
function minimalIndex() {
  const out = {};
  for (const e of allEntries()) out[e.asset_id] = [e.contract.entity.domain, e.contract.ticker, e.contract.name, e.contract.precision];
  return out;
}
function fullIndex() { const out = {}; for (const e of allEntries()) out[e.asset_id] = e; return out; }

function httpErr(status, message) { const e = new Error(message); e.status = status; return e; }

// ---------- registration ----------
async function register(assetId, contract, opts = {}) {
  if (!ASSET_RE.test(assetId)) throw httpErr(400, 'asset_id: 64-hex');
  const cerrs = validateContract(contract);
  if (cerrs.length) throw httpErr(400, 'invalid contract: ' + cerrs.join('; '));
  const ch = contractHash(contract);

  let issuance_txid = null, verified_chain = false;
  if (!opts.legacy) {
    const oc = await onChainContract(assetId);
    issuance_txid = oc.issuance_txid;
    if (oc.contract_hash !== ch)
      throw httpErr(400, `contract does not match on-chain commitment: on-chain contract_hash=${oc.contract_hash}, SHA256(contract)=${ch}. The asset must have been issued with this exact contract.`);
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
    const cerrs = validateContract(s.contract);
    if (cerrs.length) { console.error(`[registry] seed ${s.asset_id} invalid:`, cerrs.join('; ')); continue; }
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
