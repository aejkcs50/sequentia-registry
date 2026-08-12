#!/usr/bin/env node
// Smoke test for asset succession, the hand-off of an asset's public identity
// from the party that issued it to the party that adopts it.
//
// This repo has no test suite and no dependencies, so this is a self-contained
// script: it starts a registry against a temporary DB with domain proofs off,
// seeds an entry, and exercises succession end to end, including the refusals
// that make the mechanism safe.
//
//   node tools/succession-smoke.js

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const PORT = 3457;
const BASE = `http://127.0.0.1:${PORT}`;
const TOKEN = 'smoke-token';
const DB = fs.mkdtempSync(path.join(os.tmpdir(), 'registry-smoke-'));

let failures = 0;
function check(name, cond, detail = '') {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`);
  if (!cond) failures++;
}

function canonicalize(v) {
  if (Array.isArray(v)) return '[' + v.map(canonicalize).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}
const contractHash = (c) => crypto.createHash('sha256').update(canonicalize(c), 'utf8').digest('hex');

function compressed(publicKey) {
  const jwk = publicKey.export({ format: 'jwk' });
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
  return Buffer.concat([Buffer.from([y[y.length - 1] % 2 ? 3 : 2]), x]).toString('hex');
}

async function api(p, opts) {
  const res = await fetch(`${BASE}${p}`, opts);
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

async function main() {
  const bridge = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  const issuer = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  const assetId = crypto.randomBytes(32).toString('hex');

  const original = {
    name: 'Bridged USDC (Compages)',
    ticker: 'USDC.e',
    precision: 6,
    entity: { domain: 'bridge.example.com' },
    issuer_pubkey: compressed(bridge.publicKey),
    version: 0,
  };
  const successor = {
    name: 'USD Coin',
    ticker: 'USDC',
    precision: 6,
    entity: { domain: 'issuer.example.com' },
    issuer_pubkey: compressed(issuer.publicKey),
    version: 0,
  };

  const srv = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
    env: { ...process.env, PORT: String(PORT), DB_DIR: DB, SEED_FILE: '/dev/null', ADMIN_TOKEN: TOKEN, REQUIRE_DOMAIN_PROOF: '0', SEQ_ELECTRS_URL: 'http://127.0.0.1:1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const done = new Promise((r) => srv.on('exit', r));
  try {
    for (let i = 0; i < 80; i++) {
      try { await fetch(`${BASE}/health`); break; } catch { await new Promise(r => setTimeout(r, 100)); }
    }

    // Seed the bridged asset (the admin path stands in for a real chain-verified
    // registration; succession behaves the same either way).
    const seeded = await api('/admin/seed', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${TOKEN}` },
      body: JSON.stringify({ asset_id: assetId, contract: original }),
    });
    check('bridged asset registers', seeded.status === 200, `${seeded.status}`);

    const sign = (key, contract) =>
      crypto.sign('sha256', Buffer.from(`sequentia-asset-succession:v1:${assetId}:${contractHash(contract)}`, 'utf8'), key).toString('hex');

    // A succession signed by the WRONG key must be refused: otherwise anyone
    // could rename an asset they do not control.
    const forged = await api('/succeed', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ asset_id: assetId, contract: successor, signature: sign(issuer.privateKey, successor) }),
    });
    check('a succession signed by the wrong key is refused', forged.status === 403, `${forged.status}`);

    // A signature over a DIFFERENT contract must not authorize this one.
    const swapped = await api('/succeed', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ asset_id: assetId, contract: successor, signature: sign(bridge.privateKey, { ...successor, ticker: 'OTHER' }) }),
    });
    check('a signature over different metadata does not authorize this one', swapped.status === 403, `${swapped.status}`);

    // Precision is chain-committed and consumers convert amounts with it.
    const reprecision = await api('/succeed', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        asset_id: assetId,
        contract: { ...successor, precision: 8 },
        signature: sign(bridge.privateKey, { ...successor, precision: 8 }),
      }),
    });
    check('a succession cannot change precision', reprecision.status === 400, `${reprecision.status}`);

    // The real thing.
    const ok = await api('/succeed', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ asset_id: assetId, contract: successor, signature: sign(bridge.privateKey, successor) }),
    });
    check('the current issuer can hand the identity on', ok.status === 200, `${ok.status} ${ok.body.error ?? ''}`);
    check('display metadata is now the successor\'s', ok.body.contract?.ticker === 'USDC' && ok.body.contract?.name === 'USD Coin', ok.body.contract?.ticker);
    check('the original contract is preserved', ok.body.origin_contract?.ticker === 'USDC.e', ok.body.origin_contract?.ticker);
    check('the on-chain contract hash is untouched', ok.body.contract_hash === seeded.body.contract_hash, ok.body.contract_hash?.slice(0, 12));
    check('the hand-off is recorded', ok.body.successions?.length === 1 && ok.body.successions[0].from.ticker === 'USDC.e' && ok.body.successions[0].to.ticker === 'USDC');

    // Consumers see the new identity under the same asset id.
    const idx = await api('/index.minimal.json');
    const row = idx.body[assetId];
    check('the minimal index serves the successor identity', row?.[1] === 'USDC' && row?.[0] === 'issuer.example.com', JSON.stringify(row));

    // The new issuer, not the old one, controls the next hand-off.
    const third = { ...successor, ticker: 'USDC2', entity: { domain: 'third.example.com' } };
    const staleKey = await api('/succeed', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ asset_id: assetId, contract: third, signature: sign(bridge.privateKey, third) }),
    });
    check('the previous issuer can no longer hand it on', staleKey.status === 403, `${staleKey.status}`);
    const newKey = await api('/succeed', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ asset_id: assetId, contract: third, signature: sign(issuer.privateKey, third) }),
    });
    check('the current issuer can', newKey.status === 200, `${newKey.status}`);
    check('every hand-off is kept, not overwritten', newKey.body.successions?.length === 2, `${newKey.body.successions?.length}`);
    check('the original contract survives repeated hand-offs', newKey.body.origin_contract?.ticker === 'USDC.e');
  } finally {
    srv.kill();
    await done;
    fs.rmSync(DB, { recursive: true, force: true });
  }

  console.log(failures ? `\n${failures} CHECK(S) FAILED` : '\nALL CHECKS PASSED');
  process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
