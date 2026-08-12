#!/usr/bin/env node
// Sign an asset succession with the current issuer key.
//
// A succession hands an asset's public identity (name, ticker, domain, issuer
// key) to someone else without touching the asset id or its chain-committed
// original contract. The registry only accepts one when the CURRENT issuer
// signs it, which is what this produces; the successor separately proves it
// controls the new domain by serving the .well-known proof.
//
// Usage:
//   sign-succession.js <asset_id> <new-contract.json> <privkey>
//
// <privkey> is the issuer's secp256k1 key as 64-hex or WIF. It is read as an
// argument for convenience in a runbook; on a shared machine prefer piping it
// in via SUCCESSION_PRIVKEY in the environment instead of the command line,
// where it would land in shell history.
//
// Prints the DER signature as hex, which is what POST /succeed expects.

const crypto = require('crypto');
const fs = require('fs');

// ---- WIF decoding (base58check), so the key can come straight from a wallet.
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58decode(s) {
  let num = 0n;
  for (const ch of s) {
    const v = B58.indexOf(ch);
    if (v < 0) throw new Error('not base58');
    num = num * 58n + BigInt(v);
  }
  let hex = num.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  let bytes = Buffer.from(hex, 'hex');
  let leading = 0;
  for (const ch of s) { if (ch === '1') leading++; else break; }
  return Buffer.concat([Buffer.alloc(leading), bytes]);
}
function privkeyFrom(input) {
  const s = String(input).trim();
  if (/^[0-9a-fA-F]{64}$/.test(s)) return Buffer.from(s, 'hex');
  const raw = b58decode(s);
  if (raw.length < 37) throw new Error('WIF too short');
  const body = raw.subarray(0, raw.length - 4);
  const csum = raw.subarray(raw.length - 4);
  const want = crypto.createHash('sha256').update(crypto.createHash('sha256').update(body).digest()).digest().subarray(0, 4);
  if (!csum.equals(want)) throw new Error('WIF checksum mismatch');
  // body = version || key32 || [0x01 if compressed]
  const key = body.subarray(1, 33);
  if (key.length !== 32) throw new Error('WIF payload is not a 32-byte key');
  return key;
}

// ---- canonical contract hash, byte-identical to the registry's
function canonicalize(v) {
  if (Array.isArray(v)) return '[' + v.map(canonicalize).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}
const contractHash = (c) => crypto.createHash('sha256').update(canonicalize(c), 'utf8').digest('hex');

// ---- a SEC1 EC private key DER, so Node can sign with a raw 32-byte scalar
function sec1FromPrivkey(key32) {
  const header = Buffer.from('30740201010420', 'hex'); // SEQUENCE, version 1, OCTET STRING(32)
  const curve = Buffer.from('a00706052b8104000a', 'hex'); // [0] secp256k1
  // No public key element: Node derives it.
  const body = Buffer.concat([Buffer.from('020101', 'hex'), Buffer.from('0420', 'hex'), key32, curve]);
  const der = Buffer.concat([Buffer.from([0x30, body.length]), body]);
  void header;
  return der;
}

function main() {
  const [assetId, contractFile, keyArg] = process.argv.slice(2);
  const key = process.env.SUCCESSION_PRIVKEY || keyArg;
  if (!assetId || !contractFile || !key) {
    console.error('usage: sign-succession.js <asset_id> <new-contract.json> <privkey|WIF>');
    console.error('       (or set SUCCESSION_PRIVKEY and omit the last argument)');
    process.exit(2);
  }
  if (!/^[0-9a-f]{64}$/.test(assetId)) {
    console.error('asset_id must be 64 hex characters');
    process.exit(2);
  }
  const contract = JSON.parse(fs.readFileSync(contractFile, 'utf8'));
  const message = `sequentia-asset-succession:v1:${assetId}:${contractHash(contract)}`;
  const priv = crypto.createPrivateKey({ key: sec1FromPrivkey(privkeyFrom(key)), format: 'der', type: 'sec1' });
  const sig = crypto.sign('sha256', Buffer.from(message, 'utf8'), priv);
  process.stderr.write(`message: ${message}\n`);
  process.stdout.write(sig.toString('hex') + '\n');
}

main();
