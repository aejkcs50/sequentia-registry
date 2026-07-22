# Sequentia Asset Registry

The asset-metadata service for the Sequentia network. On-chain, a Sequentia asset
is only a 64-hex asset id plus a `contract_hash` commitment; this registry maps
that id to verified, human-readable metadata (name, ticker, precision, issuer
domain), the Sequentia equivalent of the Blockstream Liquid Asset Registry.
Every Sequentia surface (the node, the node GUI, the block explorer, the web
wallet) fetches asset labels from here, so there is a single source of truth
instead of hand-maintained lists.

The whole service is one file, `server.js`, with zero npm dependencies:

```
node server.js
```

> **Testnet software.** Everything here serves the public Sequentia testnet
> (parent chain: Bitcoin testnet4). There is no mainnet.

## Where this fits in the Sequentia ecosystem

| Repo | One-liner |
|---|---|
| [`Sequentia`](https://github.com/GracedEternalKingCabbageMan/Sequentia) | The Sequentia node (`elementsd` fork of Elements 23.3.3): consensus, anchoring, proof of stake, open fee market, plus the canonical protocol documentation in `doc/sequentia/`. |
| [`sequentia-electrs`](https://github.com/GracedEternalKingCabbageMan/sequentia-electrs) | The electrs fork: Rust indexer + Esplora REST API for Sequentia and its Bitcoin testnet4 parent chain. The registry uses it for on-chain verification. |
| [`sequentia-explorer`](https://github.com/GracedEternalKingCabbageMan/sequentia-explorer) | Sequentia block explorer frontend (esplora fork); the indexer lives in sequentia-electrs. Its public server also proxies this registry. |
| [`SWK`](https://github.com/GracedEternalKingCabbageMan/SWK) | Sequentia Wallet Kit: a fork of Blockstream LWK, a Rust wallet library, CLI, and WASM bindings for building Sequentia (and Bitcoin testnet4) wallets. |
| [`sequentia-web-wallet`](https://github.com/GracedEternalKingCabbageMan/sequentia-web-wallet) | Proof-of-concept browser wallet built on SWK, live at https://sequentiatestnet.com/wallet. Reads its asset labels from this registry. |
| [`openamp`](https://github.com/GracedEternalKingCabbageMan/openamp) | OpenAMP: open-source restricted-asset issuance/transfer-approval service (an AMP2 equivalent) with opt-in confidentiality; zero consensus changes. Restricted assets carry an `openamp` block in their registry contract. |

Umbrella protocol documentation:
[`Sequentia/doc/sequentia/`](https://github.com/GracedEternalKingCabbageMan/Sequentia/tree/claude/sequentia-bitcoin-sidechain-w6xady/doc/sequentia).

## Status and live instance

A public instance serves the current testnet at:

```
https://sequentiatestnet.com/registry/
```

(The explorer's public server proxies the `/registry` path to the registry
process; see `serve-public.js` in
[sequentia-explorer](https://github.com/GracedEternalKingCabbageMan/sequentia-explorer).)

Quick check:

```
curl -s https://sequentiatestnet.com/registry/health
curl -s https://sequentiatestnet.com/registry/index.minimal.json
```

The service is functional today: the full verification pipeline (on-chain
contract binding, asset-id re-derivation, domain proof, ticker uniqueness) is
implemented and enforced for new registrations. Current limitation: the node
fetches the index over plain HTTP with no signature, so labels are advisory to
consumers (see "Trust model" below).

## Trust model

Anyone can submit metadata for an asset via `POST /`, but it is only stored as
**verified** if all of the following pass:

1. **Contract binding (on-chain).** An asset's metadata is a *contract* JSON.
   Its `contract_hash = SHA256(canonical-JSON(contract))` must equal the
   `contract_hash` committed on-chain in the asset's initial issuance input
   (reissuances are rejected). The registry looks the asset up via electrs
   (`SEQ_ELECTRS_URL`) and compares. Since the asset id is derived from the
   contract hash, nobody can register false metadata for an asset they did not
   issue.
2. **Asset-id re-derivation.** As a defense in depth, the registry re-derives
   the asset id itself from the issuance prevout and the on-chain
   `contract_hash` (Elements' fast-merkle / SHA256-midstate derivation,
   reimplemented in `server.js`; references: `src/issuance.cpp` and
   `src/primitives/txwitness.cpp` in the node repo) and requires it to equal
   the submitted asset id. A forged electrs reply cannot decouple the two.
3. **Domain proof.** The issuer must publish, at
   `https://<entity.domain>/.well-known/sequentia-asset-proof-<asset_id>`,
   a body that is exactly the line:

   ```
   Authorize linking the domain name <entity.domain> to the Sequentia asset <asset_id>
   ```

   The registry fetches this over HTTPS with an SSRF guard (the domain must
   resolve to a public address). The exact-match on the whole body is what
   prevents smuggling the line inside user-generated HTML on a domain the
   issuer does not control. The declared content type may be `text/plain`,
   `application/octet-stream`, or absent — what extensionless files typically
   get — but a response declaring itself anything else (HTML, say) is refused.

Tickers are additionally unique first-come, case-insensitive: a registration
whose ticker is already held by a different asset is rejected with HTTP 409,
and a small set of legacy demo tickers is reserved for the seeded entries
(`RESERVED_TICKERS` in `server.js`).

Entries record the outcome as `verified_chain`, `verified_domain`, and the
combined `verified` flag. Seeded legacy entries (see below) are stored with
`verified: false, legacy: true`.

**Consumer caveat.** The registry's labels are advisory display metadata, not a
cryptographic guarantee to the consumer. In particular the Sequentia node
fetches the index over plain HTTP with no TLS and no signature (the
`-assetregistryurl` help text in the node says the same), so labels must never
be treated as authoritative for value decisions.

## Contract format

```json
{
  "name": "USD Stablecoin",
  "ticker": "USDX",
  "precision": 8,
  "entity": { "domain": "example.com" },
  "issuer_pubkey": "02abc...",
  "version": 0
}
```

Validation rules (from `validateContract` in `server.js`):

| Field | Rule |
|---|---|
| `name` | string, 1..255 chars |
| `ticker` | 1..12 chars of `A-Za-z0-9.-` (mixed case allowed, e.g. `tSEQ`) |
| `precision` | integer 0..8 |
| `entity.domain` | valid DNS domain; no other `entity` fields allowed |
| `issuer_pubkey` | 33-byte compressed pubkey hex, or 32-byte x-only hex (BIP340, used by OpenAMP enclave keys); an all-zeros X coordinate is rejected |
| `version` | must be `0` |
| `openamp` | optional, see below |

Unknown top-level keys are rejected so the canonical hash is well-defined.

**Canonical hashing.** Issuers must replicate this exactly so the on-chain
`contract_hash` matches: serialize the contract as JSON with object keys sorted
lexicographically and no insignificant whitespace, then SHA256 the UTF-8 bytes.

### Optional `openamp` block (restricted assets)

OpenAMP restricted assets embed their policy binding in the contract, so the
on-chain `contract_hash` commits to it:

```json
"openamp": {
  "version": 1,
  "type": "restricted",
  "policy_pubkey": "<32-byte x-only hex (FROST group key)>",
  "clawback": true,
  "confidential": false,
  "policy_endpoints": ["https://sequentiatestnet.com/openamp/"]
}
```

Rules: `version` integer >= 1; `type` is `"restricted"` or `"tracked"`;
`policy_pubkey` is 32-byte x-only hex; `clawback` boolean; optional
`burn_allowed` and `confidential` booleans; optional `policy_endpoints` array
of https URLs; optional `terms_hash`. See
[`openamp/spec/contract-v1.md`](https://github.com/GracedEternalKingCabbageMan/openamp/blob/main/spec/contract-v1.md)
for the full semantics. The seeded BONDX demo asset is an example.

## API

Base URL: `https://sequentiatestnet.com/registry` (public testnet instance) or
`http://localhost:3005` (local run). All responses are JSON with
`Access-Control-Allow-Origin: *` and `Cache-Control: public, max-age=30`.
Errors are `{ "error": "<message>" }` with an appropriate 4xx/5xx status.

| Method | Path | Description |
|---|---|---|
| GET | `/` | All registered entries (array) |
| GET | `/<asset_id>` | One entry (404 if unknown) |
| GET | `/index.json` | `{ asset_id: entry }` |
| GET | `/index.minimal.json` | `{ asset_id: [domain, ticker, name, precision, verified] }`, the format consumers use |
| GET | `/health` | `{ ok, count, electrs }` |
| POST | `/` | Submit `{ asset_id, contract }`: runs all verifications, then registers |
| POST | `/admin/seed` | (bearer `ADMIN_TOKEN`) add a pre-approved entry, skipping chain and domain checks |

`index.minimal.json` entry example (live):

```json
"8d1dbf45af45dd18eac10215efb86386695b9c4122ce6f4c18e03fea155e86c7": [
  "sequentiatestnet.com", "BONDX", "OpenAMP Demo Bond", 8, 0
]
```

The 5th element is the `verified` flag (1/0). Consumers that only read
elements 0..3 (the old Liquid `assets.minimal.json` shape) are unaffected.

A full entry (`GET /<asset_id>`) looks like:

```json
{
  "asset_id": "<64-hex>",
  "contract": { "...": "the contract JSON" },
  "contract_hash": "<64-hex>",
  "issuance_txid": "<64-hex or null for seeded entries>",
  "verified": true,
  "verified_chain": true,
  "verified_domain": true,
  "legacy": false,
  "proof_url": "https://<domain>/.well-known/sequentia-asset-proof-<asset_id>"
}
```

Request bodies are capped at 256 KB. POST failure statuses: 400 (validation,
chain mismatch, domain-proof failure), 403 (bad/missing admin token), 409
(ticker already claimed or reserved).

## Registering an asset, step by step

1. **Write the contract JSON** (see "Contract format").

2. **Compute the contract hash** with the same canonicalization the registry
   uses:

   ```
   node -e '
   function c14n(v){if(Array.isArray(v))return"["+v.map(c14n).join(",")+"]";
   if(v&&typeof v==="object")return"{"+Object.keys(v).sort().map(k=>JSON.stringify(k)+":"+c14n(v[k])).join(",")+"}";
   return JSON.stringify(v)}
   const contract={name:"Example Asset",ticker:"EXA",precision:8,entity:{domain:"example.com"},issuer_pubkey:"02...",version:0};
   console.log(require("crypto").createHash("sha256").update(c14n(contract),"utf8").digest("hex"));'
   ```

3. **Issue the asset with that hash committed on-chain**: pass the 64-hex value
   as the `contract_hash` argument of the node's `issueasset` (4th argument) or
   `rawissueasset` RPC. The contract hash affects the asset id, so it must be
   set at issuance; it cannot be added later, and reissuances do not count.

4. **Publish the domain proof** at
   `https://<entity.domain>/.well-known/sequentia-asset-proof-<asset_id>`,
   served raw (plain text; no declared content type is fine), containing
   exactly:

   ```
   Authorize linking the domain name <entity.domain> to the Sequentia asset <asset_id>
   ```

5. **Submit the registration**:

   ```
   curl -X POST https://sequentiatestnet.com/registry/ \
     -H 'Content-Type: application/json' \
     -d '{"asset_id":"<64-hex>","contract":{"name":"Example Asset","ticker":"EXA","precision":8,"entity":{"domain":"example.com"},"issuer_pubkey":"02...","version":0}}'
   ```

   The response is the stored entry; check that `verified` is `true`.
   Re-submitting the same asset (a refresh) is allowed and keeps its ticker.

## Consumers

- **Sequentia node**: start `elementsd` with `-assetregistryurl=<index url>`;
  the node fetches the minimal index shortly after startup and then every
  `-assetregistrypoll` seconds (default 300) and merges the tickers of
  **verified** entries into its asset directory (RPC output and the GUI).
  Unverified/legacy entries are skipped by the node. On the public testnet the
  node defaults this to the live registry index. Operator `-assetdir` entries
  always take precedence. See `src/assetregistry.{h,cpp}` in the
  [Sequentia](https://github.com/GracedEternalKingCabbageMan/Sequentia) repo.
- **Block explorer**: the explorer's public server proxies `/registry` to this
  service, and the `sequentia-testnet` flavor defaults its asset map
  (`ASSET_MAP_URL`) to `/registry/index.minimal.json`.
- **Web wallet**: fetches `/registry/index.minimal.json` (override with
  `window.SEQ_REGISTRY_URL`).
- **OpenAMP wallets**: discover restricted assets here, then verify the
  asset-to-policy binding against the policy server listed in the contract's
  `openamp.policy_endpoints`.

## Seeded testnet assets

The current public testnet (re-genesis 2026-07-05) demo assets, the Sequence
token (tSEQ) and USDX, EURX, GOLD, SILVR, OILX, were issued with
`contract_hash = 0`, so they can **never** pass cryptographic chain+domain
verification. They are seeded from `seed/legacy-assets.json` on first run
(`legacy: true`) so their labels resolve, alongside the BONDX OpenAMP demo asset
(which does earn verification the normal way). Seeding never overwrites an
existing entry's contract and still enforces ticker uniqueness.

### Operator override (`operator_verified`)

A seed entry may set `"operator_verified": true`. The registry **operator** then
vouches for that entry by fiat: `loadSeed` sets the consumer-facing `verified: 1`
and records `verified_by: "operator"`, while `verified_chain` and
`verified_domain` stay `false` so the audit trail never claims a cryptographic
proof that does not exist. This is reconciled idempotently on every restart (a
`git pull` that toggles the flag takes effect on the next boot), and it only ever
touches `legacy` entries that are not chain-verified, so a properly registered
asset can never be silently overridden.

**This is a testnet convenience only.** On a public or mainnet network, `verified`
must be earned through `POST /` (on-chain contract match + `.well-known` domain
proof); an operator override is a deliberate trust shortcut appropriate only when
the operator issued the demo assets themselves and no real contract exists to
verify against. The six testnet demo assets above use it because they predate the
contract scheme; every asset issued with a real `contract_hash` should verify
cryptographically instead.

## Running locally

Requirements: Node.js (no npm install needed; the server uses only Node
built-ins).

```
git clone https://github.com/GracedEternalKingCabbageMan/sequentia-registry.git
cd sequentia-registry
node server.js
```

On first run the server seeds the testnet assets and listens on port 3005.
Smoke-test it:

```
curl -s http://localhost:3005/health
curl -s http://localhost:3005/index.minimal.json
```

Chain verification needs a reachable Sequentia electrs instance
(`SEQ_ELECTRS_URL`, default `http://127.0.0.1:3003`, treated as trusted and
exempt from the SSRF guard). For local development without a domain, set
`REQUIRE_DOMAIN_PROOF=0` to skip the domain-proof check (testing only; the
chain check still runs). To bypass both checks for a hand-approved entry, set
`ADMIN_TOKEN` and use `POST /admin/seed` with `Authorization: Bearer <token>`.

### Config (env)

| Var | Default | Meaning |
|---|---|---|
| `PORT` | `3005` | listen port |
| `DB_DIR` | `./db` | per-asset JSON store |
| `SEED_FILE` | `./seed/legacy-assets.json` | pre-approved assets loaded on first run |
| `SEQ_ELECTRS_URL` | `http://127.0.0.1:3003` | esplora-API base for on-chain lookups |
| `REQUIRE_DOMAIN_PROOF` | `1` | require the `.well-known` proof (`0` to skip, testing only) |
| `PROOF_FETCH_TIMEOUT` | `8000` | ms timeout for the domain-proof fetch |
| `ADMIN_TOKEN` | (unset) | enables `POST /admin/seed` |

### Storage format

The store is a flat directory of JSON files, one per asset:
`<DB_DIR>/<asset_id>.json`, each containing the full entry shown under "API".
There is no database server; back up or migrate the registry by copying the
directory.

## For contributors

Repo layout:

- `server.js`: the entire service (HTTP API, canonical-JSON hashing, asset-id
  derivation, electrs lookups, domain-proof fetch with SSRF guard, flat-file
  store, seeding).
- `seed/legacy-assets.json`: pre-approved entries loaded on first run.

There is no automated test suite; verify changes with the smoke commands above
(and, for verification-path changes, against a local electrs). Open PRs against
the `main` branch.
