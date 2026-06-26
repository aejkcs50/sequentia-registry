# Sequentia Asset Registry

Our equivalent of the [Blockstream Liquid Asset Registry](https://docs.liquid.net/docs/blockstream-liquid-asset-registry):
a small HTTP service that maps a Sequentia **asset id** to verified, human-readable
metadata (name, ticker, precision, issuer domain). Every Sequentia surface — the
node, the node GUI, the block explorer, and the SWK wallet — fetches labels from
here, so there is a single source of truth instead of hand-maintained lists.

Zero dependencies. Run it with plain Node:

```
node server.js
```

## Trust model

Anyone can submit metadata for an asset, but it is only accepted if **both** checks pass:

1. **Contract binding (on-chain).** An asset's metadata is a *contract* JSON. Its
   `contract_hash = SHA256(canonical-JSON(contract))` must equal the `contract_hash`
   that was committed **on-chain at issuance** (the asset id is derived from it, so
   this binds the metadata to the asset — nobody can register false metadata for an
   asset they didn't issue). The registry verifies this by looking the asset up via
   electrs and comparing the issuance input's `contract_hash`.
2. **Domain proof.** The issuer must publish, at
   `https://<entity.domain>/.well-known/sequentia-asset-proof-<asset_id>`, the line:

   ```
   Authorize linking the domain name <entity.domain> to the Sequentia asset <asset_id>
   ```

## Contract format

```json
{
  "name": "USD Stablecoin",
  "ticker": "USDX",
  "precision": 8,
  "entity": { "domain": "example.com" },
  "issuer_pubkey": "02abc…",     // 33-byte compressed pubkey, hex
  "version": 0
}
```

**Canonical hashing** (issuers must replicate this so the on-chain `contract_hash`
matches): serialize the contract as JSON with object keys sorted lexicographically
and no insignificant whitespace, then `SHA256` the UTF-8 bytes. The issuer passes
that 32-byte hash to `issueasset`/`rawissueasset` (`contract_hash` arg) at issuance.

## API

| Method | Path | Description |
|---|---|---|
| GET | `/` | All registered entries (array) |
| GET | `/<asset_id>` | One entry |
| GET | `/index.json` | `{ asset_id: entry }` |
| GET | `/index.minimal.json` | `{ asset_id: [domain, ticker, name, precision] }` — the format the explorer/wallet/GUI consume |
| GET | `/health` | `{ ok, count, electrs }` |
| POST | `/` | Submit `{ asset_id, contract }` — runs both verifications, then registers |
| POST | `/admin/seed` | (bearer `ADMIN_TOKEN`) add a legacy/pre-approved entry, skipping chain+domain checks |

### Register an asset

```
curl -X POST http://localhost:3005/ \
  -H 'Content-Type: application/json' \
  -d '{"asset_id":"<64-hex>","contract":{"name":"…","ticker":"…","precision":8,"entity":{"domain":"example.com"},"issuer_pubkey":"02…","version":0}}'
```

## Config (env)

| Var | Default | Meaning |
|---|---|---|
| `PORT` | `3005` | listen port |
| `DB_DIR` | `./db` | per-asset JSON store |
| `SEED_FILE` | `./seed/legacy-assets.json` | legacy/pre-approved assets loaded on first run |
| `SEQ_ELECTRS_URL` | `http://127.0.0.1:3003` | explorer API for on-chain lookups |
| `REQUIRE_DOMAIN_PROOF` | `1` | require the `.well-known` proof (`0` to skip, testing only) |
| `ADMIN_TOKEN` | _(unset)_ | enables `POST /admin/seed` |

## Consumers

- **Block explorer / SWK**: point their asset map at `GET /index.minimal.json`
  (same shape as the old `assets.minimal.json`).
- **Node**: `-assetregistryurl=<base>` makes the node periodically fetch
  `/index.minimal.json` and merge it into its asset-metadata store.
- **Node GUI**: fetches the registry directly for asset display.

## Legacy testnet assets

The original testnet demo assets (USDX, EURX, GOLD, WBTC, SILVR, OILX, tSEQ) were
issued without an on-chain contract, so they cannot pass contract verification.
They are seeded from `seed/legacy-assets.json` as **pre-approved, unverified**
entries (`legacy: true`) so their labels still resolve. New assets get full
verification.
