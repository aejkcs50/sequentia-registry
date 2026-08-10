# sequentia-registry

The Sequentia Asset Registry: the network's analogue of the Liquid Asset Registry. It maps an
asset id to issuer-published metadata and, where possible, proves that metadata is the same
metadata the asset was issued under.

The whole service is one file, `server.js`, on raw `http.createServer` with **zero
dependencies** — Node built-ins only. There is no `package.json`.

Node and consensus conventions live in the
[`Sequentia`](https://github.com/GracedEternalKingCabbageMan/Sequentia) repo.

## Run

```sh
node server.js                                   # PORT defaults to 3005
curl -s http://localhost:3005/health
curl -s http://localhost:3005/index.minimal.json
```

No `npm install`. **There is no automated test suite** — verify changes with those smoke
commands, and for anything touching the verification path, against a local electrs.

Configuration is environment only: `PORT`, `DB_DIR`, `SEED_FILE`, `SEQ_ELECTRS_URL`,
`REQUIRE_DOMAIN_PROOF`, `PROOF_FETCH_TIMEOUT`, `ADMIN_TOKEN`. `ADMIN_TOKEN` is never written to
disk by the code; if it is unset, `POST /admin/seed` returns 403.

Storage is a flat directory of JSON files, one per asset: `<DB_DIR>/<asset_id>.json`. No
database server.

In production this is reached through the explorer, which proxies `/registry` to it.

## Byte order is where this codebase bleeds

Three separate places reverse byte order, and each one was a real bug:

- electrs prints an issuance `contract_hash` as a uint256 in **display** (reversed) order, but
  the on-chain commitment is `SHA256(canonical JSON)` in **natural** order. Without the reverse
  in `onChainContract()`, a legitimately issued asset never verifies.
- `deriveAssetId()` reverses the displayed txid on the way in, and reverses the derived id back
  to display order on the way out.
- `SerializeHash` is a **double** SHA256, not a single one. Getting that wrong silently breaks
  the asset-id re-derivation check.

If verification suddenly rejects everything or accepts everything, suspect byte order first.

## The all-zero contract case is intentional

Registration via `POST /` runs the full check: the submitted contract must hash to the
commitment recorded on chain, the asset id must re-derive from the issuance prevout and that
hash, and the issuer's domain must serve a matching `.well-known` proof.

Seeded testnet demo assets cannot pass that check at all — they were issued with
`contract_hash = 0`, so there is no on-chain contract to match. They take a separate `legacy`
path that skips `onChainContract()` entirely, and a seed entry may carry
`"operator_verified": true`, which marks it `verified` by operator fiat. The audit trail stays
honest: `verified_chain` and `verified_domain` remain `false` and `verified_by` records that a
human, not the chain, vouched.

This is a deliberate testnet convenience and is documented as such in `server.js` and in
`seed/legacy-assets.json`. Do not "harden" it into rejecting zero-contract assets — the demo
assets depend on it. Equally, do not extend the override to non-legacy entries: the reconcile
branch only ever touches an entry that is both `legacy` and not `verified_chain`, so a genuinely
chain-verified registration can never be downgraded.

## Other things worth knowing before editing

- **Unknown-key rejection in `validateContract` is load-bearing, not pedantry.** The registry has
  to accept the issuer's exact bytes to reproduce the on-chain hash, so both over-strict and
  over-lax key handling break verification. Widen it deliberately, never casually.
- Several checks carry audit-finding labels in comments (`HIGH-4`, `MED-3`). They were added on
  purpose; removing one regresses a finding.
- `tier` was scrapped from the `openamp` block. Do not reintroduce it.
- `SEQ_ELECTRS_URL` is trusted and exempt from the SSRF guard. The guarded fetch is the domain
  proof, which reaches arbitrary issuer-supplied hosts.
- The native token is named **Sequence** (ticker SEQ, tSEQ on testnet). **Sequentia** is the
  network. They are different names; never use "SEQ" to mean the network.
- **There is no `.gitignore` in this repo**, and the live `db/` directory sits untracked at the
  root. A careless `git add -A` would commit registry state. Add paths explicitly.

## Who talks to it

The web wallet POSTs `{asset_id, contract}` to `/` right after issuing an asset, and retries for
several minutes: a fresh issuance is 0-conf, and `POST /` can only succeed once electrs has
indexed the issuance transaction. The wallet and the explorer both read
`/index.minimal.json` for asset display names.

## Working in this repo

- **Repository is public.** Never commit keys, seeds, wallet files, RPC credentials, `.env`
  files or tokens.
- **Commit author:**
  `GracedEternalKingCabbageMan <151803062+GracedEternalKingCabbageMan@users.noreply.github.com>`
- **Always open a pull request, then merge it yourself immediately.** The PR exists so the
  change and its reasoning are recorded, not because anyone is waiting to review it. There is
  no review process. If you are ever told to leave one specific PR open, that applies to that
  PR only and never becomes the default.
- PRs go against `main`, which is the remote default.
- **Deployment is pull-only.** The server pulls this repo from GitHub. Never edit source on the
  server and never copy source or binaries onto it.
