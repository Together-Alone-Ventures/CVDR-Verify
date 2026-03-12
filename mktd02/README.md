# MKTd02 Verification Tools

Standalone tools for verifying Cryptographically Verifiable Deletion Receipts (CVDRs) produced by [MKTd02](https://github.com/Together-Alone-Ventures/MKTd02).

CVDR-Verify is the reference verification layer.  
This `mktd02/` directory contains the MKTd02-specific verifier entry points aligned to current v0.2.x/v0.3.x leaf-mode receipt lines (`mktd02-v2` and `mktd02-v3`).

## Scope

- Verifies receipt integrity and on-chain evidence through V1-V4 verification paths.
- Supports both pending receipts (no embedded certificate yet) and finalized receipts (embedded certificate present).
- Does not perform deletion, finalization orchestration, or adapter/business-logic validation.

## Quick Start

```bash
# Mainnet
./verify-quick.sh <canister-id> <receipt-id-hex> --network ic

# Local replica
./verify-quick.sh <canister-id> <receipt-id-hex>
```

```bash
# Rust CLI (from this directory)
cd mktd02-verify
cargo build --release

# Mainnet
cargo run --release -- \
  --canister <canister-id> \
  --receipt-id <receipt-id-hex> \
  --network https://ic0.app

# Optional published WASM hash for stronger V3 provenance comparison
cargo run --release -- \
  --canister <canister-id> \
  --receipt-id <receipt-id-hex> \
  --network https://ic0.app \
  --wasm-hash <64-char-hex>
```

## Verification Paths

- `verify-quick.sh`: V1 (sanity-only), V3, V4
- `mktd02-verify` (Rust CLI): V1, V2, V3, V4

### V1
Recomputes transition-linked hashes from receipt fields and checks they match receipt values.

### V2
Verifies certified-data linkage via IC certificate path:
- finalized receipts: embedded certificate path (primary long-term evidentiary route)
- pending receipts: live query certificate path (secondary corroboration/fallback)

Archived receipt-contained verification intentionally relaxes freshness-at-verification-time only.
It does not relax signature authenticity, delegation trust, canister authorization, or certified-data commitment matching.

### V3
Primary path is archival provenance:
`module_hash` in receipt -> published build/release record -> reproducible build -> inspectable source.

Secondary path is live on-chain module-hash corroboration when infrastructure still exists.
`module_hash` is SHA-256 of the exact deployed WASM bytes, not a special ICP object with extra metadata.

### V4
Checks tombstone persistence at verification time.

## Receipt Notes

- `protocol_version` may be `mktd02-v2` (legacy) or `mktd02-v3` (current line)
- `receipt_id` is protocol-version dependent:
  - v2 legacy: derived from `canister_id || nonce` under the v2 domain-tagged rule
  - v3: derived from `canister_id`, `record_id`, and `deletion_seq` under the v3 length-delimited domain-tagged rule
- `deletion_seq` is the runtime counter field used by the verifier; for legacy v2 receipts it carries v2 nonce-equivalent semantics
- v3 receipts do not carry receipt-level `subnet_id`
- CLI output prints `record_id` as hex (with byte length) when present/relevant (notably v3)
- Pending receipts may not yet include an embedded BLS certificate.
- Finalized receipts include finalization fields used by the offline V2 path.
- Finalized exported receipt artifacts support V1/V2 verification from file alone.
- V3 requires published release/build provenance in addition to receipt data.
- V4 remains live-dependent.

## Portable JSON Receipt Format

Portable JSON receipt files are verified over decoded field values, not raw JSON text. Key ordering, whitespace, and formatting have no verification meaning.

Canonical portable JSON encoding rules:

- `protocol_version`: string (`mktd02-v2` or `mktd02-v3`)
- `canister_id`: principal text
- `timestamp`: JSON string or number accepted by the verifier
- `receipt_id`, `pre_state_hash`, `post_state_hash`, `tombstone_hash`, `deletion_event_hash`, `certified_commitment`, `module_hash`: lowercase hex strings in canonical exports
- `record_id`:
  - v3: lowercase hex string in canonical exports
  - verifier also accepts legacy byte-array JSON for backward compatibility
- `bls_certificate`:
  - finalized receipts: lowercase hex string in canonical exports
  - pending receipts: absent or null
  - verifier also accepts legacy byte-array JSON for backward compatibility

Version-specific notes:

- v2 portable receipts carry legacy `subnet_id` and `nonce` fields on wire; `nonce` may be encoded as a JSON string or number
- v3 portable receipts do not carry receipt-level `subnet_id`
- v3 portable receipts carry `deletion_seq` on wire; `deletion_seq` may be encoded as a JSON string or number
- v3 portable receipts require non-empty `record_id`; in MKTd02 Leaf mode this is the deleted subject principal encoded as bytes
- finalized receipts must carry non-empty `trust_root_key_id` whenever `bls_certificate` is present

Current parser compatibility:

- The verifier accepts canonical hex-string portable JSON.
- For backward compatibility, the verifier also accepts legacy byte-array JSON for `record_id` and `bls_certificate`.

## Boundaries

- Canonical protocol/integration semantics: MKTd02 repo
- Reference verification implementation: CVDR-Verify repo
- Worked product example/integration template: DaffyDefs repo

## Licence

Apache-2.0
