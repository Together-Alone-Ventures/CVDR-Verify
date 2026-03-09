# MKTd02 Verification Tools

Standalone tools for verifying Cryptographically Verifiable Deletion Receipts (CVDRs) produced by [MKTd02](https://github.com/Together-Alone-Ventures/MKTd02).

CVDR-Verify is the reference verification layer.  
This `mktd02/` directory contains the MKTd02-specific verifier entry points aligned to the current v0.2.x leaf-mode receipt shape.

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
- finalized receipts: embedded certificate path
- pending receipts: live query certificate path

### V3
Checks module hash consistency (with optional published WASM hash for stronger provenance comparison).

### V4
Checks tombstone persistence at verification time.

## Receipt Notes

- receipt_id is derived from `canister_id || nonce` under the protocol’s domain-tagged hash rule
- Pending receipts may not yet include an embedded BLS certificate.
- Finalized receipts include finalization fields used by the offline V2 path.

## Boundaries

- Canonical protocol/integration semantics: MKTd02 repo
- Reference verification implementation: CVDR-Verify repo
- Worked product example/integration template: DaffyDefs repo

## Licence

Apache-2.0
