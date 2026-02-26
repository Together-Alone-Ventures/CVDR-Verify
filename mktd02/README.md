# MKTd02 Verification Tools

Standalone tools for verifying Cryptographically Verifiable Deletion Receipts (CVDRs) produced by [MKTd02](https://github.com/Together-Alone-Ventures/MKTd02), the ICP Leaf-mode deletion receipt library.

**Targets MKTd02 library version:** 0.1.0 (see MKTd02 repo for current commit)

## Two Tools

| Tool | Covers | Requires |
|------|--------|----------|
| `verify-quick.sh` | V1 (partial), V3, V4 | `dfx` CLI + `jq` |
| `mktd02-verify` (Rust CLI) | V1, V2, V3, V4 (full) | Rust toolchain |

## Quick Start: Shell Script
```bash
# Against mainnet
./verify-quick.sh <canister-id> <receipt-id-hex> --network ic

# Against local replica
./verify-quick.sh <canister-id> <receipt-id-hex>
```

## Quick Start: Rust CLI
```bash
cd mktd02-verify
cargo build --release

# Against mainnet
cargo run --release -- \
  --canister <canister-id> \
  --receipt-id <receipt-id-hex> \
  --network https://ic0.app

# With published WASM hash for full V3 provenance check
cargo run --release -- \
  --canister <canister-id> \
  --receipt-id <receipt-id-hex> \
  --network https://ic0.app \
  --wasm-hash <64-char-hex>
```

## What V1–V4 Verify

### V1: State Transition Verification

Confirms the receipt is internally consistent. The tool independently recomputes four cryptographic hashes from the receipt's raw fields using the published formulas, and checks they match the values in the receipt. If all four match, the receipt has not been tampered with and the state transition it describes is mathematically consistent.

### V2: Subnet Certificate Verification

Confirms the Internet Computer's subnet vouches for the deletion. The tool retrieves a BLS certificate from the canister and verifies the cryptographic signature chain back to the ICP root of trust. This proves that at least two-thirds of the subnet's nodes attested to the post-deletion state — it is not just the data controller's claim.

### V3: Module Hash Verification

Confirms which code was running when the deletion occurred. The tool compares the canister's current code hash against the hash recorded in the receipt. Three outcomes are possible:

- **MATCH** — the canister code has not changed since deletion.
- **MISMATCH-EXPECTED** — the canister has been upgraded (normal for maintained software). The receipt remains valid evidence of what happened under the prior code version.
- **MISMATCH-SUSPICIOUS** — the receipt was generated with development zeros. Code provenance cannot be verified.

If you supply `--wasm-hash` (from a published deterministic build), the tool performs a three-way comparison for end-to-end provenance confirmation.

### V4: Tombstone Persistence Check

Confirms the deletion has not been reversed. The tool queries the canister's current tombstone status and state hash, and checks they match the post-deletion values in the receipt. This is a point-in-time check — it confirms the tombstone is intact right now, not that it will remain so.

## What These Tools Cannot Verify

**RT3: Adapter honesty.** The tools verify that a state transition occurred and that it is cryptographically consistent with the receipt. They cannot verify that the enterprise's adapter correctly declared all PII fields. If the adapter omitted a PII field, that field would survive tombstoning and no external tool can detect this. Confirming adapter correctness requires source code audit of the enterprise's `MKTdDataSource` implementation.

For the full residual trust analysis, see the [MKTd02 README](https://github.com/Together-Alone-Ventures/MKTd02) or the Zombie Delete Configurations spreadsheet.

## Cryptographic Specification

All hash formulas, domain separation tags, and encoding rules are published in the [MKTd02 repository](https://github.com/Together-Alone-Ventures/MKTd02). The Rust CLI uses `zombie-core` (the same hashing library used by MKTd02 itself) to ensure identical hash computation — no reimplementation, no drift.

Anyone who wishes to verify the tool itself can audit `zombie-core`'s 7 hash formulas against the published specification, or reimplement them independently.

## Licence

Apache-2.0
