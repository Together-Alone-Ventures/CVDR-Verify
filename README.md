# CVDR-Verify

Standalone verification tools for Cryptographically Verifiable Deletion Receipts (CVDRs).

## Repository Role

This repository is the reference verification layer for CVDR verification flows.  
It is intentionally separate from receipt-producing systems.

Boundary mapping:
- MKTd02 repo: canonical generic protocol/integration truth
- CVDR-Verify repo: reference verification layer
- DaffyDefs repo: worked example/template layer

## What This Repo Contains

- Product-specific verifier tooling under:
  - `mktd02/`
  - `mktd01/` (placeholder)
  - `mktd03/` (placeholder)
  - `zkpd01/` (placeholder)

For MKTd02, tooling covers V1-V4 verification paths with explicit handling for pending vs finalized receipts.

## Verification Scope

These tools verify cryptographic/data-consistency properties of receipts and related on-chain evidence.  
They do not verify adapter completeness or business-process correctness.

For MKTd02, this reference layer follows an archival-first evidentiary model:
- V2 primary: receipt-contained embedded-certificate verification for finalized receipts.
- V2 secondary: live certified-query corroboration/fallback (not the primary long-term evidentiary route).
- V3 primary: archival module-hash provenance against published build/release records and reproducible builds.
- V3 secondary: live on-chain module-hash corroboration when canister infrastructure is still available.

## Disclaimer

Reference tooling only. Provided under Apache-2.0 without warranty.  
Verification outputs support technical assessment but are not legal advice or regulatory certification.

## Licence

Apache-2.0
