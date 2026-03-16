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

V1-V4 durability classification:
- V1: permanent / archival
- V2: permanent / archival for finalized receipts; pending receipts require live canister access
- V3: permanent, assuming archived build artifacts and reproducible provenance are available
- V4: point-in-time only

## Verification Scope

These tools verify cryptographic/data-consistency properties of receipts and related on-chain evidence.  
They do not verify adapter completeness or business-process correctness.

For MKTd02, this reference layer follows an archival-first evidentiary model:
- V2 primary: receipt-contained embedded-certificate verification for finalized receipts.
- V2 secondary: live certified-query corroboration/fallback (not the primary long-term evidentiary route).
- V3 primary: archival module-hash provenance against published build/release records and reproducible builds.
- V3 secondary: live on-chain module-hash corroboration when canister infrastructure is still available.

## Two-Tier Verification Model
V1 and V2 are offline proofs. For finalized receipts, both can be executed from the JSON receipt
file alone with no network access and no dependency on live infrastructure.

V3 and V4 are liveness checks. V3 requires access to the published GitHub release record and
optionally a live canister query. V4 requires a live canister query. Neither is available if
the canister no longer exists; this does not invalidate V1 or V2.

Verifiers should treat V1+V2 as the durable evidentiary core and V3+V4 as corroborating
point-in-time checks.

## Disclaimer

Reference tooling only. Provided under Apache-2.0 without warranty.  
Verification outputs support technical assessment but do not replace verifier due diligence, and are not legal advice or regulatory certification.

## Licence

Apache-2.0
