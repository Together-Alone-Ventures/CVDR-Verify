# CVDR-Verify

Standalone verification tools for **Cryptographically Verifiable Deletion Receipts** (CVDRs) produced by [Together Alone Ventures](https://github.com/Together-Alone-Ventures)' deletion products.

## What This Repo Is

This repository implements the published verification procedures (V1–V4) for CVDRs. It is deliberately separated from the library repositories that produce CVDRs to reinforce independence: this repo contains **zero deletion engine code, zero adapter code, and zero business logic**. It verifies; it does not delete.

## Who It's For

- **Data subjects** (or their representatives) who requested erasure and want proof it happened.
- **Auditors and regulators** (e.g. ICO, DPAs) who need to confirm GDPR Article 17 compliance.
- **Enterprises** (TAV clients) who want to smoke-test their integration before going live.

## Trust Model

Downloading these tools from TAV's GitHub means trusting TAV's source code. This is acknowledged and mitigated:

- The tools are small and single-purpose — an auditor can review the entire codebase in hours.
- All hash recomputations follow the published cryptographic specification. A suspicious party can reimplement the hash formulas from the spec document and compare outputs. The tools are a convenience, not the proof.
- BLS certificate verification (MKTd02/MKTd03) uses [ic-agent](https://github.com/dfinity/agent-rs), a widely-audited open-source library maintained by DFINITY.
- What no tool can verify: whether the enterprise's adapter correctly maps all PII fields (Residual Trust assumption RT3). That requires source code audit of the adapter.

## Directory Layout

| Directory | Product | Status |
|-----------|---------|--------|
| `mktd02/` | MKTd02 — ICP Leaf mode (single data subject per canister) | **Active** |
| `mktd01/` | MKTd01 — Cloud/plugin CVDRs | Placeholder |
| `mktd03/` | MKTd03 — ICP Tree mode (multiple data subjects per canister) | Placeholder |
| `zkpd01/` | ZKPd01 — Zero-knowledge proof deletion receipts | Placeholder |

Each product directory contains tools specific to that product's CVDR format and verification procedures. Placeholder directories will ship with tooling when their respective products launch.

## Licence

Apache-2.0
READMEEOF
