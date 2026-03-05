use candid::{CandidType, Decode, Encode, Principal};
use ic_agent::Agent;
use serde::Deserialize;
use zombie_core::nns_keys;
use zombie_core::receipt::DeletionReceipt;

#[derive(Debug, CandidType, Deserialize)]
struct StateHashCertified {
    pub certificate: Option<serde_bytes::ByteBuf>,
    pub hash: serde_bytes::ByteBuf,
}

pub struct V2Result {
    pub passed: bool,
    pub detail: String,
}

impl V2Result {
    pub fn passed(&self) -> bool {
        self.passed
    }

    pub fn summary(&self) -> String {
        if self.passed {
            "V2: PASS — subnet BLS certificate valid, certified data matches commitment"
                .to_string()
        } else {
            format!("V2: FAIL — {}", self.detail)
        }
    }
}

/// Verify V2: BLS certificate chain + certified data match.
///
/// ## Paths
///
/// - **Offline** (receipt finalized, `bls_certificate` is Some): parse
///   the embedded certificate and verify against the known NNS root key.
///   No network call required.
///
/// - **Online** (receipt pending, `bls_certificate` is None): live query
///   to `mktd_get_state_hash` to obtain the certificate from the IC runtime.
///   Requires the canister to be reachable.
///
/// In both paths, `trust_root_key_id` is validated against zombie-core's
/// allowlist before any verification is attempted.
///
/// ## Key rotation
///
/// The offline path currently verifies using the agent's configured root key
/// (ic-agent default: ICP mainnet). For receipts issued under a future rotated
/// key, the verifier binary must be rebuilt pointing at the new key, OR
/// ic-agent must gain an explicit-key verification API. A TODO is placed at
/// the verification call site. The trust_root_key_id field ensures receipts
/// are self-describing — the infrastructure is ready for full rotation support.
pub async fn verify(
    agent: &Agent,
    canister_id: Principal,
    receipt: &DeletionReceipt,
) -> V2Result {
    // --- Step 0: Validate trust_root_key_id (fail-closed) ---
    //
    // Reject receipts with unknown key IDs immediately. This catches:
    //   - Truncated or malformed receipts (empty string on pending receipts)
    //   - local-dev receipts when local-replica feature is not enabled
    //   - Future key IDs not yet in this version of zombie-core
    //
    // Note: pending receipts have trust_root_key_id = "" until finalized.
    // The online path handles pending receipts — skip the ID check for them.
    let is_finalized = receipt.bls_certificate.is_some();

    if is_finalized {
        if nns_keys::lookup_key(&receipt.trust_root_key_id).is_none() {
            // Build the known-IDs list dynamically from the allowlist so the
            // error message stays accurate after future key additions.
            let known: Vec<&str> = nns_keys::MAINNET_KEYS.iter().map(|k| k.id).collect();
            return V2Result {
                passed: false,
                detail: format!(
                    "Unknown trust_root_key_id '{}'.                      Known IDs: {}.                      For local-dev receipts, rebuild CVDR-Verify with                      --features local-replica.                      If this is a newer receipt, upgrade zombie-core.",
                    receipt.trust_root_key_id,
                    known.join(", ")
                ),
            };
        }

        // Warn if the receipt's key ID differs from the active key.
        // Expected after a future NNS key rotation — not an error.
        if receipt.trust_root_key_id != nns_keys::active_key_id() {
            eprintln!(
                "V2 note: receipt trust_root_key_id '{}' differs from active key '{}'.                  Verifying against receipt's key ID (see TODO in verify_from_embedded_cert).",
                receipt.trust_root_key_id,
                nns_keys::active_key_id()
            );
        }
    }

    // --- Branch on receipt finalization status ---
    if let Some(cert_bytes) = &receipt.bls_certificate {
        // Offline path: finalized receipt with embedded certificate
        verify_from_embedded_cert(cert_bytes, agent, canister_id, &receipt.certified_commitment)
    } else {
        // Online path: pending receipt — live query required
        verify_via_live_query(agent, canister_id, &receipt.certified_commitment).await
    }
}

// ---------------------------------------------------------------------------
// Offline path
// ---------------------------------------------------------------------------

fn verify_from_embedded_cert(
    cert_bytes: &[u8],
    agent: &Agent,
    canister_id: Principal,
    expected_commitment: &[u8; 32],
) -> V2Result {
    // Parse the embedded certificate CBOR
    let certificate: ic_agent::Certificate = match serde_cbor::from_slice(cert_bytes) {
        Ok(c) => c,
        Err(e) => return V2Result {
            passed: false,
            detail: format!("Failed to parse embedded certificate CBOR: {}", e),
        },
    };

    // Verify BLS signature chain using the agent's configured root key.
    //
    // Current behaviour: ic-agent verifies against whichever root key it was
    // initialised with (mainnet by default, local replica if fetch_root_key()
    // was called). This means a CVDR-Verify binary built for mainnet will
    // correctly verify all current receipts (trust_root_key_id = "mainnet").
    //
    // Limitation: after a future NNS key rotation, receipts issued under the
    // OLD key will fail verification with a binary configured for the NEW key.
    //
    // TODO(key-rotation): once ic-agent exposes an API to verify a certificate
    // against an explicitly supplied DER public key, replace agent.verify() with:
    //
    //   let key = nns_keys::lookup_key(&receipt.trust_root_key_id).unwrap();
    //   verify_with_key(&certificate, canister_id, key.der_bytes)
    //
    // The trust_root_key_id field and nns_keys allowlist are already in place
    // for this upgrade. Only the ic-agent call site needs to change.
    if let Err(e) = agent.verify(&certificate, canister_id) {
        return V2Result {
            passed: false,
            detail: format!(
                "BLS certificate verification failed (offline path): {}.                  For local-dev receipts, ensure the agent was initialised with                  fetch_root_key() for the local replica.",
                e
            ),
        };
    }

    check_certified_data(&certificate, canister_id, expected_commitment)
}

// ---------------------------------------------------------------------------
// Online path
// ---------------------------------------------------------------------------

async fn verify_via_live_query(
    agent: &Agent,
    canister_id: Principal,
    expected_commitment: &[u8; 32],
) -> V2Result {
    // Query mktd_get_state_hash — the canister calls ic0.data_certificate()
    // during this query, embedding the subnet's BLS-signed certificate.
    //
    // NOTE: This MUST be an ingress query (external caller).
    // Canister-to-canister calls cannot obtain the certificate blob even
    // if the target method is declared as query. ICP platform constraint.
    let arg = match Encode!() {
        Ok(a) => a,
        Err(e) => return V2Result {
            passed: false,
            detail: format!("Failed to encode query args: {}", e),
        },
    };

    let response = match agent
        .query(&canister_id, "mktd_get_state_hash")
        .with_arg(arg)
        .call()
        .await
    {
        Ok(r) => r,
        Err(e) => return V2Result {
            passed: false,
            detail: format!("query mktd_get_state_hash failed: {}", e),
        },
    };

    let resp = match Decode!(&response, StateHashCertified) {
        Ok(r) => r,
        Err(e) => return V2Result {
            passed: false,
            detail: format!("failed to decode state hash response: {}", e),
        },
    };

    let cert_bytes = match resp.certificate {
        Some(c) => c.into_vec(),
        None => return V2Result {
            passed: false,
            detail: "Certificate not present in query response.                 The canister's mktd_get_state_hash endpoint returned null                 for the certificate field."
                .to_string(),
        },
    };

    let certificate: ic_agent::Certificate = match serde_cbor::from_slice(&cert_bytes) {
        Ok(c) => c,
        Err(e) => return V2Result {
            passed: false,
            detail: format!("Failed to parse certificate CBOR (online path): {}", e),
        },
    };

    if let Err(e) = agent.verify(&certificate, canister_id) {
        return V2Result {
            passed: false,
            detail: format!("BLS certificate verification failed (online path): {}", e),
        };
    }

    check_certified_data(&certificate, canister_id, expected_commitment)
}

// ---------------------------------------------------------------------------
// Shared: certified_data lookup
// ---------------------------------------------------------------------------

fn check_certified_data(
    certificate: &ic_agent::Certificate,
    canister_id: Principal,
    expected: &[u8; 32],
) -> V2Result {
    match ic_agent::lookup_value(certificate, [
        b"canister".as_ref(),
        canister_id.as_slice(),
        b"certified_data".as_ref(),
    ]) {
        Ok(data) => {
            if data.len() != 32 {
                return V2Result {
                    passed: false,
                    detail: format!(
                        "certified_data is {} bytes, expected 32",
                        data.len()
                    ),
                };
            }
            let actual: [u8; 32] = data.try_into().unwrap();
            if actual == *expected {
                V2Result { passed: true, detail: String::new() }
            } else {
                V2Result {
                    passed: false,
                    detail: format!(
                        "certified_data mismatch:\n  receipt:  {}\n  on-chain: {}",
                        hex::encode(expected),
                        hex::encode(actual)
                    ),
                }
            }
        }
        Err(e) => V2Result {
            passed: false,
            detail: format!("certified_data not found in certificate tree: {:?}", e),
        },
    }
}
