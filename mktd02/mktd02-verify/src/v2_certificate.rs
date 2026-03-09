use candid::{CandidType, Decode, Encode, Principal};
use ic_agent::{lookup_value, Agent, Certificate};
use serde::Deserialize;
use zombie_core::nns_keys;
use zombie_core::receipt::DeletionReceipt;

#[derive(Debug, CandidType, Deserialize)]
struct StateHashCertified {
    pub certificate: Option<serde_bytes::ByteBuf>,
    pub hash: serde_bytes::ByteBuf,
}

const IC_STATE_ROOT_DOMAIN_SEPARATOR: &[u8; 14] = b"\x0Dic-state-root";
const DER_PREFIX: &[u8; 37] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00";
const BLS_RAW_KEY_LEN: usize = 96;
const V2_TIME_WARN_ENV: &str = "CVDR_V2_CERT_TIME_WARN_SECS";
const DEFAULT_V2_TIME_WARN_SECS: u64 = 300;

pub struct V2Result {
    pub passed: bool,
    pub mode: &'static str,
    pub degraded: bool,
    pub detail: String,
    pub notes: Vec<String>,
}

impl V2Result {
    fn pass(mode: &'static str, degraded: bool, notes: Vec<String>) -> Self {
        Self {
            passed: true,
            mode,
            degraded,
            detail: String::new(),
            notes,
        }
    }

    fn fail(mode: &'static str, degraded: bool, detail: impl Into<String>) -> Self {
        Self {
            passed: false,
            mode,
            degraded,
            detail: detail.into(),
            notes: vec![],
        }
    }

    fn fail_with_notes(
        mode: &'static str,
        degraded: bool,
        detail: impl Into<String>,
        notes: Vec<String>,
    ) -> Self {
        Self {
            passed: false,
            mode,
            degraded,
            detail: detail.into(),
            notes,
        }
    }

    pub fn passed(&self) -> bool {
        self.passed
    }

    pub fn summary(&self) -> String {
        if self.passed {
            if self.degraded {
                "V2: PASS (live corroboration mode) — subnet BLS certificate valid, certified_data matches receipt commitment".to_string()
            } else {
                "V2: PASS (receipt-contained mode) — embedded certificate valid, certified_data matches receipt commitment".to_string()
            }
        } else {
            format!("V2: FAIL [{}] — {}", self.mode, self.detail)
        }
    }
}

/// Verify V2: certificate path + certified_data commitment match.
///
/// ## Security model by mode
///
/// - **Receipt-contained mode** (`bls_certificate` present): verifies signature authenticity,
///   delegation trust, canister-range authorization, and certified-data commitment match using
///   receipt-contained data and receipt-selected trust root.
///   It intentionally skips only freshness-at-verification-time because this path validates
///   archived evidence captured at deletion time.
///
/// - **Live corroboration mode** (`bls_certificate` absent): unchanged live query path using
///   `agent.verify(...)`, including normal freshness semantics.
pub async fn verify(
    agent: &Agent,
    canister_id: Principal,
    receipt: &DeletionReceipt,
) -> V2Result {
    // Receipt-contained path (finalized receipt with embedded certificate)
    if let Some(cert_bytes) = &receipt.bls_certificate {
        let trust_id = receipt.trust_root_key_id.trim();
        if trust_id.is_empty() {
            return V2Result::fail(
                "receipt-contained",
                false,
                "embedded bls_certificate present but trust_root_key_id is missing",
            );
        }

        let Some(trust_key) = nns_keys::lookup_key(trust_id) else {
            let known: Vec<&str> = nns_keys::MAINNET_KEYS.iter().map(|k| k.id).collect();
            return V2Result::fail(
                "receipt-contained",
                false,
                format!(
                    "Unknown trust_root_key_id '{}'. Known IDs: {}. For local-dev receipts, rebuild CVDR-Verify with --features local-replica. If this is a newer receipt, upgrade zombie-core.",
                    trust_id,
                    known.join(", ")
                ),
            );
        };

        if trust_id != nns_keys::active_key_id() {
            eprintln!(
                "V2 note: receipt trust_root_key_id '{}' differs from build active key '{}'; using receipt-selected key.",
                trust_id,
                nns_keys::active_key_id()
            );
        }

        return verify_from_embedded_cert(
            cert_bytes,
            canister_id,
            &receipt.certified_commitment,
            trust_key.der_bytes,
            receipt.timestamp,
        );
    }

    // Pending/non-finalized path: degraded live corroboration.
    verify_via_live_query(agent, canister_id, &receipt.certified_commitment).await
}

// ---------------------------------------------------------------------------
// Receipt-contained path (archived evidence)
// ---------------------------------------------------------------------------

fn verify_from_embedded_cert(
    cert_bytes: &[u8],
    canister_id: Principal,
    expected_commitment: &[u8; 32],
    trust_root_der: &[u8],
    receipt_timestamp_ns: u64,
) -> V2Result {
    let certificate: Certificate = match serde_cbor::from_slice(cert_bytes) {
        Ok(c) => c,
        Err(e) => {
            return V2Result::fail(
                "receipt-contained",
                false,
                format!("Failed to parse embedded certificate CBOR: {}", e),
            )
        }
    };

    let notes = certificate_timing_notes(&certificate, receipt_timestamp_ns);

    // Archived-mode verification intentionally skips freshness-at-verification-time.
    // It still validates signature authenticity, delegation trust, canister authorization,
    // and certified_data commitment matching.
    if let Err(e) = verify_archived_certificate_no_freshness(&certificate, canister_id, trust_root_der)
    {
        return V2Result::fail_with_notes(
            "receipt-contained",
            false,
            format!(
                "BLS certificate verification failed (receipt-contained path): {}",
                e
            ),
            notes,
        );
    }

    check_certified_data(
        &certificate,
        canister_id,
        expected_commitment,
        "receipt-contained",
        false,
        notes,
    )
}

fn verify_archived_certificate_no_freshness(
    cert: &Certificate,
    effective_canister_id: Principal,
    trust_root_der: &[u8],
) -> Result<(), String> {
    let signer_der = match &cert.delegation {
        None => trust_root_der.to_vec(),
        Some(delegation) => {
            let delegated_cert: Certificate = serde_cbor::from_slice(delegation.certificate.as_ref())
                .map_err(|e| format!("Failed to parse delegation certificate CBOR: {}", e))?;

            if delegated_cert.delegation.is_some() {
                return Err("Delegation certificate contains nested delegation (unsupported)".to_string());
            }

            // Verify delegation certificate signature against trust root.
            verify_signature_with_der_key(&delegated_cert, trust_root_der)
                .map_err(|e| format!("Delegation certificate signature invalid: {}", e))?;

            // Enforce canister authorization exactly as ic-agent::check_delegation:
            // lookup subnet/<subnet_id>/canister_ranges and require effective_canister_id in range.
            let canister_range_lookup = [
                b"subnet".as_ref(),
                delegation.subnet_id.as_ref(),
                b"canister_ranges".as_ref(),
            ];
            let canister_range = lookup_value(&delegated_cert, canister_range_lookup)
                .map_err(|e| format!("Delegation certificate missing canister_ranges: {}", e))?;
            let ranges: Vec<(Principal, Principal)> = serde_cbor::from_slice(canister_range)
                .map_err(|e| format!("Invalid canister_ranges payload in delegation cert: {}", e))?;
            if !principal_is_within_ranges(&effective_canister_id, &ranges) {
                return Err("Certificate delegation is not authorized for this canister".to_string());
            }

            let public_key_path = [
                b"subnet".as_ref(),
                delegation.subnet_id.as_ref(),
                b"public_key".as_ref(),
            ];
            lookup_value(&delegated_cert, public_key_path)
                .map_err(|e| format!("Delegation certificate missing subnet public_key: {}", e))?
                .to_vec()
        }
    };

    verify_signature_with_der_key(cert, &signer_der)
}

fn verify_signature_with_der_key(cert: &Certificate, der_key: &[u8]) -> Result<(), String> {
    let key = extract_der_public_key(der_key)?;

    let root_hash = cert.tree.digest();
    let mut msg = Vec::with_capacity(IC_STATE_ROOT_DOMAIN_SEPARATOR.len() + root_hash.len());
    msg.extend_from_slice(IC_STATE_ROOT_DOMAIN_SEPARATOR);
    msg.extend_from_slice(&root_hash);

    ic_verify_bls_signature::verify_bls_signature(cert.signature.as_ref(), &msg, &key)
        .map_err(|_| "BLS signature check failed".to_string())
}

fn extract_der_public_key(der_key: &[u8]) -> Result<Vec<u8>, String> {
    let expected_len = DER_PREFIX.len() + BLS_RAW_KEY_LEN;
    if der_key.len() != expected_len {
        return Err(format!(
            "DER key length mismatch (expected {}, got {})",
            expected_len,
            der_key.len()
        ));
    }
    if &der_key[..DER_PREFIX.len()] != DER_PREFIX {
        return Err("DER key prefix mismatch".to_string());
    }
    Ok(der_key[DER_PREFIX.len()..].to_vec())
}

fn principal_is_within_ranges(principal: &Principal, ranges: &[(Principal, Principal)]) -> bool {
    ranges
        .iter()
        .any(|(low, high)| principal >= low && principal <= high)
}

fn certificate_timing_notes(cert: &Certificate, receipt_timestamp_ns: u64) -> Vec<String> {
    let mut notes = vec![];
    match lookup_certificate_time_ns(cert) {
        Ok(cert_time_ns) => {
            let delta_ns = cert_time_ns as i128 - receipt_timestamp_ns as i128;
            let delta_secs = delta_ns as f64 / 1_000_000_000f64;
            notes.push(format!(
                "V2 timestamp: certificate_time_ns={} receipt_time_ns={} delta_secs={:.3}",
                cert_time_ns, receipt_timestamp_ns, delta_secs
            ));

            let warn_secs = std::env::var(V2_TIME_WARN_ENV)
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(DEFAULT_V2_TIME_WARN_SECS);
            if delta_ns.unsigned_abs() > warn_secs as u128 * 1_000_000_000u128 {
                notes.push(format!(
                    "V2 warning: certificate/receipt timestamp delta exceeds {}s (set {} to adjust warning threshold)",
                    warn_secs, V2_TIME_WARN_ENV
                ));
            }
        }
        Err(e) => {
            notes.push(format!(
                "V2 note: could not decode certificate time field: {}",
                e
            ));
        }
    }
    notes
}

fn lookup_certificate_time_ns(cert: &Certificate) -> Result<u64, String> {
    let encoded = lookup_value(cert, [b"time".as_ref()])
        .map_err(|e| format!("time path lookup failed: {}", e))?;
    decode_unsigned_leb128_u64(encoded)
}

fn decode_unsigned_leb128_u64(bytes: &[u8]) -> Result<u64, String> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for (idx, byte) in bytes.iter().copied().enumerate() {
        let chunk = (byte & 0x7f) as u64;
        if shift >= 64 && chunk != 0 {
            return Err(format!("ULEB128 overflow at byte {}", idx));
        }
        result |= chunk << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift = shift.saturating_add(7);
        if shift > 63 {
            return Err("ULEB128 too large for u64".to_string());
        }
    }
    Err("ULEB128 terminated unexpectedly".to_string())
}

// ---------------------------------------------------------------------------
// Live corroboration path
// ---------------------------------------------------------------------------

async fn verify_via_live_query(
    agent: &Agent,
    canister_id: Principal,
    expected_commitment: &[u8; 32],
) -> V2Result {
    // Query mktd_get_state_hash — the canister calls ic0.data_certificate()
    // during this query, embedding the subnet's BLS-signed certificate.
    let arg = match Encode!() {
        Ok(a) => a,
        Err(e) => {
            return V2Result::fail(
                "live-corroboration",
                true,
                format!("Failed to encode query args: {}", e),
            )
        }
    };

    let response = match agent
        .query(&canister_id, "mktd_get_state_hash")
        .with_arg(arg)
        .call()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return V2Result::fail(
                "live-corroboration",
                true,
                format!("query mktd_get_state_hash failed: {}", e),
            )
        }
    };

    let resp = match Decode!(&response, StateHashCertified) {
        Ok(r) => r,
        Err(e) => {
            return V2Result::fail(
                "live-corroboration",
                true,
                format!("failed to decode state hash response: {}", e),
            )
        }
    };

    let cert_bytes = match resp.certificate {
        Some(c) => c.into_vec(),
        None => {
            return V2Result::fail(
                "live-corroboration",
                true,
                "Certificate not present in query response. The canister's mktd_get_state_hash endpoint returned null for the certificate field.",
            )
        }
    };

    let certificate: Certificate = match serde_cbor::from_slice(&cert_bytes) {
        Ok(c) => c,
        Err(e) => {
            return V2Result::fail(
                "live-corroboration",
                true,
                format!("Failed to parse certificate CBOR (live path): {}", e),
            )
        }
    };

    if let Err(e) = agent.verify(&certificate, canister_id) {
        return V2Result::fail(
            "live-corroboration",
            true,
            format!("BLS certificate verification failed (live path): {}", e),
        );
    }

    check_certified_data(
        &certificate,
        canister_id,
        expected_commitment,
        "live-corroboration",
        true,
        vec![],
    )
}

// ---------------------------------------------------------------------------
// Shared: certified_data lookup
// ---------------------------------------------------------------------------

fn check_certified_data(
    certificate: &Certificate,
    canister_id: Principal,
    expected: &[u8; 32],
    mode: &'static str,
    degraded: bool,
    notes: Vec<String>,
) -> V2Result {
    match lookup_value(
        certificate,
        [
            b"canister".as_ref(),
            canister_id.as_slice(),
            b"certified_data".as_ref(),
        ],
    ) {
        Ok(data) => {
            if data.len() != 32 {
                return V2Result::fail_with_notes(
                    mode,
                    degraded,
                    format!("certified_data is {} bytes, expected 32", data.len()),
                    notes,
                );
            }
            let actual: [u8; 32] = data.try_into().unwrap();
            if actual == *expected {
                V2Result::pass(mode, degraded, notes)
            } else {
                V2Result::fail_with_notes(
                    mode,
                    degraded,
                    format!(
                        "certified_data mismatch:\n  receipt:  {}\n  on-chain: {}",
                        hex::encode(expected),
                        hex::encode(actual)
                    ),
                    notes,
                )
            }
        }
        Err(e) => V2Result::fail_with_notes(
            mode,
            degraded,
            format!("certified_data not found in certificate tree: {:?}", e),
            notes,
        ),
    }
}
