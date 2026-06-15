use candid::{CandidType, Decode, Encode, Principal};
use ic_agent::hash_tree::{LookupResult, SubtreeLookupResult};
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

            // Enforce canister authorization. The IC may present the subnet's
            // canister ranges in EITHER tree layout; accept both, and in both
            // cases still require effective_canister_id to fall within a range
            // proven for the delegating subnet under the same delegation
            // signature (no weakening — see `authorize_canister_ranges`).
            authorize_canister_ranges(
                &delegated_cert,
                delegation.subnet_id.as_ref(),
                &effective_canister_id,
            )?;

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

/// Enforce that `effective_canister_id` falls within the canister ranges proven
/// for the delegating subnet, accepting EITHER tree layout the IC may present:
///
///   - **Legacy:**  `/subnet/<subnet_id>/canister_ranges` — a single CBOR
///     `Vec<(Principal, Principal)>` blob. This is the only layout the pinned
///     ic-agent 0.39 (and 0.40) `check_delegation` understands.
///   - **Sharded:** `/canister_ranges/<subnet_id>/<shard_key>` — one CBOR
///     `Vec<(Principal, Principal)>` blob per shard leaf. This is the newer IC
///     routing-table layout, not yet handled by the pinned ic-agent, resolved
///     here via the maintained `lookup_subtree`/`list_paths`/`lookup_path`
///     primitives (no hand-rolled tree-digest walking).
///
/// Authorization semantics are identical across layouts: authorize iff there is
/// **any authenticated ranges leaf under the target subnet whose signed range
/// contains the target canister**. A pruned shard carries no leaf and therefore
/// cannot authorize. The function rejects when (a) neither layout exists, (b) a
/// present leaf fails to CBOR-decode, (c) a present authenticated leaf is not an
/// exact three-level shard leaf (`/canister_ranges/<subnet_id>/<shard_key>` —
/// deeper descendant paths are rejected, never authorized), or (d) no signed
/// range contains the target. This widens *where* the proof is read, never
/// *whether* the canister must be proven in range.
fn authorize_canister_ranges(
    delegated_cert: &Certificate,
    subnet_id: &[u8],
    effective_canister_id: &Principal,
) -> Result<(), String> {
    // Legacy single-blob layout: /subnet/<subnet_id>/canister_ranges
    if let Ok(blob) = lookup_value(
        delegated_cert,
        [b"subnet".as_ref(), subnet_id, b"canister_ranges".as_ref()],
    ) {
        let ranges: Vec<(Principal, Principal)> = serde_cbor::from_slice(blob)
            .map_err(|e| format!("Invalid canister_ranges payload (legacy layout): {}", e))?;
        return if principal_is_within_ranges(effective_canister_id, &ranges) {
            Ok(())
        } else {
            Err("Certificate delegation is not authorized for this canister (legacy canister_ranges layout)".to_string())
        };
    }

    // New sharded layout: /canister_ranges/<subnet_id>/<shard_key> leaves.
    // Enumerate the authenticated (present, non-pruned) ranges leaves directly
    // under the target subnet and CBOR-decode EVERY present leaf. Authorize iff
    // some decoded signed range contains the target — but only after confirming
    // that NO present leaf failed to decode (G §2.4 (b)) and that every present
    // leaf is an exact three-level shard leaf (G §2.4 — no deeper descendant may
    // authorize). We deliberately do NOT return early on a match, so a later
    // malformed sibling cannot be skipped.
    if let SubtreeLookupResult::Found(subtree) = delegated_cert
        .tree
        .lookup_subtree([b"canister_ranges".as_ref(), subnet_id])
    {
        // `list_paths()` returns paths RELATIVE to the subtree root (the
        // <subnet_id> node — verified against ic-certification 3.1.0
        // `HashTreeNode::list_paths`, which seeds an empty prefix), so a direct
        // `<shard_key>` leaf has depth 1. If a real cert ever surfaced a
        // different convention, the live V1–V4 run regresses V2 to FAIL with the
        // "expected direct shard leaf" message below — the fix would be to set
        // this constant to the observed depth, never to drop the check.
        const SHARDED_LEAF_DEPTH: usize = 1;

        let mut present_shard = false;
        let mut authorized = false;
        for path in subtree.list_paths() {
            present_shard = true;
            // Fail closed: enforce exact three-level shard depth FIRST, then
            // require the path to resolve to a Found leaf — any non-Found result
            // (Absent / Unknown / Error) rejects rather than being silently
            // skipped (G ratified form).
            if path.len() != SHARDED_LEAF_DEPTH {
                return Err(format!(
                    "Invalid sharded canister_ranges layout: expected direct shard leaf at depth {} under /canister_ranges/<subnet_id>, found authenticated leaf at depth {}",
                    SHARDED_LEAF_DEPTH,
                    path.len()
                ));
            }
            let leaf = match subtree.lookup_path(&path) {
                LookupResult::Found(leaf) => leaf,
                other => {
                    return Err(format!(
                        "Sharded canister_ranges path enumerated by list_paths did not resolve to a Found leaf (lookup result: {:?})",
                        other
                    ));
                }
            };
            // Decode every present leaf; a failure here rejects regardless of
            // whether an earlier leaf already matched.
            let ranges: Vec<(Principal, Principal)> = serde_cbor::from_slice(leaf)
                .map_err(|e| format!("Invalid canister_ranges payload (sharded layout): {}", e))?;
            if principal_is_within_ranges(effective_canister_id, &ranges) {
                authorized = true;
            }
        }
        if present_shard {
            return if authorized {
                Ok(())
            } else {
                Err("Certificate delegation is not authorized for this canister (sharded canister_ranges layout)".to_string())
            };
        }
    }

    Err("Delegation certificate missing canister_ranges in both legacy (/subnet/<id>/canister_ranges) and sharded (/canister_ranges/<id>/<shard>) tree layouts".to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use ic_agent::hash_tree::{fork, label, leaf, HashTree};

    const SUBNET_ID: &[u8] = &[0xfe, 0x32, 0x0f, 0x2f, 0xbb];
    // A different subnet — ranges signed under it must NOT authorize a lookup
    // performed against SUBNET_ID (the delegating subnet).
    const OTHER_SUBNET_ID: &[u8] = &[0xab, 0xcd, 0xef, 0x01, 0x23];
    // Range [00000000013000000101 .. 00000000013fffff0101] — the live shard.
    const RANGE_LOW: &[u8] = &[0, 0, 0, 0, 1, 0x30, 0, 0, 1, 1];
    const RANGE_HIGH: &[u8] = &[0, 0, 0, 0, 1, 0x3f, 0xff, 0xff, 1, 1];
    const IN_RANGE: &[u8] = &[0, 0, 0, 0, 1, 0x30, 0x90, 0x42, 1, 1]; // fg23v-... shard member
    const OUT_OF_RANGE: &[u8] = &[0, 0, 0, 0, 1, 0x40, 0, 0, 1, 1];

    fn ranges_cbor() -> Vec<u8> {
        let ranges: Vec<(Principal, Principal)> = vec![(
            Principal::from_slice(RANGE_LOW),
            Principal::from_slice(RANGE_HIGH),
        )];
        serde_cbor::to_vec(&ranges).unwrap()
    }

    fn cert_with_tree(tree: HashTree<Vec<u8>>) -> Certificate {
        Certificate {
            tree,
            signature: Vec::new(),
            delegation: None,
        }
    }

    /// Legacy layout: /subnet/<subnet_id>/canister_ranges -> single CBOR blob.
    fn legacy_cert() -> Certificate {
        cert_with_tree(label(
            "subnet",
            label(SUBNET_ID, label("canister_ranges", leaf(ranges_cbor()))),
        ))
    }

    /// Sharded layout: /canister_ranges/<subnet_id>/<shard_key> -> CBOR blob.
    fn sharded_cert() -> Certificate {
        cert_with_tree(label(
            "canister_ranges",
            label(SUBNET_ID, label(RANGE_LOW, leaf(ranges_cbor()))),
        ))
    }

    /// Sharded layout, but the shard leaf is not valid CBOR.
    fn sharded_cert_malformed_leaf() -> Certificate {
        cert_with_tree(label(
            "canister_ranges",
            label(SUBNET_ID, label(RANGE_LOW, leaf(vec![0xff, 0xff, 0xff]))),
        ))
    }

    /// Sharded layout whose ranges are signed under a DIFFERENT subnet than the
    /// one the delegation names — the lookup against SUBNET_ID must miss it.
    fn sharded_cert_wrong_subnet() -> Certificate {
        cert_with_tree(label(
            "canister_ranges",
            label(OTHER_SUBNET_ID, label(RANGE_LOW, leaf(ranges_cbor()))),
        ))
    }

    /// Sharded layout with TWO direct (depth-1) shard leaves: the first valid and
    /// containing the target, the second malformed CBOR. The fork children must
    /// be in sorted label order, so RANGE_LOW (valid) precedes RANGE_HIGH
    /// (malformed). Decode-all must reject for the malformed sibling rather than
    /// passing early on the first containing leaf.
    fn sharded_cert_valid_then_malformed() -> Certificate {
        cert_with_tree(label(
            "canister_ranges",
            label(
                SUBNET_ID,
                fork(
                    label(RANGE_LOW, leaf(ranges_cbor())),
                    label(RANGE_HIGH, leaf(vec![0xff, 0xff, 0xff])),
                ),
            ),
        ))
    }

    /// Sharded layout with a DEEPER descendant leaf at
    /// /canister_ranges/<subnet_id>/<shard_key>/extra (relative depth 2). The
    /// leaf is valid CBOR and contains the target, but the depth violation must
    /// reject before any authorization.
    fn sharded_cert_deeper_path() -> Certificate {
        cert_with_tree(label(
            "canister_ranges",
            label(
                SUBNET_ID,
                label(RANGE_LOW, label("extra", leaf(ranges_cbor()))),
            ),
        ))
    }

    #[test]
    fn legacy_layout_authorizes_in_range() {
        authorize_canister_ranges(&legacy_cert(), SUBNET_ID, &Principal::from_slice(IN_RANGE))
            .expect("in-range canister must be authorized via legacy layout");
    }

    #[test]
    fn sharded_layout_authorizes_in_range() {
        authorize_canister_ranges(&sharded_cert(), SUBNET_ID, &Principal::from_slice(IN_RANGE))
            .expect("in-range canister must be authorized via sharded layout");
    }

    #[test]
    fn sharded_layout_rejects_out_of_range() {
        let err = authorize_canister_ranges(
            &sharded_cert(),
            SUBNET_ID,
            &Principal::from_slice(OUT_OF_RANGE),
        )
        .unwrap_err();
        assert!(err.contains("not authorized"), "unexpected error: {err}");
    }

    #[test]
    fn legacy_layout_rejects_out_of_range() {
        let err = authorize_canister_ranges(
            &legacy_cert(),
            SUBNET_ID,
            &Principal::from_slice(OUT_OF_RANGE),
        )
        .unwrap_err();
        assert!(err.contains("not authorized"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_when_ranges_absent_from_both_layouts() {
        let cert = cert_with_tree(label("time", leaf(vec![1, 2, 3])));
        let err =
            authorize_canister_ranges(&cert, SUBNET_ID, &Principal::from_slice(IN_RANGE)).unwrap_err();
        assert!(
            err.contains("missing canister_ranges in both"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn sharded_layout_rejects_malformed_cbor_leaf() {
        // A present (authenticated) shard leaf that fails to CBOR-decode must
        // reject, not silently skip — per G ruling §2.4 condition (b).
        let err = authorize_canister_ranges(
            &sharded_cert_malformed_leaf(),
            SUBNET_ID,
            &Principal::from_slice(IN_RANGE),
        )
        .unwrap_err();
        assert!(
            err.contains("Invalid canister_ranges payload (sharded layout)"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_when_ranges_signed_under_wrong_subnet() {
        // Ranges proven for OTHER_SUBNET_ID must not authorize a canister whose
        // delegation names SUBNET_ID — even though the canister is within those
        // ranges. The lookup is scoped to the delegating subnet's path.
        let err = authorize_canister_ranges(
            &sharded_cert_wrong_subnet(),
            SUBNET_ID,
            &Principal::from_slice(IN_RANGE),
        )
        .unwrap_err();
        assert!(
            err.contains("missing canister_ranges in both"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn sharded_layout_rejects_when_a_later_leaf_is_malformed() {
        // A valid containing leaf must NOT short-circuit past a later malformed
        // present leaf — decode-all rejects (CD Finding 1). The IN_RANGE target
        // lies within the first (valid) leaf, so an early-return implementation
        // would wrongly PASS; this must fail on the malformed sibling instead.
        let err = authorize_canister_ranges(
            &sharded_cert_valid_then_malformed(),
            SUBNET_ID,
            &Principal::from_slice(IN_RANGE),
        )
        .unwrap_err();
        assert!(
            err.contains("Invalid canister_ranges payload (sharded layout)"),
            "must reject for the malformed sibling's decode failure, got: {err}"
        );
    }

    #[test]
    fn sharded_layout_rejects_deeper_descendant_path() {
        // A leaf one level too deep (/.../<shard_key>/extra) must reject for the
        // depth violation specifically (CD Finding 2), even though its CBOR is
        // valid and contains the target.
        let err = authorize_canister_ranges(
            &sharded_cert_deeper_path(),
            SUBNET_ID,
            &Principal::from_slice(IN_RANGE),
        )
        .unwrap_err();
        assert!(
            err.contains("expected direct shard leaf"),
            "must reject for the depth violation, got: {err}"
        );
    }
}
