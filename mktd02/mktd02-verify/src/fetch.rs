use anyhow::{anyhow, Result};
use candid::{Decode, Encode, Principal};
use ic_agent::Agent;
use zombie_core::receipt::DeletionReceipt;

/// Fetch a CVDR receipt from the canister by hex-encoded receipt ID.
///
/// The canister returns `Option<DeletionReceipt>` in Candid. This verifier
/// first attempts optional decode, then falls back to direct decode for
/// compatibility with endpoint/interface variation.
///
/// ## Trust root key note
/// Receipts include `trust_root_key_id` used by V2 certificate-path checks.
/// Pending receipts may carry an empty key id until finalization data exists.
pub async fn fetch_receipt(
    agent: &Agent,
    canister_id: Principal,
    receipt_id_hex: &str,
) -> Result<DeletionReceipt> {
    let arg = Encode!(&receipt_id_hex)?;

    let response = agent
        .query(&canister_id, "mktd_get_receipt")
        .with_arg(arg)
        .call()
        .await
        .map_err(|e| anyhow!("Query mktd_get_receipt failed: {}", e))?;

    // Primary: canister returns opt DeletionReceipt
    if let Ok(Some(receipt)) = Decode!(&response, Option<DeletionReceipt>) {
        return Ok(receipt);
    }

    // Fallback: try direct (non-optional) decode
    if let Ok(receipt) = Decode!(&response, DeletionReceipt) {
        return Ok(receipt);
    }

    Err(anyhow!(
        "Failed to decode receipt from canister {} — check Candid interface compatibility with current zombie-core/MKTd02 receipt types",
        canister_id
    ))
}

// ---------------------------------------------------------------------------
// Golden receipt fixture
// ---------------------------------------------------------------------------
// These tests assert that zombie-core's canonical DeletionReceipt round-trips
// through CBOR serialisation correctly and that critical hash fields are
// preserved exactly. If zombie-core's serialisation changes in a way that
// alters field values, these tests will catch it before the change reaches
// production.
//
// We do NOT store a raw CBOR blob here because the blob would need to be
// regenerated every time a non-hash field (e.g. protocol_version string)
// changes. Instead we assert field-level round-trip fidelity and exact hash
// values — which is what matters for verification correctness.
#[cfg(test)]
mod tests {
    use super::*;
    use candid::Principal;
    use zombie_core::receipt::ProtocolVersion;

    fn golden_receipt() -> DeletionReceipt {
        DeletionReceipt {
            protocol_version: ProtocolVersion::V2.into(),
            receipt_id:           [0x1F; 32],
            canister_id:          Principal::from_text("aaaaa-aa").unwrap(),
            subnet_id:            Principal::from_text("2vxsx-fae").unwrap(),
            pre_state_hash:       [0xAA; 32],
            post_state_hash:      [0xBB; 32],
            tombstone_hash:       [0xCC; 32],
            deletion_event_hash:  [0xDD; 32],
            certified_commitment: [0xEE; 32],
            module_hash:          [0xFF; 32],
            timestamp:            1_000_000,
            nonce:                1,
            bls_certificate:      None,
            trust_root_key_id:       String::from("mainnet"),
        }
    }

    /// Hash fields must survive CBOR round-trip without any byte mutation.
    /// This guards against accidental endianness swaps, truncation, or
    /// field reordering in zombie-core's serialisation layer.
    #[test]
    fn golden_receipt_cbor_round_trip() {
        let original = golden_receipt();

        // Encode to CBOR
        let mut buf = Vec::new();
        ciborium::into_writer(&original, &mut buf)
            .expect("CBOR encode failed");

        // Decode back
        let decoded: DeletionReceipt = ciborium::from_reader(buf.as_slice())
            .expect("CBOR decode failed");

        // All hash fields must be byte-identical
        assert_eq!(decoded.receipt_id,           original.receipt_id,           "receipt_id mutated");
        assert_eq!(decoded.pre_state_hash,        original.pre_state_hash,       "pre_state_hash mutated");
        assert_eq!(decoded.post_state_hash,       original.post_state_hash,      "post_state_hash mutated");
        assert_eq!(decoded.tombstone_hash,        original.tombstone_hash,       "tombstone_hash mutated");
        assert_eq!(decoded.deletion_event_hash,   original.deletion_event_hash,  "deletion_event_hash mutated");
        assert_eq!(decoded.certified_commitment,  original.certified_commitment, "certified_commitment mutated");
        assert_eq!(decoded.module_hash,           original.module_hash,          "module_hash mutated");
        assert_eq!(decoded.timestamp,             original.timestamp,            "timestamp mutated");
        assert_eq!(decoded.nonce,                 original.nonce,                "nonce mutated");
        assert_eq!(decoded.protocol_version,      original.protocol_version,     "protocol_version mutated");
        assert_eq!(decoded.trust_root_key_id,        original.trust_root_key_id,       "trust_root_key mutated");
    }

    /// Protocol version string must be exactly "mktd02-v2" — not an enum
    /// variant name, not a numeric code. Verifiers parse this string.
    #[test]
    fn golden_protocol_version_string() {
        let r = golden_receipt();
        assert_eq!(r.protocol_version, "mktd02-v2",
            "protocol_version string changed — verifiers parse this field directly");
    }

    /// receipt_id golden vector — matches zombie-core's own golden test.
    /// canister = aaaaa-aa (empty bytes), nonce = 1.
    #[test]
    fn golden_receipt_id_matches_zombie_core() {
        use zombie_core::receipt::compute_receipt_id;
        let c = Principal::from_text("aaaaa-aa").unwrap();
        let id = compute_receipt_id(&c, 1);
        assert_eq!(
            hex::encode(id),
            "1f213a0f2bf4992071a7f23e72d1942e564a4e871e3decce8ac8ee27d08f534b",
            "receipt_id derivation changed — breaks all existing receipts"
        );
    }
}
