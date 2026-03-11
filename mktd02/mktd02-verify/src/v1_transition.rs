use candid::Principal;
use zombie_core::hashing::{
    sha256, hash_with_tag,
    TAG_TOMBSTONE_HASH, TAG_EVENT, TAG_CERTIFIED,
    TOMBSTONE_SEED,
};
use zombie_core::receipt::{compute_receipt_id, compute_receipt_id_v2, DeletionReceipt};

pub struct V1Result {
    pub tombstone_hash_ok: bool,
    pub deletion_event_hash_ok: bool,
    pub certified_commitment_ok: bool,
    pub receipt_id_ok: bool,
    pub details: Vec<String>,
}

impl V1Result {
    pub fn passed(&self) -> bool {
        self.tombstone_hash_ok
            && self.deletion_event_hash_ok
            && self.certified_commitment_ok
            && self.receipt_id_ok
    }

    pub fn summary(&self) -> String {
        if self.passed() {
            "V1: PASS — all 4 hashes independently recomputed and match".to_string()
        } else {
            let fails: Vec<&str> = [
                (!self.tombstone_hash_ok).then_some("tombstone_hash"),
                (!self.deletion_event_hash_ok).then_some("deletion_event_hash"),
                (!self.certified_commitment_ok).then_some("certified_commitment"),
                (!self.receipt_id_ok).then_some("receipt_id"),
            ]
            .into_iter()
            .flatten()
            .collect();
            format!("V1: FAIL — mismatched: {}", fails.join(", "))
        }
    }
}

/// V1 verification: independently recompute the transition-linked hash fields
/// and compare against the receipt values.
///
/// ## v0.2.x formula notes
///
/// `deletion_event_hash` preimage:
/// `TAG_EVENT || pre_state_hash || post_state_hash || timestamp_be || module_hash || nonce_be`
///
/// `manifest_hash` is not part of the v0.2.x leaf-mode `deletion_event_hash`
/// preimage (it was removed in v0.2.0). Verifiers that still include
/// `manifest_hash` in this preimage will mismatch valid v0.2.x receipts.
///
/// V1 is where receipt-formula alignment is most sensitive; keep this logic
/// aligned with current MKTd02 formulas.
pub fn verify(receipt: &DeletionReceipt, canister_id: Principal) -> V1Result {
    let mut result = V1Result {
        tombstone_hash_ok: false,
        deletion_event_hash_ok: false,
        certified_commitment_ok: false,
        receipt_id_ok: false,
        details: Vec::new(),
    };

    let canister_bytes = canister_id.as_slice();
    let timestamp_bytes = receipt.timestamp.to_be_bytes();
    let deletion_seq_bytes = receipt.deletion_seq.to_be_bytes();

    // TOMBSTONE_CONSTANT = SHA-256("MKTD_TOMBSTONE_V1")
    let tombstone_constant = sha256(TOMBSTONE_SEED);

    // 1. tombstone_hash
    let expected_tombstone = hash_with_tag(TAG_TOMBSTONE_HASH, &[
        canister_bytes,
        &tombstone_constant,
        &timestamp_bytes,
        &deletion_seq_bytes,
    ]);
    result.tombstone_hash_ok = receipt.tombstone_hash == expected_tombstone;
    if !result.tombstone_hash_ok {
        result.details.push(format!(
            "tombstone_hash mismatch:\n    expected: {}\n    actual:   {}",
            hex::encode(expected_tombstone), hex::encode(receipt.tombstone_hash)
        ));
    }

    // 2. deletion_event_hash — v0.2.x formula: NO manifest_hash in preimage.
    //    Formula: TAG_EVENT || pre_state || post_state || timestamp_be || module_hash || deletion_seq_be
    let expected_event = hash_with_tag(TAG_EVENT, &[
        &receipt.pre_state_hash,
        &receipt.post_state_hash,
        &timestamp_bytes,
        &receipt.module_hash,
        &deletion_seq_bytes,
    ]);
    result.deletion_event_hash_ok = receipt.deletion_event_hash == expected_event;
    if !result.deletion_event_hash_ok {
        result.details.push(format!(
            "deletion_event_hash mismatch:\n    expected: {}\n    actual:   {}\n    \
             Note: v0.2.x formula — manifest_hash is NOT in preimage.",
            hex::encode(expected_event), hex::encode(receipt.deletion_event_hash)
        ));
    }

    // 3. certified_commitment
    let expected_cert = hash_with_tag(TAG_CERTIFIED, &[
        &receipt.post_state_hash,
        &expected_event,
    ]);
    result.certified_commitment_ok = receipt.certified_commitment == expected_cert;
    if !result.certified_commitment_ok {
        result.details.push(format!(
            "certified_commitment mismatch:\n    expected: {}\n    actual:   {}",
            hex::encode(expected_cert), hex::encode(receipt.certified_commitment)
        ));
    }

    // 4. receipt_id is protocol-version dependent:
    //    - v2: legacy formula (canister_id || nonce_be under TAG_RECEIPT)
    //    - v3: length-delimited formula with record_id + deletion_seq under TAG_RECEIPT_V3
    let expected_id = match receipt.protocol_version.as_str() {
        "mktd02-v2" => compute_receipt_id_v2(&canister_id, receipt.deletion_seq),
        "mktd02-v3" => compute_receipt_id(&canister_id, &receipt.record_id, receipt.deletion_seq),
        other => {
            result.details.push(format!(
                "unsupported protocol_version for receipt_id verification: {}",
                other
            ));
            [0u8; 32]
        }
    };
    result.receipt_id_ok = receipt.receipt_id == expected_id;
    if !result.receipt_id_ok {
        result.details.push(format!(
            "receipt_id mismatch:\n    expected: {}\n    actual:   {}",
            hex::encode(expected_id), hex::encode(receipt.receipt_id)
        ));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use zombie_core::receipt::ProtocolVersion;
    use zombie_core::hashing::{sha256, hash_with_tag, TOMBSTONE_SEED, TAG_TOMBSTONE_HASH, TAG_EVENT, TAG_CERTIFIED};
    use zombie_core::receipt::{compute_receipt_id, compute_receipt_id_v2};

    /// Golden vector test: uses identical inputs to zombie-core's own
    /// `golden_deletion_event_hash_v2` test so expected hash values are
    /// already independently verified.
    ///
    /// pre_state=[1;32], post_state=[2;32], module_hash=[3;32],
    /// timestamp=1_000_000, nonce=1, canister=aaaaa-aa
    ///
    /// IMPORTANT: manifest_hash is NOT present in the v0.2.x preimage (removed in v0.2.0).
    /// The golden `deletion_event_hash` value matches zombie-core exactly.
    /// Any formula regression (e.g. re-adding manifest_hash) will break this.
    #[test]
    fn golden_v1_full_verification_v2() {
        let canister_id = Principal::from_text("aaaaa-aa").unwrap();
        let canister_bytes = canister_id.as_slice();
        let timestamp: u64 = 1_000_000;
        let deletion_seq: u64 = 1;
        let timestamp_bytes = timestamp.to_be_bytes();
        let deletion_seq_bytes = deletion_seq.to_be_bytes();

        let pre_state_hash = [0x01u8; 32];
        let post_state_hash = [0x02u8; 32];
        let module_hash = [0x03u8; 32];

        // Compute expected hashes using v0.2.x formulas
        let tombstone_constant = sha256(TOMBSTONE_SEED);
        let tombstone_hash = hash_with_tag(TAG_TOMBSTONE_HASH, &[
            canister_bytes, &tombstone_constant, &timestamp_bytes, &deletion_seq_bytes,
        ]);
        // v0.2.x: NO manifest_hash in preimage
        let deletion_event_hash = hash_with_tag(TAG_EVENT, &[
            &pre_state_hash, &post_state_hash, &timestamp_bytes,
            &module_hash, &deletion_seq_bytes,
        ]);
        let certified_commitment = hash_with_tag(TAG_CERTIFIED, &[
            &post_state_hash, &deletion_event_hash,
        ]);
        let receipt_id = compute_receipt_id_v2(&canister_id, deletion_seq);

        // Lock down exact values.
        // deletion_event_hash matches zombie-core golden_deletion_event_hash_v2.
        assert_eq!(
            hex::encode(deletion_event_hash),
            "9078d9a080606b46298bd9d66d3dd4a75389b04f7531b53a3a0e7c8f25955023",
            "v0.2.x deletion_event_hash changed — manifest_hash must NOT be in preimage"
        );
        assert_eq!(
            hex::encode(receipt_id),
            "1f213a0f2bf4992071a7f23e72d1942e564a4e871e3decce8ac8ee27d08f534b",
            "receipt_id derivation changed"
        );

        // Build synthetic v0.2.x receipt (no manifest_hash, no commit_mode)
        let receipt = DeletionReceipt {
            protocol_version:     ProtocolVersion::V2.into(),
            receipt_id,
            canister_id,
            record_id:            Vec::new(),
            pre_state_hash,
            post_state_hash,
            tombstone_hash,
            deletion_event_hash,
            certified_commitment,
            module_hash,
            timestamp,
            deletion_seq,
            bls_certificate:  None,
            trust_root_key_id:   String::new(),
        };

        let result = verify(&receipt, canister_id);
        assert!(result.tombstone_hash_ok,        "tombstone_hash mismatch: {:?}", result.details);
        assert!(result.deletion_event_hash_ok,   "deletion_event_hash mismatch: {:?}", result.details);
        assert!(result.certified_commitment_ok,  "certified_commitment mismatch: {:?}", result.details);
        assert!(result.receipt_id_ok,            "receipt_id mismatch: {:?}", result.details);
        assert!(result.passed(),                 "V1 should pass: {:?}", result.details);
    }

    #[test]
    fn golden_v1_full_verification_v3() {
        let canister_id = Principal::from_text("aaaaa-aa").unwrap();
        let canister_bytes = canister_id.as_slice();
        let timestamp: u64 = 1_000_000;
        let deletion_seq: u64 = 2;
        let timestamp_bytes = timestamp.to_be_bytes();
        let deletion_seq_bytes = deletion_seq.to_be_bytes();

        let pre_state_hash = [0x11u8; 32];
        let post_state_hash = [0x22u8; 32];
        let module_hash = [0x33u8; 32];
        let record_id = canister_id.as_slice().to_vec();

        let tombstone_constant = sha256(TOMBSTONE_SEED);
        let tombstone_hash = hash_with_tag(TAG_TOMBSTONE_HASH, &[
            canister_bytes, &tombstone_constant, &timestamp_bytes, &deletion_seq_bytes,
        ]);
        let deletion_event_hash = hash_with_tag(TAG_EVENT, &[
            &pre_state_hash, &post_state_hash, &timestamp_bytes,
            &module_hash, &deletion_seq_bytes,
        ]);
        let certified_commitment = hash_with_tag(TAG_CERTIFIED, &[
            &post_state_hash, &deletion_event_hash,
        ]);
        let receipt_id = compute_receipt_id(&canister_id, &record_id, deletion_seq);

        let receipt = DeletionReceipt {
            protocol_version: ProtocolVersion::V3.into(),
            receipt_id,
            canister_id,
            record_id,
            pre_state_hash,
            post_state_hash,
            tombstone_hash,
            deletion_event_hash,
            certified_commitment,
            module_hash,
            timestamp,
            deletion_seq,
            bls_certificate: None,
            trust_root_key_id: String::new(),
        };

        let result = verify(&receipt, canister_id);
        assert!(result.tombstone_hash_ok,        "tombstone_hash mismatch: {:?}", result.details);
        assert!(result.deletion_event_hash_ok,   "deletion_event_hash mismatch: {:?}", result.details);
        assert!(result.certified_commitment_ok,  "certified_commitment mismatch: {:?}", result.details);
        assert!(result.receipt_id_ok,            "receipt_id mismatch: {:?}", result.details);
        assert!(result.passed(),                 "V1 should pass: {:?}", result.details);
    }
}
