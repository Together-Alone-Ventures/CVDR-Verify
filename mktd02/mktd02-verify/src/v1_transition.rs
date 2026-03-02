use candid::Principal;
use zombie_core::hashing::{
    sha256, hash_with_tag,
    TAG_TOMBSTONE_HASH, TAG_EVENT, TAG_CERTIFIED, TAG_RECEIPT,
    TOMBSTONE_SEED,
};
use crate::fetch::Receipt;

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

pub fn verify(receipt: &Receipt, canister_id: Principal) -> V1Result {
    let mut result = V1Result {
        tombstone_hash_ok: false,
        deletion_event_hash_ok: false,
        certified_commitment_ok: false,
        receipt_id_ok: false,
        details: Vec::new(),
    };

    let canister_bytes = canister_id.as_slice();
    let timestamp_bytes = receipt.timestamp.to_be_bytes();
    let nonce_bytes = receipt.nonce.to_be_bytes();

    // TOMBSTONE_CONSTANT = SHA-256("MKTD_TOMBSTONE_V1")
    let tombstone_constant = sha256(TOMBSTONE_SEED);

    // 1. tombstone_hash
    let expected_tombstone = hash_with_tag(TAG_TOMBSTONE_HASH, &[
        canister_bytes,
        &tombstone_constant,
        &timestamp_bytes,
        &nonce_bytes,
    ]);
    result.tombstone_hash_ok = receipt.tombstone_hash == expected_tombstone;
    if !result.tombstone_hash_ok {
        result.details.push(format!(
            "tombstone_hash mismatch:\n    expected: {}\n    actual:   {}",
            hex::encode(expected_tombstone), hex::encode(receipt.tombstone_hash)
        ));
    }

    // 2. deletion_event_hash
    let expected_event = hash_with_tag(TAG_EVENT, &[
        &receipt.pre_state_hash,
        &receipt.post_state_hash,
        &timestamp_bytes,
        &receipt.module_hash,
        &receipt.manifest_hash,
        &nonce_bytes,
    ]);
    result.deletion_event_hash_ok = receipt.deletion_event_hash == expected_event;
    if !result.deletion_event_hash_ok {
        result.details.push(format!(
            "deletion_event_hash mismatch:\n    expected: {}\n    actual:   {}",
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

    // 4. receipt_id = hash_with_tag(TAG_RECEIPT, canister_id || nonce)
    // Note: no timestamp — matches zombie_core::receipt::compute_receipt_id()
    let expected_id = hash_with_tag(TAG_RECEIPT, &[
        canister_bytes,
        &nonce_bytes,
    ]);
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
    use zombie_core::hashing::{sha256, hash_with_tag, TOMBSTONE_SEED,
        TAG_TOMBSTONE_HASH, TAG_EVENT, TAG_CERTIFIED, TAG_RECEIPT};

    /// Golden vector test: synthetic receipt with known inputs.
    /// Locks down field ordering in every hash_with_tag call.
    /// If any input ordering changes, this test fails.
    #[test]
    fn golden_v1_full_verification() {
        let canister_id = Principal::from_text("aaaaa-aa").unwrap();
        let canister_bytes = canister_id.as_slice();
        let timestamp: u64 = 1_000_000;
        let nonce: u64 = 1;
        let timestamp_bytes = timestamp.to_be_bytes();
        let nonce_bytes = nonce.to_be_bytes();

        let pre_state_hash = [0xAA; 32];
        let post_state_hash = [0xBB; 32];
        let manifest_hash = [0xCC; 32];
        let module_hash = [0xDD; 32];

        // Compute expected hashes
        let tombstone_constant = sha256(TOMBSTONE_SEED);
        let tombstone_hash = hash_with_tag(TAG_TOMBSTONE_HASH, &[
            canister_bytes, &tombstone_constant, &timestamp_bytes, &nonce_bytes,
        ]);
        let deletion_event_hash = hash_with_tag(TAG_EVENT, &[
            &pre_state_hash, &post_state_hash, &timestamp_bytes,
            &module_hash, &manifest_hash, &nonce_bytes,
        ]);
        let certified_commitment = hash_with_tag(TAG_CERTIFIED, &[
            &post_state_hash, &deletion_event_hash,
        ]);
        let receipt_id = hash_with_tag(TAG_RECEIPT, &[
            canister_bytes, &nonce_bytes,
        ]);

        // Lock down exact values (computed once, never change)
        assert_eq!(hex::encode(tombstone_hash),
            "a7ed8b1f03c075e1c7e1a7b3cd93422a8c5b7013f5a14c4c9d3e01f5ecbf34c0");
        assert_eq!(hex::encode(receipt_id),
            "1f213a0f2bf4992071a7f23e72d1942e564a4e871e3decce8ac8ee27d08f534b");

        // Build synthetic receipt
        let receipt = Receipt {
            receipt_id,
            canister_id,
            subnet_id: Principal::from_text("2vxsx-fae").unwrap(),
            commit_mode: "Leaf".into(),
            pre_state_hash,
            post_state_hash,
            tombstone_hash,
            deletion_event_hash,
            certified_commitment,
            manifest_hash,
            module_hash,
            timestamp,
            nonce,
        };

        let result = verify(&receipt, canister_id);
        assert!(result.tombstone_hash_ok, "tombstone_hash mismatch");
        assert!(result.deletion_event_hash_ok, "deletion_event_hash mismatch");
        assert!(result.certified_commitment_ok, "certified_commitment mismatch");
        assert!(result.receipt_id_ok, "receipt_id mismatch");
        assert!(result.passed(), "V1 should pass: {:?}", result.details);
    }
}
