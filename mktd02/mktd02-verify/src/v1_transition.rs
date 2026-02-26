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
    let timestamp_bytes = receipt.timestamp.to_le_bytes();
    let nonce_bytes = receipt.nonce.to_le_bytes();

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

    // 4. receipt_id
    let expected_id = hash_with_tag(TAG_RECEIPT, &[
        canister_bytes,
        &timestamp_bytes,
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
