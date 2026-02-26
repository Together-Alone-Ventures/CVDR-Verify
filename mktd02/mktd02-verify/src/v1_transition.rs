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

    // Extract hash fields
    let pre_state = match Receipt::hash_field(&receipt.pre_state_hash, "pre_state_hash") {
        Ok(h) => h,
        Err(e) => { result.details.push(e.to_string()); return result; }
    };
    let post_state = match Receipt::hash_field(&receipt.post_state_hash, "post_state_hash") {
        Ok(h) => h,
        Err(e) => { result.details.push(e.to_string()); return result; }
    };
    let module = match Receipt::hash_field(&receipt.module_hash, "module_hash") {
        Ok(h) => h,
        Err(e) => { result.details.push(e.to_string()); return result; }
    };
    let manifest = match Receipt::hash_field(&receipt.manifest_hash, "manifest_hash") {
        Ok(h) => h,
        Err(e) => { result.details.push(e.to_string()); return result; }
    };

    let canister_bytes = canister_id.as_slice();
    let timestamp_bytes = receipt.timestamp.to_le_bytes();
    let nonce_bytes = receipt.nonce.to_le_bytes();

    // TOMBSTONE_CONSTANT = SHA-256("MKTD_TOMBSTONE_V1")
    let tombstone_constant = sha256(TOMBSTONE_SEED);

    // 1. tombstone_hash = hash_with_tag(TAG_TOMBSTONE_HASH, canister_id || TOMBSTONE_CONSTANT || timestamp || nonce)
    let expected_tombstone = hash_with_tag(TAG_TOMBSTONE_HASH, &[
        canister_bytes,
        &tombstone_constant,
        &timestamp_bytes,
        &nonce_bytes,
    ]);

    match Receipt::hash_field(&receipt.tombstone_hash, "tombstone_hash") {
        Ok(actual) => {
            result.tombstone_hash_ok = actual == expected_tombstone;
            if !result.tombstone_hash_ok {
                result.details.push(format!(
                    "tombstone_hash mismatch:\n    expected: {}\n    actual:   {}",
                    hex::encode(expected_tombstone), hex::encode(actual)
                ));
            }
        }
        Err(e) => result.details.push(e.to_string()),
    }

    // 2. deletion_event_hash = hash_with_tag(TAG_EVENT, pre || post || timestamp || module || manifest || nonce)
    let expected_event = hash_with_tag(TAG_EVENT, &[
        &pre_state,
        &post_state,
        &timestamp_bytes,
        &module,
        &manifest,
        &nonce_bytes,
    ]);

    match Receipt::hash_field(&receipt.deletion_event_hash, "deletion_event_hash") {
        Ok(actual) => {
            result.deletion_event_hash_ok = actual == expected_event;
            if !result.deletion_event_hash_ok {
                result.details.push(format!(
                    "deletion_event_hash mismatch:\n    expected: {}\n    actual:   {}",
                    hex::encode(expected_event), hex::encode(actual)
                ));
            }
        }
        Err(e) => result.details.push(e.to_string()),
    }

    // 3. certified_commitment = hash_with_tag(TAG_CERTIFIED, post_state || deletion_event_hash)
    let expected_cert = hash_with_tag(TAG_CERTIFIED, &[
        &post_state,
        &expected_event,
    ]);

    match Receipt::hash_field(&receipt.certified_commitment, "certified_commitment") {
        Ok(actual) => {
            result.certified_commitment_ok = actual == expected_cert;
            if !result.certified_commitment_ok {
                result.details.push(format!(
                    "certified_commitment mismatch:\n    expected: {}\n    actual:   {}",
                    hex::encode(expected_cert), hex::encode(actual)
                ));
            }
        }
        Err(e) => result.details.push(e.to_string()),
    }

    // 4. receipt_id = hash_with_tag(TAG_RECEIPT, canister_id || timestamp || nonce)
    let expected_id = hash_with_tag(TAG_RECEIPT, &[
        canister_bytes,
        &timestamp_bytes,
        &nonce_bytes,
    ]);

    match Receipt::hash_field(&receipt.receipt_id, "receipt_id") {
        Ok(actual) => {
            result.receipt_id_ok = actual == expected_id;
            if !result.receipt_id_ok {
                result.details.push(format!(
                    "receipt_id mismatch:\n    expected: {}\n    actual:   {}",
                    hex::encode(expected_id), hex::encode(actual)
                ));
            }
        }
        Err(e) => result.details.push(e.to_string()),
    }

    result
}
