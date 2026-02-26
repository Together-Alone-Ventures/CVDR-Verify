use anyhow::{anyhow, Result};
use candid::{CandidType, Decode, Encode, Principal};
use ic_agent::Agent;
use serde::Deserialize;

/// CVDR receipt as returned by mktd_get_receipt()
/// The canister returns hash fields as hex strings, not blobs.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct RawReceipt {
    pub receipt_id: String,
    pub canister_id: Principal,
    pub subnet_id: Principal,
    pub commit_mode: String,
    pub pre_state_hash: String,
    pub post_state_hash: String,
    pub tombstone_hash: String,
    pub deletion_event_hash: String,
    pub certified_commitment: String,
    pub manifest_hash: String,
    pub module_hash: String,
    pub timestamp: u64,
    pub nonce: u64,
}

/// Parsed receipt with hash fields as byte arrays
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Receipt {
    pub receipt_id: [u8; 32],
    pub canister_id: Principal,
    pub subnet_id: Principal,
    pub commit_mode: String,
    pub pre_state_hash: [u8; 32],
    pub post_state_hash: [u8; 32],
    pub tombstone_hash: [u8; 32],
    pub deletion_event_hash: [u8; 32],
    pub certified_commitment: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub module_hash: [u8; 32],
    pub timestamp: u64,
    pub nonce: u64,
}

fn decode_hash(hex_str: &str, field: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| anyhow!("{}: invalid hex: {}", field, e))?;
    bytes.try_into()
        .map_err(|_| anyhow!("{}: expected 32 bytes, got {}", field, hex_str.len() / 2))
}

impl RawReceipt {
    pub fn into_receipt(self) -> Result<Receipt> {
        Ok(Receipt {
            receipt_id: decode_hash(&self.receipt_id, "receipt_id")?,
            canister_id: self.canister_id,
            subnet_id: self.subnet_id,
            commit_mode: self.commit_mode,
            pre_state_hash: decode_hash(&self.pre_state_hash, "pre_state_hash")?,
            post_state_hash: decode_hash(&self.post_state_hash, "post_state_hash")?,
            tombstone_hash: decode_hash(&self.tombstone_hash, "tombstone_hash")?,
            deletion_event_hash: decode_hash(&self.deletion_event_hash, "deletion_event_hash")?,
            certified_commitment: decode_hash(&self.certified_commitment, "certified_commitment")?,
            manifest_hash: decode_hash(&self.manifest_hash, "manifest_hash")?,
            module_hash: decode_hash(&self.module_hash, "module_hash")?,
            timestamp: self.timestamp,
            nonce: self.nonce,
        })
    }
}

/// Fetch a receipt from the canister by hex-encoded receipt_id
pub async fn fetch_receipt(
    agent: &Agent,
    canister_id: Principal,
    receipt_id_hex: &str,
) -> Result<Receipt> {
    let arg = Encode!(&receipt_id_hex)?;

    let response = agent
        .query(&canister_id, "mktd_get_receipt")
        .with_arg(arg)
        .call()
        .await
        .map_err(|e| anyhow!("Query mktd_get_receipt failed: {}", e))?;

    // Canister returns opt record (Option<RawReceipt>)
    if let Ok(Some(raw)) = Decode!(&response, Option<RawReceipt>) {
        return raw.into_receipt();
    }

    // Fallback: try direct decode
    if let Ok(raw) = Decode!(&response, RawReceipt) {
        return raw.into_receipt();
    }

    Err(anyhow!("Failed to decode receipt — check Candid interface"))
}
