use anyhow::{anyhow, Result};
use candid::{CandidType, Decode, Encode, Principal};
use ic_agent::Agent;
use serde::Deserialize;

/// CVDR receipt as returned by mktd_get_receipt()
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct Receipt {
    pub receipt_id: Vec<u8>,
    pub canister_id: Principal,
    pub subnet_id: Principal,
    pub commit_mode: String,
    pub pre_state_hash: Vec<u8>,
    pub post_state_hash: Vec<u8>,
    pub tombstone_hash: Vec<u8>,
    pub deletion_event_hash: Vec<u8>,
    pub certified_commitment: Vec<u8>,
    pub manifest_hash: Vec<u8>,
    pub module_hash: Vec<u8>,
    pub timestamp: u64,
    pub nonce: u64,
}

impl Receipt {
    /// Extract a [u8; 32] from a Vec<u8> field, or error
    pub fn hash_field(field: &[u8], name: &str) -> Result<[u8; 32]> {
        field.try_into()
            .map_err(|_| anyhow!("{} is not 32 bytes (got {})", name, field.len()))
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

    // The canister returns Result<Receipt, String> — try to decode
    // First try direct Receipt decode, then try Result wrapper
    if let Ok(receipt) = Decode!(&response, Receipt) {
        return Ok(receipt);
    }

    // Try as Result<Receipt, String>
    match Decode!(&response, std::result::Result<Receipt, String>) {
        Ok(Ok(receipt)) => Ok(receipt),
        Ok(Err(e)) => Err(anyhow!("Canister returned error: {}", e)),
        Err(e) => Err(anyhow!("Failed to decode receipt response: {}", e)),
    }
}
