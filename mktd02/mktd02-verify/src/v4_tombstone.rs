use anyhow::Result;
use candid::{CandidType, Decode, Encode, Principal};
use ic_agent::Agent;
use serde::Deserialize;
use crate::fetch::Receipt;

#[derive(Debug, CandidType, Deserialize)]
pub struct TombstoneStatus {
    pub is_tombstoned: bool,
    pub tombstoned_at: Option<u64>,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct StateHashResponse {
    pub certificate: Option<serde_bytes::ByteBuf>,
    pub hash: serde_bytes::ByteBuf,
}

pub struct V4Result {
    pub tombstone_ok: bool,
    pub state_hash_ok: bool,
    pub detail: String,
}

impl V4Result {
    pub fn passed(&self) -> bool {
        self.tombstone_ok && self.state_hash_ok
    }

    pub fn summary(&self) -> String {
        if self.passed() {
            "V4: PASS — tombstone intact, state hash matches".to_string()
        } else {
            format!("V4: FAIL — {}", self.detail)
        }
    }
}

pub async fn verify(
    agent: &Agent,
    canister_id: Principal,
    receipt: &Receipt,
) -> V4Result {
    let post_state = receipt.post_state_hash;

    // Check tombstone status
    let tombstone = match query_tombstone_status(agent, canister_id).await {
        Ok(t) => t,
        Err(e) => return V4Result {
            tombstone_ok: false,
            state_hash_ok: false,
            detail: format!("tombstone status query failed: {}", e),
        },
    };

    if !tombstone.is_tombstoned {
        return V4Result {
            tombstone_ok: false,
            state_hash_ok: false,
            detail: "canister is not tombstoned".to_string(),
        };
    }

    // Check current state hash matches post_state_hash
    let current_hash = match query_state_hash(agent, canister_id).await {
        Ok(h) => h,
        Err(e) => return V4Result {
            tombstone_ok: true,
            state_hash_ok: false,
            detail: format!("state hash query failed: {}", e),
        },
    };

    if current_hash == post_state {
        V4Result {
            tombstone_ok: true,
            state_hash_ok: true,
            detail: String::new(),
        }
    } else {
        V4Result {
            tombstone_ok: true,
            state_hash_ok: false,
            detail: format!(
                "state hash diverged (possible resurrection):\n    receipt:  {}\n    current: {}",
                hex::encode(post_state),
                hex::encode(current_hash)
            ),
        }
    }
}

async fn query_tombstone_status(
    agent: &Agent,
    canister_id: Principal,
) -> Result<TombstoneStatus> {
    let arg = Encode!()?;
    let response = agent
        .query(&canister_id, "mktd_get_tombstone_status")
        .with_arg(arg)
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("query mktd_get_tombstone_status failed: {}", e))?;

    Decode!(&response, TombstoneStatus)
        .map_err(|e| anyhow::anyhow!("failed to decode tombstone status: {}", e))
}

async fn query_state_hash(
    agent: &Agent,
    canister_id: Principal,
) -> Result<[u8; 32]> {
    let arg = Encode!()?;
    let response = agent
        .query(&canister_id, "mktd_get_state_hash")
        .with_arg(arg)
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("query mktd_get_state_hash failed: {}", e))?;

    // Try as StateHashResponse struct (record with certificate + hash as blobs)
    if let Ok(resp) = Decode!(&response, StateHashResponse) {
        let bytes: Vec<u8> = resp.hash.into_vec();
        return bytes.try_into()
            .map_err(|_| anyhow::anyhow!("state hash is not 32 bytes"));
    }

    // Try as plain blob
    if let Ok(hash_bytes) = Decode!(&response, serde_bytes::ByteBuf) {
        let bytes: Vec<u8> = hash_bytes.into_vec();
        return bytes.try_into()
            .map_err(|_| anyhow::anyhow!("state hash is not 32 bytes"));
    }

    // Try as hex string
    if let Ok(hash_hex) = Decode!(&response, String) {
        let bytes = hex::decode(&hash_hex)
            .map_err(|e| anyhow::anyhow!("state hash hex decode failed: {}", e))?;
        return bytes.try_into()
            .map_err(|_| anyhow::anyhow!("state hash is not 32 bytes"));
    }

    Err(anyhow::anyhow!("could not decode state hash response"))
}
