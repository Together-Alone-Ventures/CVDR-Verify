use anyhow::Result;
use candid::Principal;
use ic_agent::Agent;
use crate::fetch::Receipt;

pub struct V2Result {
    pub passed: bool,
    pub detail: String,
}

impl V2Result {
    pub fn passed(&self) -> bool {
        self.passed
    }

    pub fn summary(&self) -> String {
        if self.passed {
            "V2: PASS — subnet BLS certificate valid, certified data matches commitment".to_string()
        } else {
            format!("V2: FAIL — {}", self.detail)
        }
    }
}

/// Verify the certified commitment via ICP's BLS certificate chain.
///
/// Flow:
/// 1. Read the canister's certified data via read_state
/// 2. ic-agent automatically verifies the BLS signature chain
///    (subnet sig → subnet public key → NNS root of trust)
/// 3. Compare certified data against the receipt's certified_commitment
///
/// NOTE: The ic-agent API for certificate verification has changed across
/// versions. The code below targets ic-agent 0.39.x. If you use a different
/// version, consult the ic-agent docs and adjust accordingly. The key
/// concept is:
///   - read_state_canister_info() returns verified data (agent checks BLS
///     internally)
///   - We compare the canister's certified_data against the receipt
pub async fn verify(
    agent: &Agent,
    canister_id: Principal,
    receipt: &Receipt,
) -> V2Result {
    let expected = match Receipt::hash_field(&receipt.certified_commitment, "certified_commitment") {
        Ok(h) => h,
        Err(e) => return V2Result { passed: false, detail: e.to_string() },
    };

    // Approach: Use a certified query to mktd_get_state_hash, which returns
    // the certificate alongside the data. The agent verifies the BLS chain.
    //
    // Alternative approach if the above doesn't expose the raw certified_data:
    // Use agent.read_state_canister_info(canister_id, "certified_data")
    // which returns the raw 32 bytes set via ic0.certified_data_set().
    //
    // Try read_state approach first as it's the most direct.
    match read_certified_data(agent, canister_id).await {
        Ok(certified_data) => {
            if certified_data.len() != 32 {
                return V2Result {
                    passed: false,
                    detail: format!(
                        "certified_data is {} bytes, expected 32",
                        certified_data.len()
                    ),
                };
            }
            let actual: [u8; 32] = certified_data.try_into().unwrap();
            if actual == expected {
                V2Result { passed: true, detail: String::new() }
            } else {
                V2Result {
                    passed: false,
                    detail: format!(
                        "certified_data mismatch:\n    receipt:  {}\n    on-chain: {}",
                        hex::encode(expected),
                        hex::encode(actual)
                    ),
                }
            }
        }
        Err(e) => V2Result {
            passed: false,
            detail: format!("Failed to read certified data: {}", e),
        },
    }
}

/// Read the canister's certified_data via read_state.
/// ic-agent verifies the BLS certificate chain automatically.
///
/// IMPORTANT: This is the function most likely to need adjustment based
/// on your ic-agent version. If read_state_canister_info doesn't exist
/// or has a different signature, check the ic-agent docs.
async fn read_certified_data(
    agent: &Agent,
    canister_id: Principal,
) -> Result<Vec<u8>> {
    // ic-agent provides read_state_canister_info which:
    // 1. Issues a read_state request for the given path
    // 2. Verifies the BLS certificate from the subnet
    // 3. Returns the raw bytes
    //
    // The path "certified_data" returns whatever the canister set
    // via ic0.certified_data_set()
    let certified_data = agent
        .read_state_canister_info(canister_id, "certified_data")
        .await
        .map_err(|e| anyhow::anyhow!("read_state certified_data failed: {}", e))?;

    Ok(certified_data)
}
