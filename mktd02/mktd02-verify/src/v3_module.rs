use anyhow::Result;
use candid::Principal;
use ic_agent::Agent;
use zombie_core::receipt::DeletionReceipt;

pub enum V3Classification {
    Match,
    MismatchExpected,
    MismatchSuspicious,
    FullMatch,
    MismatchExpectedWithProvenance,
    Failed(String),
}

pub struct V3Result {
    pub classification: V3Classification,
}

#[allow(dead_code)]
impl V3Result {
    pub fn passed(&self) -> bool {
        // V3 doesn't have a hard pass/fail — only SUSPICIOUS is a concern
        !matches!(
            self.classification,
            V3Classification::MismatchSuspicious | V3Classification::Failed(_)
        )
    }

    pub fn summary(&self) -> String {
        match &self.classification {
            V3Classification::Match =>
                "V3: MATCH — canister code unchanged since deletion".to_string(),
            V3Classification::MismatchExpected =>
                "V3: MISMATCH-EXPECTED — canister upgraded since deletion \
                 (receipt remains valid under prior code version)".to_string(),
            V3Classification::MismatchSuspicious =>
                "V3: MISMATCH-SUSPICIOUS — receipt has dev zeros, \
                 cannot verify code provenance".to_string(),
            V3Classification::FullMatch =>
                "V3: FULL MATCH — code provenance confirmed end-to-end \
                 (on-chain == receipt == published)".to_string(),
            V3Classification::MismatchExpectedWithProvenance =>
                "V3: MISMATCH-EXPECTED with provenance — upgraded since deletion, \
                 but deletion-time code confirmed against published hash".to_string(),
            V3Classification::Failed(e) =>
                format!("V3: FAILED — {}", e),
        }
    }
}

/// Verify module hash: on-chain vs receipt, optionally vs published build.
pub async fn verify(
    agent: &Agent,
    canister_id: Principal,
    receipt: &DeletionReceipt,
    published_hash: Option<[u8; 32]>,
) -> V3Result {
    let receipt_hash = receipt.module_hash;
    let zeros = [0u8; 32];

    // Fetch current on-chain module hash
    let onchain_hash = match read_module_hash(agent, canister_id).await {
        Ok(h) => h,
        Err(e) => return V3Result {
            classification: V3Classification::Failed(
                format!("Could not read module hash: {}", e)
            ),
        },
    };

    // Three-way classification
    if receipt_hash == zeros {
        return V3Result { classification: V3Classification::MismatchSuspicious };
    }

    if onchain_hash == receipt_hash {
        match published_hash {
            Some(pub_hash) if pub_hash == receipt_hash => {
                V3Result { classification: V3Classification::FullMatch }
            }
            Some(_) => V3Result {
                classification: V3Classification::Failed(
                    "on-chain matches receipt but differs from published hash — investigate"
                        .to_string()
                ),
            },
            None => V3Result { classification: V3Classification::Match },
        }
    } else {
        match published_hash {
            Some(pub_hash) if pub_hash == receipt_hash => {
                V3Result { classification: V3Classification::MismatchExpectedWithProvenance }
            }
            _ => V3Result { classification: V3Classification::MismatchExpected },
        }
    }
}

/// Read the canister's current module hash via read_state.
async fn read_module_hash(agent: &Agent, canister_id: Principal) -> Result<[u8; 32]> {
    let hash_bytes = agent
        .read_state_canister_info(canister_id, "module_hash")
        .await
        .map_err(|e| anyhow::anyhow!("read_state module_hash failed: {}", e))?;

    hash_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("module_hash from IC is not 32 bytes"))
}
