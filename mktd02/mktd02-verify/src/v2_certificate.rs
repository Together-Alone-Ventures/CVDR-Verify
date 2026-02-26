use candid::Principal;
use ic_agent::Agent;
use ic_agent::hash_tree::{Label, LookupResult};
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

pub async fn verify(
    agent: &Agent,
    canister_id: Principal,
    receipt: &Receipt,
) -> V2Result {
    let expected = receipt.certified_commitment;

    // Read certified_data via read_state with explicit path construction.
    // ic-agent verifies the BLS certificate chain automatically.
    let paths: Vec<Vec<Label<Vec<u8>>>> = vec![vec![
        Label::from(b"canister".to_vec()),
        Label::from(canister_id.as_slice().to_vec()),
        Label::from(b"certified_data".to_vec()),
    ]];

    let certificate = match agent.read_state_raw(paths, canister_id).await {
        Ok(cert) => cert,
        Err(e) => {
            return V2Result {
                passed: false,
                detail: format!("read_state failed: {}. V2 requires the canister to have set certified data via ic0.certified_data_set().", e),
            };
        }
    };

    // Look up certified_data in the verified certificate's hash tree
    let path: Vec<Label<&[u8]>> = vec![
        Label::from("canister".as_bytes()),
        Label::from(canister_id.as_slice()),
        Label::from("certified_data".as_bytes()),
    ];

    match certificate.tree.lookup_path(&path) {
        LookupResult::Found(data) => {
            if data.len() != 32 {
                return V2Result {
                    passed: false,
                    detail: format!("certified_data is {} bytes, expected 32", data.len()),
                };
            }
            let actual: [u8; 32] = data.try_into().unwrap();
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
        LookupResult::Absent => {
            V2Result {
                passed: false,
                detail: "certified_data absent from state tree".to_string(),
            }
        }
        _ => {
            V2Result {
                passed: false,
                detail: "certified_data lookup returned unexpected result".to_string(),
            }
        }
    }
}
