use candid::{CandidType, Decode, Encode, Principal};
use ic_agent::Agent;
use serde::Deserialize;
use crate::fetch::Receipt;

#[derive(Debug, CandidType, Deserialize)]
struct StateHashCertified {
    pub certificate: Option<serde_bytes::ByteBuf>,
    pub hash: serde_bytes::ByteBuf,
}

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

    // V2 requires a certified query response containing an ICP certificate.
    // The canister's mktd_get_state_hash endpoint should return a certificate
    // (from ic0.data_certificate()) when called as a certified query.
    // 
    // Note: Anonymous queries may not receive certificates on all subnets.
    // If the certificate is null, V2 cannot be completed.

    let arg = match Encode!() {
        Ok(a) => a,
        Err(e) => return V2Result {
            passed: false,
            detail: format!("Failed to encode query args: {}", e),
        },
    };

    let response = match agent
        .query(&canister_id, "mktd_get_state_hash")
        .with_arg(arg)
        .call()
        .await
    {
        Ok(r) => r,
        Err(e) => return V2Result {
            passed: false,
            detail: format!("query mktd_get_state_hash failed: {}", e),
        },
    };

    let resp = match Decode!(&response, StateHashCertified) {
        Ok(r) => r,
        Err(e) => return V2Result {
            passed: false,
            detail: format!("failed to decode state hash response: {}", e),
        },
    };

    // Check if certificate is present
    let cert_bytes = match resp.certificate {
        Some(c) => c.into_vec(),
        None => return V2Result {
            passed: false,
            detail: "Certificate not present in query response. The canister's mktd_get_state_hash endpoint returned null for the certificate field. This may occur with anonymous queries or if the endpoint does not call ic0.data_certificate(). V2 verification requires a certified query.".to_string(),
        },
    };

    // Parse and verify the certificate using ic-agent
    // ic-agent's Certificate verification checks the BLS signature chain
    use ic_agent::agent::status::Status;

    match ic_agent::Certificate::from_cbor(&cert_bytes) {
        Ok(certificate) => {
            // Verify the certificate against the root key
            match agent.verify(&certificate, canister_id) {
                Ok(()) => {
                    // Look up certified_data in the tree
                    use ic_agent::hash_tree::{Label, LookupResult};
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
                        _ => V2Result {
                            passed: false,
                            detail: "certified_data not found in certificate tree".to_string(),
                        },
                    }
                }
                Err(e) => V2Result {
                    passed: false,
                    detail: format!("Certificate verification failed: {}", e),
                },
            }
        }
        Err(e) => V2Result {
            passed: false,
            detail: format!("Failed to parse certificate CBOR: {}", e),
        },
    }
}
