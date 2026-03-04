use candid::{CandidType, Decode, Encode, Principal};
use ic_agent::Agent;
use serde::Deserialize;
use zombie_core::receipt::DeletionReceipt;

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
            "V2: PASS — subnet BLS certificate valid, certified data matches commitment"
                .to_string()
        } else {
            format!("V2: FAIL — {}", self.detail)
        }
    }
}

pub async fn verify(
    agent: &Agent,
    canister_id: Principal,
    receipt: &DeletionReceipt,
) -> V2Result {
    let expected = receipt.certified_commitment;

    // Step 1: Query mktd_get_state_hash — returns certificate + hash.
    // The canister calls ic0.data_certificate() during this query,
    // embedding the subnet's BLS-signed certificate in the response.
    //
    // NOTE: This query MUST be an ingress query (external caller).
    // Canister-to-canister calls cannot obtain the certificate blob even
    // if the target method is declared as query — they always go through
    // consensus. This is a foundational ICP platform constraint.
    //
    // TODO(Change A): use receipt.trust_root_key_id to select the correct
    // NNS root key from the zombie-core allowlist. Never assume the current
    // active key is the right one for a historical receipt.
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

    // Step 2: Check certificate is present
    let cert_bytes = match resp.certificate {
        Some(c) => c.into_vec(),
        None => return V2Result {
            passed: false,
            detail: "Certificate not present in query response. \
                The canister's mktd_get_state_hash endpoint returned null \
                for the certificate field. This may occur with anonymous \
                queries or if the endpoint does not call \
                ic0.data_certificate()."
                .to_string(),
        },
    };

    // Step 3: Parse CBOR certificate into ic-agent's Certificate type
    let certificate: ic_agent::Certificate = match serde_cbor::from_slice(&cert_bytes) {
        Ok(c) => c,
        Err(e) => return V2Result {
            passed: false,
            detail: format!("Failed to parse certificate CBOR: {}", e),
        },
    };

    // Step 4: Verify BLS signature chain.
    // agent.verify() checks:
    //   - The BLS signature on the tree root hash
    //   - The delegation chain (subnet key → NNS root of trust)
    //   - That the certificate has authority over this canister
    if let Err(e) = agent.verify(&certificate, canister_id) {
        return V2Result {
            passed: false,
            detail: format!("BLS certificate verification failed: {}", e),
        };
    }

    // Step 5: Look up certified_data in the verified hash tree.
    // Path: ["canister", <canister_id_bytes>, "certified_data"]
    // This is the 32-byte value the canister set via ic0.certified_data_set().
    match ic_agent::lookup_value(&certificate, [
        b"canister".as_ref(),
        canister_id.as_slice(),
        b"certified_data".as_ref(),
    ]) {
        Ok(data) => {
            if data.len() != 32 {
                return V2Result {
                    passed: false,
                    detail: format!(
                        "certified_data is {} bytes, expected 32",
                        data.len()
                    ),
                };
            }
            let actual: [u8; 32] = data.try_into().unwrap();
            if actual == expected {
                V2Result { passed: true, detail: String::new() }
            } else {
                V2Result {
                    passed: false,
                    detail: format!(
                        "certified_data mismatch:\n  receipt:  {}\n  on-chain: {}",
                        hex::encode(expected),
                        hex::encode(actual)
                    ),
                }
            }
        }
        Err(e) => V2Result {
            passed: false,
            detail: format!("certified_data not found in certificate tree: {:?}", e),
        },
    }
}
