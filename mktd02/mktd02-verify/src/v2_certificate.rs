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
    let _cert_bytes = match resp.certificate {
        Some(c) => c.into_vec(),
        None => return V2Result {
            passed: false,
            detail: "Certificate not present in query response. The canister returned null for the certificate field. This typically means the mktd_get_state_hash endpoint does not call ic0.data_certificate() during query execution. V2 requires a certified query response — this is a known limitation that will be resolved when the library properly surfaces the ICP certificate.".to_string(),
        },
    };

    // TODO: When a certificate is present, verify the BLS signature chain
    // and look up certified_data in the certificate tree. This requires
    // ic-agent's Certificate parsing API, which varies across versions.
    // For now, if we reach here, the certificate exists but we need to
    // implement the full verification pipeline.
    //
    // The verification steps would be:
    // 1. Parse CBOR certificate
    // 2. Verify BLS signature against subnet public key via NNS root
    // 3. Look up canister/<id>/certified_data in the hash tree
    // 4. Compare
