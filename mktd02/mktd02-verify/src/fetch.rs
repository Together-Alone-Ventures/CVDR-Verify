use anyhow::{anyhow, Result};
use candid::{Decode, Encode, Principal};
use ic_agent::Agent;
use serde::Deserialize;
use serde_json::Value;
use std::fs;
use zombie_core::receipt::DeletionReceipt;

/// Fetch a CVDR receipt from the canister by hex-encoded receipt ID.
///
/// The canister returns `Option<DeletionReceipt>` in Candid. This verifier
/// first attempts optional decode, then falls back to direct decode for
/// compatibility with endpoint/interface variation.
///
/// ## Trust root key note
/// Receipts include `trust_root_key_id` used by V2 certificate-path checks.
/// Pending receipts may carry an empty key id until finalization data exists.
pub async fn fetch_receipt(
    agent: &Agent,
    canister_id: Principal,
    receipt_id_hex: &str,
) -> Result<DeletionReceipt> {
    let arg = Encode!(&receipt_id_hex)?;

    let response = agent
        .query(&canister_id, "mktd_get_receipt")
        .with_arg(arg)
        .call()
        .await
        .map_err(|e| anyhow!("Query mktd_get_receipt failed: {}", e))?;

    // Primary: canister returns opt DeletionReceipt
    if let Ok(Some(receipt)) = Decode!(&response, Option<DeletionReceipt>) {
        validate_v2_fields(&receipt, canister_id)?;
        return Ok(receipt);
    }

    // Fallback: try direct (non-optional) decode
    if let Ok(receipt) = Decode!(&response, DeletionReceipt) {
        validate_v2_fields(&receipt, canister_id)?;
        return Ok(receipt);
    }

    Err(anyhow!(
        "Failed to decode receipt from canister {} — check Candid interface compatibility with current zombie-core/MKTd02 receipt types (including bls_certificate/trust_root_key_id fields)",
        canister_id
    ))
}

#[derive(Debug, Deserialize)]
struct FileReceipt {
    protocol_version: String,
    receipt_id: String,
    canister_id: String,
    subnet_id: String,
    pre_state_hash: String,
    post_state_hash: String,
    tombstone_hash: String,
    deletion_event_hash: String,
    certified_commitment: String,
    module_hash: String,
    timestamp: Value,
    nonce: Value,
    #[serde(default)]
    bls_certificate: Option<Vec<u8>>,
    #[serde(default)]
    trust_root_key_id: Option<String>,
    #[serde(default)]
    profile_canister: Option<String>,
}

/// Load a DaffyDefs-exported receipt JSON file and map it into DeletionReceipt.
pub fn load_receipt_from_file(path: &str) -> Result<DeletionReceipt> {
    let raw = fs::read_to_string(path)
        .map_err(|e| anyhow!("Failed to read receipt file '{}': {}", path, e))?;
    let wire: FileReceipt = serde_json::from_str(&raw)
        .map_err(|e| anyhow!("Failed to parse receipt JSON '{}': {}", path, e))?;

    if let Some(profile_canister) = wire.profile_canister.as_deref() {
        if profile_canister == wire.canister_id {
            eprintln!(
                "Note: canister_id matches profile_canister (expected in Leaf mode)."
            );
        }
    }

    let trust_root_key_id = match wire.trust_root_key_id {
        Some(v) => v,
        None => {
            if wire.bls_certificate.is_some() {
                return Err(anyhow!(
                    "Finalized receipt file has bls_certificate but missing trust_root_key_id"
                ));
            }
            String::new()
        }
    };

    if wire.bls_certificate.is_some() && trust_root_key_id.trim().is_empty() {
        return Err(anyhow!(
            "Finalized receipt file has bls_certificate but empty trust_root_key_id"
        ));
    }

    let canister_id = Principal::from_text(&wire.canister_id)
        .map_err(|e| anyhow!("Invalid canister_id in receipt file: {}", e))?;

    let receipt = DeletionReceipt {
        protocol_version: wire.protocol_version,
        receipt_id: decode_hex32("receipt_id", &wire.receipt_id)?,
        canister_id,
        subnet_id: Principal::from_text(&wire.subnet_id)
            .map_err(|e| anyhow!("Invalid subnet_id in receipt file: {}", e))?,
        pre_state_hash: decode_hex32("pre_state_hash", &wire.pre_state_hash)?,
        post_state_hash: decode_hex32("post_state_hash", &wire.post_state_hash)?,
        tombstone_hash: decode_hex32("tombstone_hash", &wire.tombstone_hash)?,
        deletion_event_hash: decode_hex32("deletion_event_hash", &wire.deletion_event_hash)?,
        certified_commitment: decode_hex32("certified_commitment", &wire.certified_commitment)?,
        module_hash: decode_hex32("module_hash", &wire.module_hash)?,
        timestamp: parse_u64_field("timestamp", &wire.timestamp)?,
        nonce: parse_u64_field("nonce", &wire.nonce)?,
        bls_certificate: wire.bls_certificate,
        trust_root_key_id,
    };

    validate_v2_fields(&receipt, receipt.canister_id)?;
    Ok(receipt)
}

fn parse_u64_field(name: &str, value: &Value) -> Result<u64> {
    match value {
        Value::String(s) => s
            .parse::<u64>()
            .map_err(|e| anyhow!("Invalid {} '{}': {}", name, s, e)),
        Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| anyhow!("Invalid {} number '{}': expected u64", name, n)),
        _ => Err(anyhow!("Invalid {} type: expected string or number", name)),
    }
}

fn decode_hex32(field: &str, hex_str: &str) -> Result<[u8; 32]> {
    let s = hex_str.trim();
    let bytes = hex::decode(s)
        .map_err(|e| anyhow!("Invalid {} hex '{}': {}", field, s, e))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{} must be 32 bytes (64 hex chars)", field))
}

fn validate_v2_fields(receipt: &DeletionReceipt, canister_id: Principal) -> Result<()> {
    // Finalized-style receipts must carry explicit trust metadata.
    if receipt.bls_certificate.is_some() && receipt.trust_root_key_id.trim().is_empty() {
        return Err(anyhow!(
            "Receipt from canister {} has embedded bls_certificate but missing trust_root_key_id",
            canister_id
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Golden receipt fixture
// ---------------------------------------------------------------------------
// These tests assert that zombie-core's canonical DeletionReceipt round-trips
// through CBOR serialisation correctly and that critical hash fields are
// preserved exactly. If zombie-core's serialisation changes in a way that
// alters field values, these tests will catch it before the change reaches
// production.
//
// We do NOT store a raw CBOR blob here because the blob would need to be
// regenerated every time a non-hash field (e.g. protocol_version string)
// changes. Instead we assert field-level round-trip fidelity and exact hash
// values — which is what matters for verification correctness.
#[cfg(test)]
mod tests {
    use super::*;
    use candid::Principal;
    use zombie_core::receipt::ProtocolVersion;

    fn golden_receipt() -> DeletionReceipt {
        DeletionReceipt {
            protocol_version: ProtocolVersion::V2.into(),
            receipt_id: [0x1F; 32],
            canister_id: Principal::from_text("aaaaa-aa").unwrap(),
            subnet_id: Principal::from_text("2vxsx-fae").unwrap(),
            pre_state_hash: [0xAA; 32],
            post_state_hash: [0xBB; 32],
            tombstone_hash: [0xCC; 32],
            deletion_event_hash: [0xDD; 32],
            certified_commitment: [0xEE; 32],
            module_hash: [0xFF; 32],
            timestamp: 1_000_000,
            nonce: 1,
            bls_certificate: None,
            trust_root_key_id: String::from("mainnet"),
        }
    }

    /// Hash fields must survive CBOR round-trip without any byte mutation.
    /// This guards against accidental endianness swaps, truncation, or
    /// field reordering in zombie-core's serialisation layer.
    #[test]
    fn golden_receipt_cbor_round_trip() {
        let original = golden_receipt();

        // Encode to CBOR
        let mut buf = Vec::new();
        ciborium::into_writer(&original, &mut buf).expect("CBOR encode failed");

        // Decode back
        let decoded: DeletionReceipt =
            ciborium::from_reader(buf.as_slice()).expect("CBOR decode failed");

        // All hash fields must be byte-identical
        assert_eq!(
            decoded.receipt_id, original.receipt_id,
            "receipt_id mutated"
        );
        assert_eq!(
            decoded.pre_state_hash, original.pre_state_hash,
            "pre_state_hash mutated"
        );
        assert_eq!(
            decoded.post_state_hash, original.post_state_hash,
            "post_state_hash mutated"
        );
        assert_eq!(
            decoded.tombstone_hash, original.tombstone_hash,
            "tombstone_hash mutated"
        );
        assert_eq!(
            decoded.deletion_event_hash, original.deletion_event_hash,
            "deletion_event_hash mutated"
        );
        assert_eq!(
            decoded.certified_commitment, original.certified_commitment,
            "certified_commitment mutated"
        );
        assert_eq!(
            decoded.module_hash, original.module_hash,
            "module_hash mutated"
        );
        assert_eq!(decoded.timestamp, original.timestamp, "timestamp mutated");
        assert_eq!(decoded.nonce, original.nonce, "nonce mutated");
        assert_eq!(
            decoded.protocol_version, original.protocol_version,
            "protocol_version mutated"
        );
        assert_eq!(
            decoded.trust_root_key_id, original.trust_root_key_id,
            "trust_root_key mutated"
        );
    }

    /// Protocol version string must be exactly "mktd02-v2" — not an enum
    /// variant name, not a numeric code. Verifiers parse this string.
    #[test]
    fn golden_protocol_version_string() {
        let r = golden_receipt();
        assert_eq!(
            r.protocol_version, "mktd02-v2",
            "protocol_version string changed — verifiers parse this field directly"
        );
    }

    /// receipt_id golden vector — matches zombie-core's own golden test.
    /// canister = aaaaa-aa (empty bytes), nonce = 1.
    #[test]
    fn golden_receipt_id_matches_zombie_core() {
        use zombie_core::receipt::compute_receipt_id;
        let c = Principal::from_text("aaaaa-aa").unwrap();
        let id = compute_receipt_id(&c, 1);
        assert_eq!(
            hex::encode(id),
            "1f213a0f2bf4992071a7f23e72d1942e564a4e871e3decce8ac8ee27d08f534b",
            "receipt_id derivation changed — breaks all existing receipts"
        );
    }

    #[test]
    fn file_receipt_parses_integer_bls_array() {
        let path = std::env::temp_dir().join(format!(
            "cvdr_verify_receipt_{}_{}.json",
            std::process::id(),
            1
        ));
        let json = r#"{
  "protocol_version": "mktd02-v2",
  "receipt_id": "1f213a0f2bf4992071a7f23e72d1942e564a4e871e3decce8ac8ee27d08f534b",
  "canister_id": "aaaaa-aa",
  "subnet_id": "2vxsx-fae",
  "pre_state_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "post_state_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "tombstone_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "deletion_event_hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  "certified_commitment": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
  "module_hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "timestamp": "1000000",
  "nonce": "1",
  "bls_certificate": [1,2,3,4],
  "trust_root_key_id": "mainnet",
  "profile_canister": "aaaaa-aa"
}"#;

        fs::write(&path, json).unwrap();
        let receipt = load_receipt_from_file(path.to_str().unwrap()).unwrap();
        fs::remove_file(&path).unwrap();

        assert_eq!(receipt.trust_root_key_id, "mainnet");
        assert_eq!(receipt.bls_certificate, Some(vec![1, 2, 3, 4]));
    }

    #[test]
    fn file_receipt_finalized_requires_trust_root_key_id() {
        let path = std::env::temp_dir().join(format!(
            "cvdr_verify_receipt_{}_{}.json",
            std::process::id(),
            2
        ));
        let json = r#"{
  "protocol_version": "mktd02-v2",
  "receipt_id": "1f213a0f2bf4992071a7f23e72d1942e564a4e871e3decce8ac8ee27d08f534b",
  "canister_id": "aaaaa-aa",
  "subnet_id": "2vxsx-fae",
  "pre_state_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "post_state_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "tombstone_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "deletion_event_hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  "certified_commitment": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
  "module_hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "timestamp": "1000000",
  "nonce": "1",
  "bls_certificate": [1,2,3,4]
}"#;

        fs::write(&path, json).unwrap();
        let err = load_receipt_from_file(path.to_str().unwrap()).unwrap_err();
        fs::remove_file(&path).unwrap();

        assert!(
            err.to_string().contains("missing trust_root_key_id"),
            "unexpected error: {}",
            err
        );
    }
}
