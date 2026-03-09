mod fetch;
mod v1_transition;
mod v2_certificate;
mod v3_module;
mod v4_tombstone;

use anyhow::Result;
use clap::Parser;
use ic_agent::Agent;
use candid::Principal;

#[derive(Parser)]
#[command(name = "mktd02-verify")]
#[command(about = "Reference V1-V4 verification paths for MKTd02 CVDRs")]
struct Cli {
    /// Canister principal that holds the receipt
    #[arg(long)]
    canister: String,

    /// Hex-encoded receipt ID
    #[arg(long)]
    receipt_id: String,

    /// IC network URL
    #[arg(long, default_value = "https://ic0.app")]
    network: String,

    /// Optional: published WASM hash (hex) for V3 three-way comparison
    #[arg(long)]
    wasm_hash: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let canister_id = Principal::from_text(&cli.canister)
        .map_err(|e| anyhow::anyhow!("Invalid canister ID: {}", e))?;

    let published_hash: Option<[u8; 32]> = match &cli.wasm_hash {
        Some(h) => {
            let bytes = hex::decode(h)?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("--wasm-hash must be 64 hex chars (32 bytes)"))?;
            Some(arr)
        }
        None => None,
    };

    // Build agent
    let agent = Agent::builder()
        .with_url(&cli.network)
        .build()?;

    // Fetch root key for non-mainnet (local replica)
    if cli.network != "https://ic0.app" && cli.network != "https://icp0.io" {
        agent.fetch_root_key().await?;
    }

    println!("============================================================");
    println!(" CVDR-Verify: MKTd02 Full Verification (V1-V4)");
    println!(" Canister : {}", cli.canister);
    println!(" Receipt  : {}", cli.receipt_id);
    println!(" Network  : {}", cli.network);
    println!("============================================================");
    println!();

    // Step 1: Fetch receipt
    println!("[1/5] Fetching receipt...");
    let receipt = fetch::fetch_receipt(&agent, canister_id, &cli.receipt_id).await?;
    println!("  protocol_version : {}", receipt.protocol_version);
    println!("  Receipt fetched successfully.");
    println!();

    // Step 2: V1 — Hash recomputation
    println!("[2/5] V1: State transition verification...");
    let v1 = v1_transition::verify(&receipt, canister_id);
    println!("  {}", v1.summary());
    println!();

    // Step 3: V2 — BLS certificate
    println!("[3/5] V2: Certificate verification path...");
    let v2 = v2_certificate::verify(&agent, canister_id, &receipt).await;
    println!("  {}", v2.summary());
    println!();

    // Step 4: V3 — Module hash
    println!("[4/5] V3: Module hash verification...");
    let v3 = v3_module::verify(&agent, canister_id, &receipt, published_hash).await;
    println!("  {}", v3.summary());
    println!();

    // Step 5: V4 — Tombstone persistence
    println!("[5/5] V4: Tombstone persistence check...");
    let v4 = v4_tombstone::verify(&agent, canister_id, &receipt).await;
    println!("  {}", v4.summary());
    println!();

    // Summary
    println!("============================================================");
    println!(" CVDR Verification Summary");
    println!("============================================================");
    println!(" {:<16} : {}", "V1 (hashes)",   v1.summary());
    println!(" {:<16} : {}", "V2 (cert path)", v2.summary());
    println!(" {:<16} : {}", "V3 (module)",   v3.summary());
    println!(" {:<16} : {}", "V4 (tombstone)", v4.summary());
    println!("============================================================");

    if v1.passed() && v2.passed() && v4.passed() {
        std::process::exit(0);
    } else {
        std::process::exit(1);
    }
}
