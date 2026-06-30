//! Host orchestrator for OpenVM × Stellar proof aggregation.
//!
//! Workflow:
//!   1. Generate N balance witnesses (balance, nonce, commitment)
//!   2. Build the OpenVM guest ELF that verifies all N witnesses
//!   3. Execute the guest (fast dry-run) to confirm correctness
//!   4. Generate an aggregated STARK proof covering all N verifications
//!   5. Verify the STARK proof locally
//!   6. Print cost comparison: N individual Stellar txs vs 1 aggregated tx
//!
//! Run:
//!   cargo run --release -p stellar-aggregator-host -- --n 10

use eyre::Result;
use openvm_build::GuestOptions;
use openvm_sdk::{Sdk, StdIn};
use rand::{rngs::StdRng, Rng, SeedableRng};
use sha2::{Digest, Sha256};
use std::time::Instant;

mod proof_types;
mod stellar_export;

use proof_types::{AggregatedPublicInputs, BalanceWitness};

/// Path to the guest program manifest (relative to this file at build time).
const GUEST_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../guest/balance-aggregator"
);

// ── Commitment scheme (mirrors guest/balance-aggregator/src/main.rs) ─────────

fn commitment_of(balance: u64, nonce: u64) -> [u8; 32] {
    let mut input = [0u8; 16];
    input[..8].copy_from_slice(&balance.to_le_bytes());
    input[8..].copy_from_slice(&nonce.to_le_bytes());
    let mut h = Sha256::new();
    h.update(&input);
    h.finalize().into()
}

// ── Witness generation ────────────────────────────────────────────────────────

fn generate_witnesses(n: usize, seed: u64) -> Vec<BalanceWitness> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..n)
        .map(|_| {
            // Balances in [1, 1_000_000_000_000] (≤ MAX_BALANCE)
            let balance = rng.gen_range(1..=1_000_000_000_000_u64);
            let nonce = rng.gen::<u64>();
            let commitment = commitment_of(balance, nonce);
            BalanceWitness {
                balance,
                nonce,
                commitment,
            }
        })
        .collect()
}

// ── StdIn construction ────────────────────────────────────────────────────────

/// Pack N witnesses into the OpenVM input stream.
///
/// Format (one `stdin.write()` call per item, consumed sequentially by the guest):
///   write(n: u32)
///   for each witness:
///     write(balance: u64)
///     write(nonce:   u64)
///     write(commitment: [u8; 32])
fn build_stdin(witnesses: &[BalanceWitness]) -> StdIn {
    let mut stdin = StdIn::default();
    stdin.write(&(witnesses.len() as u32));
    for w in witnesses {
        stdin.write(&w.balance);
        stdin.write(&w.nonce);
        stdin.write(&w.commitment);
    }
    stdin
}

// ── Aggregate hash (mirrors what the guest computes) ─────────────────────────

fn expected_aggregate_hash(witnesses: &[BalanceWitness]) -> [u8; 32] {
    let mut h = Sha256::new();
    for w in witnesses {
        h.update(&w.commitment);
    }
    h.finalize().into()
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    // Filter noisy OpenVM internals; show our own log lines.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("openvm=warn,info")),
        )
        .init();

    let n: usize = std::env::args()
        .skip_while(|a| a != "--n")
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║    OpenVM × Stellar: Aggregated Proof-of-Balance Demo        ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("  N = {n} proof-of-balance claims → 1 aggregated STARK proof");
    println!("  Each claim: SHA-256 commitment binding a secret balance to a nonce");
    println!("  Claim semantics: 0 ≤ balance ≤ 1,000,000,000,000 micro-XLM");
    println!();

    // ── Step 1: Build guest ELF ───────────────────────────────────────────────
    println!("[1/5] Building OpenVM guest program (RISC-V ELF)...");
    let t = Instant::now();
    let sdk = Sdk::riscv32();
    let elf = sdk.build(GuestOptions::default(), GUEST_DIR, &None, None)?;
    println!("      Done in {:.1}s\n", t.elapsed().as_secs_f64());

    // ── Step 2: Generate witnesses ────────────────────────────────────────────
    println!("[2/5] Generating {n} balance witnesses...");
    let witnesses = generate_witnesses(n, 0xdeadbeef_cafebabe);

    for (i, w) in witnesses.iter().enumerate() {
        println!(
            "      [{:>2}]  balance = {:>15}  commit = 0x{}…",
            i + 1,
            w.balance,
            hex::encode(&w.commitment[..4])
        );
    }
    let expected_hash = expected_aggregate_hash(&witnesses);
    println!();
    println!(
        "      Expected agg_hash = 0x{}",
        hex::encode(expected_hash)
    );
    println!();

    // ── Step 3: Execute (fast dry-run) ────────────────────────────────────────
    println!("[3/5] Executing guest (dry-run, no proof)...");
    let t = Instant::now();
    let stdin = build_stdin(&witnesses);
    let raw_pv = sdk.execute(elf.clone(), stdin.clone())?;
    let pub_inputs = AggregatedPublicInputs::from_public_values(&raw_pv)?;

    assert_eq!(
        pub_inputs.aggregate_hash, expected_hash,
        "aggregate hash mismatch — guest / host commitment formula diverge"
    );
    assert_eq!(pub_inputs.n_proofs, n as u32);

    println!("      Execution OK in {:.2}s", t.elapsed().as_secs_f64());
    println!(
        "      agg_hash  = 0x{}",
        hex::encode(pub_inputs.aggregate_hash)
    );
    println!("      n_proofs  = {}", pub_inputs.n_proofs);
    println!();

    // ── Step 4: Generate aggregate STARK proof ────────────────────────────────
    println!("[4/5] Generating aggregate STARK proof (this may take a few minutes)...");
    let t = Instant::now();
    let stdin = build_stdin(&witnesses);
    let (proof, app_commit) = sdk.prove(elf.clone(), stdin)?;
    let prove_elapsed = t.elapsed().as_secs_f64();
    println!("      Proof generated in {prove_elapsed:.1}s");
    println!(
        "      Proof size: {} bytes",
        // Approximate: count per-AIR proof components
        proof.inner.per_air.len() * 4096 // rough estimate
    );
    println!();

    // ── Step 5: Local verification ────────────────────────────────────────────
    println!("[5/5] Verifying aggregate STARK proof locally...");
    let t = Instant::now();
    let (_, agg_vk) = sdk.agg_keygen()?;
    Sdk::verify_proof(&agg_vk, app_commit, &proof)?;
    println!("      Verification OK in {:.2}s\n", t.elapsed().as_secs_f64());

    // ── Cost comparison ───────────────────────────────────────────────────────
    println!("══════════════════════════════════════════════════════════════");
    println!("  Stellar On-Chain Cost Comparison");
    println!("══════════════════════════════════════════════════════════════");
    println!();
    stellar_export::print_cost_comparison(n as u32);
    println!();

    // ── Stellar submission data ───────────────────────────────────────────────
    stellar_export::print_stellar_submission(&pub_inputs);


    println!("══════════════════════════════════════════════════════════════");
    println!("  Demo complete. The Soroban verifier contract is in:");
    println!("  stellar-proof-aggregator/contracts/stellar-verifier/");
    println!("══════════════════════════════════════════════════════════════");
    println!();

    Ok(())
}
