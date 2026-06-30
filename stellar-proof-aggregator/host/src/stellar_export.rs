/// Cost model for Stellar's Soroban instruction metering (Protocol 25/26).
///
/// Sources:
///   CAP-0074 — BN254 host function cost schedule
///   CAP-0080 — Additional BN254/BLS12-381 host functions (Protocol 26)
///
/// All figures are conservative estimates; real costs should be benchmarked
/// via `stellar-cli contract invoke --cost` on testnet.
pub mod cost {
    /// Soroban instruction units for a single BN254 G1 scalar multiplication.
    /// Dominates the vk_x computation in Groth16 verification.
    pub const G1_MUL_INSTRUCTIONS: u64 = 1_500_000;

    /// Soroban instruction units for a BN254 multi-pairing check with P pairs.
    /// The pairing itself is constant-time regardless of P for small P.
    pub const PAIRING_CHECK_4_PAIRS_INSTRUCTIONS: u64 = 15_000_000;

    /// Overhead per contract call (storage reads, dispatch, etc.).
    pub const CALL_OVERHEAD_INSTRUCTIONS: u64 = 500_000;

    /// Cost of one Groth16 BN254 proof verification with `n_pub_inputs` public inputs.
    pub fn groth16_verify_cost(n_pub_inputs: u32) -> u64 {
        // vk_x = IC[0] + Σ_i (pub[i] · IC[i+1])  →  n_pub_inputs g1_mul calls
        let vk_x_cost = G1_MUL_INSTRUCTIONS * n_pub_inputs as u64;
        CALL_OVERHEAD_INSTRUCTIONS + vk_x_cost + PAIRING_CHECK_4_PAIRS_INSTRUCTIONS
    }
}

/// Print a human-readable cost comparison between N individual Stellar verifications
/// and one aggregated OpenVM proof.
///
/// Public inputs for the aggregated proof:
///   - n_proofs (1 × u32 → 1 scalar)
///   - aggregate_hash (32 bytes → 8 × Bn254Fr scalars)
///   Total: 9 public inputs
pub fn print_cost_comparison(n: u32) {
    // Individual: each proof has 1 public input (its own commitment, 32-byte hash).
    // We represent it as 8 × Bn254Fr for the full hash → 8 public inputs each.
    let per_proof_pub_inputs: u32 = 8; // 32-byte commitment as 8 × Bn254Fr
    let individual_total =
        cost::groth16_verify_cost(per_proof_pub_inputs) * n as u64;

    // Aggregated: ONE proof for all N, with 9 public inputs (n + 8-element hash).
    let aggregated_pub_inputs: u32 = 9; // 1 (n_proofs) + 8 (agg_hash)
    let aggregated_total = cost::groth16_verify_cost(aggregated_pub_inputs);

    let savings_pct =
        100.0 * (1.0 - aggregated_total as f64 / individual_total as f64);
    let multiplier = individual_total as f64 / aggregated_total as f64;

    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│          Stellar On-Chain Cost Comparison (N = {n:>2})          │");
    println!("├─────────────────────────────────────────────────────────────┤");
    println!("│  Without aggregation ({n} separate verify_proof calls)        │");
    println!("│    Soroban instructions : {:>14}                      │", individual_total);
    println!("│    G1 multiplications   : {:>14}                      │", 8 * n);
    println!("│    Pairing checks       : {:>14}                      │", n);
    println!("├─────────────────────────────────────────────────────────────┤");
    println!("│  With OpenVM aggregation (1 verify_aggregate call)          │");
    println!("│    Soroban instructions : {:>14}                      │", aggregated_total);
    println!("│    G1 multiplications   : {:>14}                      │", 9u32);
    println!("│    Pairing checks       : {:>14}                      │", 1u32);
    println!("├─────────────────────────────────────────────────────────────┤");
    println!("│  Savings: {savings_pct:>5.1}% — {multiplier:>4.1}× cheaper on-chain                 │");
    println!("│  Scaling: savings grow linearly with N                      │");
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();
    println!("  Soroban fee model (approximate, Mainnet 2025):");
    println!("  • 1 instruction unit ≈ 0.0000001 XLM");
    println!(
        "  • Individual cost : {:.4} XLM",
        individual_total as f64 * 1e-7
    );
    println!(
        "  • Aggregated cost : {:.4} XLM  (proof generation is off-chain)",
        aggregated_total as f64 * 1e-7
    );
    println!(
        "  • Fee saved       : {:.4} XLM",
        (individual_total - aggregated_total) as f64 * 1e-7
    );
}

/// Print the calldata that would be submitted to the Soroban verifier contract.
pub fn print_stellar_submission(
    public_inputs: &crate::proof_types::AggregatedPublicInputs,
) {
    println!("=== Stellar Submission (verify_aggregate call) ===");
    println!();
    println!("  Contract : StellarAggregatedVerifier");
    println!("  Function : verify_aggregate(proof, vk, pub_inputs)");
    println!();
    println!("  Public inputs supplied to the Soroban contract:");
    println!(
        "    pub_inputs[0]  = n_proofs = {}",
        public_inputs.n_proofs
    );
    println!(
        "    pub_inputs[1..9] = agg_hash = 0x{}",
        hex::encode(public_inputs.aggregate_hash)
    );
    println!();
    println!("  Proof format (Groth16 BN254, derived from STARK aggregation):");
    println!("    proof.a : Bn254G1Affine  (64 bytes, Ethereum-compatible)");
    println!("    proof.b : Bn254G2Affine  (128 bytes)");
    println!("    proof.c : Bn254G1Affine  (64 bytes)");
    println!();
    println!("  Verification equation on Stellar:");
    println!("    e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) == 1");
    println!("    where vk_x = IC[0] + n_proofs·IC[1] + agg_hash·IC[2..10]");
    println!();
    println!("  This single transaction replaces {} separate on-chain verifications.", public_inputs.n_proofs);
    println!();
    println!("  Production path:");
    println!("    1. Run OpenVM prove() → STARK proof (BabyBear)");
    println!("    2. Run OpenVM agg_keygen / prove with aggregation → root STARK");
    println!("    3. Wrap root STARK in Groth16 (e.g. bellman/ark-groth16)");
    println!("       OR use the EVM Halo2/PLONK proof adapted to Stellar pairing API");
    println!("    4. Submit (proof, vk, pub_inputs) to Soroban verifier contract");
}
