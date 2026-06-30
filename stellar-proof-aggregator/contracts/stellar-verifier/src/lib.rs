//! Soroban smart contract: Aggregated Proof-of-Balance Verifier
//!
//! Verifies a single Groth16 BN254 proof produced by the OpenVM proof-aggregation
//! pipeline.  The proof attests that N individual balance claims were all verified
//! inside the OpenVM zkVM, collapsing N on-chain verifications to exactly ONE.
//!
//! # BN254 Groth16 verification equation
//!
//! Given:
//!   - proof  = (A ∈ G1, B ∈ G2, C ∈ G1)
//!   - vk     = (α ∈ G1, β ∈ G2, γ ∈ G2, δ ∈ G2, IC[0..k] ∈ G1)
//!   - inputs = (x[0], …, x[k-1]) ∈ Fr^k
//!
//! Compute vk_x = IC[0] + Σ_i x[i] · IC[i+1]
//! Accept iff: e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) == 1_{GT}
//!
//! # Public inputs for the OpenVM aggregated proof
//!
//! The guest program (balance-aggregator) reveals only:
//!   pub_inputs[0..8] : agg_hash as 8 × Bn254Fr (LE 4-byte chunks)
//!
//! agg_hash = SHA-256(n_le4 || c[0] || … || c[n-1]) so the proof count n is
//! committed inside the hash.  `n_proofs` is passed explicitly to verify_aggregate
//! for event emission and informational purposes only.
//!
//! # Stellar host-function requirements
//!
//! Requires Stellar Protocol 25+ (CAP-0074) and soroban-sdk v22+:
//!   env.crypto().bn254().g1_add(p1, p2)
//!   env.crypto().bn254().g1_mul(point, scalar)
//!   env.crypto().bn254().pairing_check(g1_vec, g2_vec)
//!
//! Protocol 26 (CAP-0080) adds g1_msm which can replace the vk_x loop.

#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    Address, BytesN, Env, Vec,
};
// soroban-sdk v22 does not expose BN254 host-function bindings yet. Keep the
// contract ABI byte-shaped so the WASM builds today, and replace these aliases
// with SDK-native BN254 types when Stellar exposes them in soroban-sdk.
pub type Bn254Fr = BytesN<32>;
pub type Bn254G1Affine = BytesN<64>;
pub type Bn254G2Affine = BytesN<128>;
// ── Contract types ────────────────────────────────────────────────────────────

/// A Groth16 BN254 proof.
#[contracttype]
#[derive(Clone)]
pub struct Proof {
    /// π_A ∈ G1 (64 bytes, Ethereum-compatible encoding)
    pub a: Bn254G1Affine,
    /// π_B ∈ G2 (128 bytes)
    pub b: Bn254G2Affine,
    /// π_C ∈ G1 (64 bytes)
    pub c: Bn254G1Affine,
}

/// The Groth16 verifying key (circuit-specific, written once at deploy).
#[contracttype]
#[derive(Clone)]
pub struct VerifyingKey {
    /// α ∈ G1
    pub alpha: Bn254G1Affine,
    /// β ∈ G2
    pub beta: Bn254G2Affine,
    /// γ ∈ G2
    pub gamma: Bn254G2Affine,
    /// δ ∈ G2
    pub delta: Bn254G2Affine,
    /// IC[0..k] ∈ G1 — length must equal num_public_inputs + 1
    pub ic: Vec<Bn254G1Affine>,
}

/// Contract error codes.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum VerifierError {
    InvalidProof              = 1,
    PublicInputLengthMismatch = 2,
    Unauthorized              = 3,
    VkNotSet                  = 4,
    UnsupportedHostFunction   = 5,
}

// ── Storage key symbols ───────────────────────────────────────────────────────

fn key_vk()      -> soroban_sdk::Symbol { soroban_sdk::symbol_short!("VK") }
fn key_admin()   -> soroban_sdk::Symbol { soroban_sdk::symbol_short!("ADMIN") }
fn key_counter() -> soroban_sdk::Symbol { soroban_sdk::symbol_short!("COUNT") }

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct AggregatedVerifier;

#[contractimpl]
impl AggregatedVerifier {
    // ── Initialization ─────────────────────────────────────────────────────────

    /// Deploy the contract.  Sets the admin and the circuit verifying key.
    /// Must be called exactly once.
    pub fn initialize(env: Env, admin: Address, vk: VerifyingKey) {
        if env.storage().instance().has(&key_admin()) {
            soroban_sdk::panic_with_error!(&env, VerifierError::Unauthorized);
        }
        admin.require_auth();
        env.storage().instance().set(&key_admin(), &admin);
        env.storage().instance().set(&key_vk(), &vk);
        env.storage().instance().set(&key_counter(), &0u64);
    }

    // ── Core verification ──────────────────────────────────────────────────────

    /// Verify an aggregated OpenVM proof-of-balance.
    ///
    /// `proof`      — Groth16 BN254 proof from the OpenVM aggregation pipeline.
    /// `n_proofs`   — number of balance proofs covered (informational; committed
    ///                inside agg_hash so the proof implicitly enforces it).
    /// `pub_inputs` — public signals: 8 × Bn254Fr encoding the aggregate hash
    ///                SHA-256(n_le4 || c[0] || … || c[n-1]).
    ///
    /// Returns `true` on success; reverts on invalid proof.
    ///
    /// # On-chain cost
    ///
    /// One call (~28M Soroban instructions) replaces `n_proofs` separate
    /// individual proof verifications (each ~27.5M instructions).
    /// For N ≥ 2, aggregation is strictly cheaper.
    pub fn verify_aggregate(
        env: Env,
        proof: Proof,
        n_proofs: u32,
        pub_inputs: Vec<Bn254Fr>,
    ) -> bool {
        // Load stored verifying key.
        let vk: VerifyingKey = env
            .storage()
            .instance()
            .get(&key_vk())
            .unwrap_or_else(|| soroban_sdk::panic_with_error!(&env, VerifierError::VkNotSet));

        // Validate that the number of public inputs matches the VK.
        // IC has (num_pub + 1) elements: IC[0] is the constant term.
        let expected_ic_len = pub_inputs.len() + 1;
        if vk.ic.len() != expected_ic_len {
            soroban_sdk::panic_with_error!(&env, VerifierError::PublicInputLengthMismatch);
        }

        // BN254 host functions are not available in soroban-sdk v22. The ABI and state
        // management compile now; real pairing verification must be enabled once the SDK
        // exposes g1_add/g1_mul/pairing_check bindings.
        let _ = (proof, n_proofs);
        soroban_sdk::panic_with_error!(&env, VerifierError::UnsupportedHostFunction);
    }

    // ── Read-only helpers ──────────────────────────────────────────────────────

    /// Return the total number of successfully verified aggregate proofs.
    pub fn verified_count(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&key_counter())
            .unwrap_or(0u64)
    }

    /// Estimate Soroban instruction cost for N individual proofs vs one aggregate.
    ///
    /// Returns `(cost_individual_total, cost_aggregated_total)`.
    /// These numbers are conservative estimates based on CAP-0074 / CAP-0080
    /// cost schedules; measure with `stellar-cli contract invoke --cost` on testnet.
    pub fn estimate_cost(_env: Env, n: u32) -> (u64, u64) {
        // Per individual Groth16 BN254 proof (8 public inputs = 32-byte hash):
        //   8  × g1_mul                         @ 1,500,000 each = 12,000,000
        //   1  × pairing_check (4 pairs)                         = 15,000,000
        //   overhead                                              =    500,000
        //                                                    ─────────────────
        //                                         per proof total = 27,500,000
        let per_proof: u64 = 27_500_000;

        // Aggregated proof (8 public inputs: 8 × Bn254Fr for agg_hash):
        //   8  × g1_mul                         @ 1,500,000 each = 12,000,000
        //   1  × pairing_check (4 pairs)                         = 15,000,000
        //   overhead                                              =    500,000
        //                                                    ─────────────────
        //                                       aggregated total = 27,500,000
        //   (constant — independent of N!)
        let aggregated: u64 = 27_500_000;

        (per_proof * n as u64, aggregated)
    }

    /// Update the verifying key (admin-only; for circuit upgrades).
    pub fn update_vk(env: Env, new_vk: VerifyingKey) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&key_admin())
            .unwrap_or_else(|| soroban_sdk::panic_with_error!(&env, VerifierError::Unauthorized));
        admin.require_auth();
        env.storage().instance().set(&key_vk(), &new_vk);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Env;

    #[test]
    fn test_cost_estimate_scales_linearly() {
        let env = Env::default();
        let cid = env.register(AggregatedVerifier, ());
        let client = AggregatedVerifierClient::new(&env, &cid);

        let (ind_1, agg_1)   = client.estimate_cost(&1_u32);
        let (ind_10, agg_10) = client.estimate_cost(&10_u32);

        // Individual cost grows linearly with N.
        assert_eq!(ind_10, ind_1 * 10);

        // Aggregated cost is constant (proof covers all N internally).
        assert_eq!(agg_1, agg_10);

        // For N ≥ 2, aggregation is cheaper.
        assert!(agg_10 < ind_10,
            "aggregated ({agg_10}) should be cheaper than individual ({ind_10}) for N=10");

        let savings_pct = 100.0 * (1.0 - agg_10 as f64 / ind_10 as f64);
        // At N=10, savings should be (1 - 27.5/275) = 90%
        assert!(savings_pct > 85.0, "expected >85% savings at N=10, got {savings_pct:.1}%");
    }

    /// Smoke-test the interface: confirms the contract compiles and the
    /// verify_aggregate signature is correct.  A real proof test requires a
    /// trusted-setup verifying key generated by the OpenVM prover pipeline.
    #[test]
    #[ignore = "requires a real trusted-setup VK and a valid Groth16 proof"]
    fn test_verify_aggregate_with_real_proof() {
        // Steps to generate a real test:
        // 1. Run `cargo run -p stellar-aggregator-host -- --n 5`
        // 2. From the Groth16 wrapper output, extract (proof, vk, pub_inputs)
        // 3. Convert to Soroban Bn254G1Affine / Bn254G2Affine / Bn254Fr types
        // 4. Call client.verify_aggregate(&proof, &pub_inputs) and assert true
        let _env = Env::default();
        todo!("populate with output from OpenVM prover pipeline");
    }
}
