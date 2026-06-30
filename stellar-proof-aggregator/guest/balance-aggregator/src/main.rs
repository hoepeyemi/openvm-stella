// OpenVM guest program: aggregate N proof-of-balance claims into one STARK proof.
//
// Each "inner proof" is a Pedersen-style commitment: the prover knows (balance, nonce)
// such that SHA-256(balance_le8 || nonce_le8) == commitment, and 0 <= balance <= MAX_BALANCE.
//
// The guest verifies all N witnesses inside the zkVM. OpenVM then produces a single
// aggregate STARK proof covering all N verifications, which gets compressed to a SNARK
// for Stellar on-chain verification.

#![cfg_attr(target_os = "zkvm", no_main)]
#![cfg_attr(target_os = "zkvm", no_std)]

extern crate alloc;

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

openvm::entry!(main);

/// Maximum allowed balance (1 trillion micro-XLM ≈ 100M XLM).
const MAX_BALANCE: u64 = 1_000_000_000_000_u64;

/// Upper bound on the number of inner proofs per aggregation batch.
const MAX_PROOFS: usize = 64;

/// Compute the balance commitment: SHA-256(balance_le_8 || nonce_le_8).
///
/// This is the same function used off-chain by the prover. The guest re-derives
/// the commitment from the private witness (balance, nonce) and checks it matches
/// the public commitment supplied by the verifier.
fn commitment_of(balance: u64, nonce: u64) -> [u8; 32] {
    let mut input = [0u8; 16];
    input[..8].copy_from_slice(&balance.to_le_bytes());
    input[8..].copy_from_slice(&nonce.to_le_bytes());
    let mut h = Sha256::new();
    h.update(&input);
    h.finalize().into()
}

pub fn main() {
    // ── Read number of proofs ─────────────────────────────────────────────────
    let n: u32 = openvm::io::read();
    assert!(n > 0, "batch must contain at least one proof");
    assert!((n as usize) <= MAX_PROOFS, "batch exceeds MAX_PROOFS");

    // ── Verify each witness ───────────────────────────────────────────────────
    // We accumulate all 32-byte commitments into a single buffer so we can
    // produce an aggregate hash covering the whole batch.
    let mut commitment_buf: Vec<u8> = Vec::with_capacity(n as usize * 32);

    for i in 0..n {
        // Private inputs (hidden from verifier, known to prover)
        let balance: u64 = openvm::io::read();
        let nonce: u64 = openvm::io::read();
        // Public input (visible to both, must equal commitment_of(balance, nonce))
        let commitment: [u8; 32] = openvm::io::read();

        // Proof check 1 — range: 0 ≤ balance ≤ MAX_BALANCE
        // (u64 ≥ 0 is guaranteed by the type; only the upper bound needs checking)
        assert!(balance <= MAX_BALANCE, "proof {}: balance out of range", i);

        // Proof check 2 — commitment integrity: SHA-256(balance||nonce) == commitment
        let recomputed = commitment_of(balance, nonce);
        assert_eq!(
            recomputed, commitment,
            "proof {}: commitment mismatch",
            i
        );

        commitment_buf.extend_from_slice(&commitment);
    }

    // ── Produce aggregate hash over all commitments ───────────────────────────
    // This single 32-byte value is the canonical public fingerprint of the batch.
    // The Soroban verifier contract will check it against the public inputs
    // supplied to the on-chain SNARK verifier.
    let mut agg_hasher = Sha256::new();
    agg_hasher.update(&commitment_buf);
    let agg_hash: [u8; 32] = agg_hasher.finalize().into();

    // ── Reveal public values ──────────────────────────────────────────────────
    // Layout (byte offsets in the public-values region):
    //   [0 .. 32)  aggregate hash of all commitments (8 × u32 at word indices 0..7)
    //   [32 .. 36) number of proofs verified (u32 at word index 8)
    openvm::io::reveal_bytes32(agg_hash);
    openvm::io::reveal_u32(n, 8);
}
