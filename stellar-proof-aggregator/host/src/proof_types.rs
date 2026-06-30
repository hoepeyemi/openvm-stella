/// Private witness for a single balance proof.
///
/// The prover holds (balance, nonce) and publishes `commitment`.
/// Inside the OpenVM zkVM the guest re-derives `commitment_of(balance, nonce)`
/// and checks it equals `commitment`, plus checks `balance ≤ MAX_BALANCE`.
#[derive(Debug, Clone)]
pub struct BalanceWitness {
    /// The secret balance (private).
    pub balance: u64,
    /// Random nonce that hides `balance` in the commitment (private).
    pub nonce: u64,
    /// Public commitment: SHA-256(balance_le8 || nonce_le8).
    pub commitment: [u8; 32],
}

/// On-chain public inputs extracted from the OpenVM public-values region
/// after proof generation.
#[derive(Debug, Clone)]
pub struct AggregatedPublicInputs {
    /// SHA-256 of all N commitments concatenated: SHA-256(c[0] || … || c[N-1]).
    pub aggregate_hash: [u8; 32],
    /// Number of balance proofs aggregated.
    pub n_proofs: u32,
}

impl AggregatedPublicInputs {
    /// Decode from the raw public-values byte slice returned by OpenVM execute/prove.
    ///
    /// Layout (as written by the guest):
    ///   bytes [0..32)  → aggregate_hash (8 × u32 via reveal_bytes32)
    ///   bytes [32..36) → n_proofs (u32 via reveal_u32 at word-index 8)
    pub fn from_public_values(pv: &[u8]) -> eyre::Result<Self> {
        eyre::ensure!(pv.len() >= 36, "public values too short ({})", pv.len());
        let aggregate_hash = pv[0..32].try_into().unwrap();
        let n_proofs = u32::from_le_bytes(pv[32..36].try_into().unwrap());
        Ok(Self { aggregate_hash, n_proofs })
    }
}
