# OpenVM x Stellar: Aggregated Proof-of-Balance

OpenVM x Stellar is a proof-aggregation demo that turns many private balance checks into one locally verified OpenVM STARK proof, then packages the result for a single Soroban verifier call.

The core idea is simple: instead of verifying N independent proofs on Stellar, verify one aggregate statement whose public output is a 32-byte hash committing to the whole batch.

This repository contains:

- an OpenVM guest program that checks N private balance witnesses inside the zkVM,
- a Rust host orchestrator that builds the guest, generates witnesses, executes, proves, verifies, and prints Stellar cost estimates,
- a Soroban verifier contract scaffold with the final ABI shape for a BN254 Groth16 verifier,
- a local runner script that installs/checks prerequisites and exercises the full demo path.

## Current Status

The local OpenVM proof path works end to end:

- OpenVM workspace sanity check passes.
- Guest RISC-V ELF builds.
- Host generates N private witnesses.
- Guest execution reveals the expected aggregate hash.
- OpenVM generates an aggregate STARK proof.
- OpenVM verifies that proof locally.
- Soroban verifier WASM builds.
- Soroban contract unit tests pass with no ignored tests.
- The contract can be deployed to Stellar testnet.

A testnet deployment has been produced:

```text
Contract ID: CCAHXA6BGMR3CLUCSYAK7CSIWTLJOMDRHFZW2RXNFKWZ7J3FA5CRJREM
Upload tx  : https://stellar.expert/explorer/testnet/tx/5ff1ec80fa0ec772819e01d2dd0b048af94630f67753b10fc47d084c5662f877
Deploy tx  : https://stellar.expert/explorer/testnet/tx/7346f003f27bc72fc828f491417bfb80dba126fa57a675151a1e234ec1bc4617
Lab link   : https://lab.stellar.org/r/testnet/contract/CCAHXA6BGMR3CLUCSYAK7CSIWTLJOMDRHFZW2RXNFKWZ7J3FA5CRJREM
```

Important limitation: `soroban-sdk 22.0.11` does not expose `crypto::bn254` or `env.crypto().bn254()` bindings. Because of that, the deployed Soroban contract is currently an ABI/storage scaffold. Its `verify_aggregate` entrypoint validates the stored verifying-key shape and then intentionally fails with `UnsupportedHostFunction`. The local OpenVM proof is real; real on-chain BN254 pairing verification must wait for usable Stellar/Soroban BN254 SDK bindings or be adapted to the final supported Stellar pairing API.

## What The ZK Proof Does

Each proof-of-balance claim has:

- private witness: `balance: u64`, `nonce: u64`,
- public commitment: `SHA-256(balance_le8 || nonce_le8)`,
- statement: `0 <= balance <= 1_000_000_000_000` and the commitment is correct.

The OpenVM guest verifies all N claims in one execution. The chain does not see balances or nonces. It only needs the aggregate public output:

```text
agg_hash = SHA-256(n_le4 || commitment[0] || ... || commitment[n-1])
```

The public hash commits to both the number of proofs and every individual commitment in the batch.

## Why Aggregation Matters

Without aggregation, Stellar would verify N separate proofs. With OpenVM aggregation, Stellar verifies one proof whose public input is the aggregate hash.

The demo cost model assumes a BN254 Groth16 verifier with 8 public inputs:

```text
per verification = 8 * g1_mul + 1 * pairing_check(4 pairs) + call overhead
                 = 8 * 1,500,000 + 15,000,000 + 500,000
                 = 27,500,000 Soroban instructions
```

Approximate comparison:

| N | Separate verifications | Aggregated verification | Savings |
|---:|-----------------------:|------------------------:|--------:|
| 5  | 137,500,000 | 27,500,000 | 80.0% |
| 10 | 275,000,000 | 27,500,000 | 90.0% |
| 50 | 1,375,000,000 | 27,500,000 | 98.0% |

The exact fee model must be re-benchmarked against the Stellar network and SDK version used for production. The numbers here are conservative demo estimates based on the intended BN254 host-function cost model.

## Architecture

```text
prover machine                                         Stellar / Soroban

private balances + nonces
        |
        v
OpenVM guest: balance-aggregator
- reads N witnesses
- checks range bound
- recomputes SHA-256 commitments
- reveals agg_hash
        |
        v
OpenVM SDK host orchestrator
- builds guest ELF
- dry-runs execution
- generates aggregate STARK proof
- verifies proof locally
- prints Stellar submission shape
        |
        v
future production wrapper
- root STARK -> Groth16/Halo2-style proof
- proof.a/proof.b/proof.c + vk + pub_inputs
        |
        v
Soroban verifier contract
- stores admin and verifying key
- checks input/VK shape
- future: runs BN254 pairing equation
```

Intended Groth16 equation:

```text
e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1

where vk_x = IC[0] + sum_i pub_input[i] * IC[i + 1]
```

Current SDK reality: the contract keeps the ABI shape but cannot call BN254 host functions yet.

## Source Layout

```text
stellar-proof-aggregator/
  README.md
  run_local.sh
  Cargo.toml

  guest/balance-aggregator/
    Cargo.toml
    openvm.toml
    src/main.rs

  host/
    Cargo.toml
    src/main.rs
    src/proof_types.rs
    src/stellar_export.rs

  contracts/stellar-verifier/
    Cargo.toml
    src/lib.rs
```

### `guest/balance-aggregator`

The OpenVM guest program. It is `no_std` under the zkVM target and uses `openvm::entry!(main)`.

It consumes this input stream:

```text
n: u32
for each witness:
  balance: u64
  nonce: u64
  commitment: [u8; 32]
```

For every witness it checks:

```text
balance <= 1_000_000_000_000
SHA-256(balance_le8 || nonce_le8) == commitment
```

Then it reveals exactly one 32-byte public value:

```text
SHA-256(n_le4 || all commitments)
```

The guest is configured with OpenVM RV32IM + IO support in `openvm.toml`.

### `host`

The host orchestrator drives the proof demo.

`src/main.rs` does the full flow:

1. Build the OpenVM guest package into a RISC-V ELF.
2. Generate deterministic random witnesses using a fixed seed.
3. Construct `StdIn` for the guest.
4. Execute the guest without proving and verify the aggregate hash.
5. Generate an OpenVM aggregate STARK proof with `Sdk::prove`.
6. Run local verification with `Sdk::verify_proof`.
7. Print Stellar cost and submission information.

`src/proof_types.rs` defines:

- `BalanceWitness`, the private balance/nonce plus public commitment,
- `AggregatedPublicInputs`, the decoded 32-byte aggregate hash and proof count.

`src/stellar_export.rs` defines the demo cost model and prints the future Soroban `verify_aggregate` submission shape.

### `contracts/stellar-verifier`

The Soroban contract is an ABI-ready verifier scaffold.

It defines:

- `Proof { a, b, c }`, byte-shaped BN254 proof fields,
- `VerifyingKey { alpha, beta, gamma, delta, ic }`, byte-shaped VK fields,
- `VerifierError`, including `UnsupportedHostFunction`,
- `initialize(admin, vk)`,
- `verify_aggregate(proof, n_proofs, pub_inputs)`,
- `verified_count()`,
- `estimate_cost(n)`,
- `update_vk(new_vk)`.

Because `soroban-sdk 22.0.11` has no BN254 Rust bindings, the BN254 field/group types are currently represented as bytes:

```rust
pub type Bn254Fr = BytesN<32>;
pub type Bn254G1Affine = BytesN<64>;
pub type Bn254G2Affine = BytesN<128>;
```

The active verifier-entrypoint test confirms that the contract reaches the intended unsupported-host-function boundary after validating ABI and VK shape. There are no ignored tests.

## Running Locally, Step By Step

These steps match the real `run_local.sh` flow.

### 0. Requirements

| Tool | Why | Install |
|---|---|---|
| Rust + Cargo | builds OpenVM, host, guest, contract | <https://rustup.rs> |
| Rust 1.90.0 compatible toolchain | OpenVM workspace requirement | pinned by root `rust-toolchain.toml` |
| `nightly-2025-08-02` + `rust-src` | OpenVM guest RISC-V compilation | `rustup toolchain install nightly-2025-08-02` |
| `cargo-nextest` | preferred test runner for OpenVM workspaces | `cargo install cargo-nextest --version 0.9.128 --locked` on Rust <= 1.90 |
| `wasm32-unknown-unknown` target | builds Soroban WASM | `rustup target add wasm32-unknown-unknown` |
| Stellar CLI | deploys Soroban contract | `cargo install stellar-cli --locked` |
| Linux/WSL2 recommended | OpenVM guest/proof tooling is smoother there | use Ubuntu/WSL2 on Windows |

Confirm basics:

```bash
cargo --version
rustc --version
rustup --version
stellar --version
```

Install the OpenVM guest toolchain pieces:

```bash
rustup toolchain install nightly-2025-08-02
rustup component add rust-src --toolchain nightly-2025-08-02
rustup target add riscv32im-risc0-zkvm-elf --toolchain nightly-2025-08-02 || true
rustup target add wasm32-unknown-unknown
```

Note: `riscv32im-risc0-zkvm-elf` may report unavailable for that nightly. OpenVM builds the guest with `-Z build-std`, so this warning can be harmless; the demo has completed successfully with that warning.

### 1. Run the full local demo script

From the OpenVM repository root:

```bash
bash stellar-proof-aggregator/run_local.sh --n 10
```

This performs seven steps:

1. Check `cargo` and `rustup`.
2. Install/check Rust toolchains.
3. Install/check `cargo-nextest`.
4. Run `cargo check -p openvm-sdk -p openvm-circuit`.
5. Build the guest program.
6. Run the host orchestrator for N proofs.
7. Build and test the Soroban contract.

A successful run ends with:

```text
All steps completed successfully!

Summary:
  Guest ELF    : .../guest/balance-aggregator/target/riscv32im-risc0-zkvm-elf/release/balance-aggregator
  Soroban WASM : .../contracts/stellar-verifier/target/wasm32-unknown-unknown/release/stellar_aggregated_verifier.wasm
```

### 2. Run the pieces manually

Sanity-check the OpenVM crates:

```bash
cargo check -p openvm-sdk -p openvm-circuit
```

Build the guest:

```bash
cd stellar-proof-aggregator/guest/balance-aggregator
cargo +nightly-2025-08-02 build --release
```

Run the host orchestrator from the aggregator workspace:

```bash
cd stellar-proof-aggregator
cargo run --release -p stellar-aggregator-host -- --n 10
```

Build the Soroban contract from the repo root:

```bash
cd stellar-proof-aggregator/contracts/stellar-verifier
cargo build --target wasm32-unknown-unknown --release
```

Run contract tests:

```bash
cargo test --features testutils
```

Expected result:

```text
2 passed; 0 failed; 0 ignored
```

### 3. Deploy the Soroban contract to Stellar testnet

Create/fund a Stellar CLI identity first if needed:

```bash
stellar keys generate demo --network testnet
stellar keys fund demo --network testnet
```

Deploy:

```bash
stellar contract deploy \
  --wasm stellar-proof-aggregator/contracts/stellar-verifier/target/wasm32-unknown-unknown/release/stellar_aggregated_verifier.wasm \
  --source demo \
  --network testnet
```

The CLI prints a contract ID. Save it.

Reminder: deployment proves the WASM and ABI are accepted by Stellar, not that real BN254 proof verification is live. With the current SDK, calling `verify_aggregate` reaches `UnsupportedHostFunction` by design.

## What Is Private vs Public

| Data | Visibility |
|---|---|
| `balance` | Private; only in the host process and OpenVM guest witness |
| `nonce` | Private; only in the host process and OpenVM guest witness |
| individual `commitment` values | Public to the proof system; included in aggregate hash preimage |
| `n_proofs` | Public contract argument and included in aggregate hash preimage |
| `agg_hash` | Public OpenVM output and future Soroban public input |
| OpenVM STARK proof | Public proof object generated off-chain |
| Groth16/Halo2 wrapper proof | Future public on-chain proof payload |

## Production Path

The repository currently proves the aggregate statement as an OpenVM STARK and verifies it locally.

A production Stellar verifier path needs one additional cryptographic bridge:

1. Generate the OpenVM app proof.
2. Aggregate recursively to a root STARK using OpenVM's aggregation stack.
3. Wrap that root proof in a proof system Stellar can verify with supported host functions.
4. Submit proof, verifying key, `n_proofs`, and aggregate-hash public inputs to Soroban.
5. Replace the current `UnsupportedHostFunction` placeholder with the real Stellar BN254 or equivalent pairing API once the SDK exposes it.

OpenVM already supports EVM-oriented Halo2/KZG verification flows. This project demonstrates the Stellar-facing shape and cost model, but the final on-chain verifier must be adapted to the actual Stellar/Soroban cryptographic host-function surface available at production time.

## Testing

OpenVM sanity check:

```bash
cargo check -p openvm-sdk -p openvm-circuit
```

Contract tests:

```bash
cd stellar-proof-aggregator/contracts/stellar-verifier
cargo test --features testutils
```

The contract tests cover:

- cost scaling: individual verification cost grows linearly with N while aggregated cost stays constant,
- `verify_aggregate` active smoke path: validates ABI/VK shape and reaches the explicit unsupported BN254 host-function boundary.

No test is intentionally ignored.

## Troubleshooting

### `soroban-sdk` has no `crypto::bn254`

That is expected with `soroban-sdk 22.0.11`. The current contract uses byte-shaped aliases and an explicit `UnsupportedHostFunction` error until real SDK bindings exist.

### `soroban-sdk/export-abi` feature does not exist

Use the current contract manifest shape:

```toml
[features]
default = []
testutils = ["soroban-sdk/testutils"]
```

### Cargo says the contract believes it is in a workspace when it is not

The contract is intentionally its own workspace root. Its manifest should include:

```toml
[workspace]
```

This prevents Cargo from trying to treat it as a member of the parent `stellar-proof-aggregator` workspace.

### `cargo check -p openvm-sdk -p openvm-circuit` resolves the Soroban contract

The root OpenVM `Cargo.toml` should not include `stellar-proof-aggregator/contracts/stellar-verifier` as a workspace member. The contract has different target/toolchain needs and is built separately.

### RISC-V target install warns that it is unavailable

This can be okay. OpenVM's guest build uses nightly `-Z build-std` and may still build successfully. Continue to the guest build step and only debug if that step fails.

### Proof generation takes a long time

Normal. The host step can take many minutes, especially the first time. In one successful local run, `--n 10` generated and locally verified the aggregate STARK proof, with proof generation taking about 25 minutes on a VirtualBox Linux VM.

### Contract deploy succeeds, but `verify_aggregate` fails

Expected for now. The current deployed contract is a scaffold and intentionally fails at `UnsupportedHostFunction` because the installed Soroban SDK has no BN254 verification bindings.

## Known Gaps

- No live on-chain BN254 verification yet under `soroban-sdk 22.0.11`.
- The host currently prints the future Stellar submission shape; it does not output a final Groth16/Halo2 wrapper proof consumable by the contract.
- The proof-size print in the host is a rough estimate based on per-AIR proof components, not a serialized byte measurement.
- The commitment scheme is SHA-256 over `balance || nonce`; production systems should carefully choose nonce size, replay/nullifier design, and domain separation.
- The Soroban contract stores a verifying key shape, but real VK encoding must be finalized with the production proof system and Stellar host-function API.

## License

MIT OR Apache-2.0