# Solidus bridge programs for Solana

Solana programs that let any Solana program require a Solidus credential, without seeing the
person's data. A credential issued on Solidus (for example a completed KYC check) is exported, with
the holder's consent, to a Solana account. Solidus validators sign a status message, anyone can
deliver it, and the mirror program on Solana checks the signatures before it stores the status.

What reaches Solana is an export id, a hash of the issuer, a hash of the credential type, the holder's
key, a status, an expiry and an issuer-accredited flag. No name, no document, no claim.

## What is here

| Path | What it is |
|---|---|
| `programs/solidus_mirror` | Verifies validator-signed status messages (threshold of the registered signers) and stores credential status, issuer status and a heartbeat |
| `crates/solidus-gate` | The check another program calls: active credential, right type, accepted issuer, not expired, mirror not stale. Returns a reason when it refuses |
| `programs/example_gated` | A vault whose `deposit` requires a credential, using the gate |
| `programs/gated_usdc_receiver` | USDC over Circle CCTP v2 that only a credentialed recipient can receive; otherwise it is held, then released or refunded |
| `crates/solidus-bridge-codec` | The message layouts, ids and consent digests shared with the Solidus chain |
| `tests` | LiteSVM tests of all of the above |

## Devnet deployments

| Program | Program id |
|---|---|
| `solidus_mirror` | `2MWe3EHixse6MGx5gBjqdY54Xn3SZ2bmkaSXnXp6tg7u` |
| `example_gated` | `FSssMtBBVvMc3t6Aj1mUJTyu2X3qF4rgC2HHt3oWcocQ` |
| `gated_usdc_receiver` | `567KfnzfZujzHpwuV9pj2EWTmLdHUYgMm2riPktpLdyU` |

Read the live addresses from the `/v1/routes` endpoint of the Bridge API, documented at
https://docs.solidus.network/api/bridge. This is testnet software with no value at stake.

## Build and test

Toolchain: Solana CLI 4.1.2 (Agave), Anchor 1.2.0, Rust from `rust-toolchain.toml`.

```bash
for p in solidus_mirror example_gated gated_usdc_receiver; do
  (cd programs/$p && cargo build-sbf --arch v0 --sbf-out-dir ../../target/deploy)
done
cargo test --no-fail-fast
```

Build each program from its own directory: one build over the whole workspace unifies features, and
the gate library's `cpi` feature would strip the mirror's entrypoint. Build with `--arch v0`;
`anchor build` emits SBPF v3, which the deployed programs do not use.

## More

- [Bridge developers page](https://bridge.solidus.network/developers) and the [API reference](https://docs.solidus.network/api/bridge)
- EVM contracts: https://github.com/solidusnetwork/bridge-contracts

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
