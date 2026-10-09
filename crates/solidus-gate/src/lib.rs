//! The Solana twin of `SolidusGate.sol`.
//!
//! A calling program passes the mirror PDAs it already holds; `check` reads them and returns a reason,
//! with no CPI. Same reasons, same order, same arithmetic as the EVM library.
//!
//! ⛔ AN ACCOUNT THAT IS NOT THE RIGHT MIRROR PDA FAILS CLOSED. Every account is checked against the
//! PDA its seeds derive and against the mirror program as owner. A caller passing a forged account
//! gets the reason for that slot (no export, not accredited, stale), never `OK`.

use anchor_lang::prelude::*;
use solidus_bridge_codec as codec;
use solidus_mirror::state::{ExportRecord, IssuerRecord, LatestExport, MirrorConfig};
use solidus_mirror::{CONFIG_SEED, EXPORT_SEED, ISSUER_SEED, LATEST_SEED};

/// Reason codes, numerically identical to the EVM `GateReason` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GateReason {
    Ok = 0,
    NoExport = 1,
    NotActive = 2,
    IssuerNotAccredited = 3,
    Expired = 4,
    Stale = 5,
}

/// The four mirror PDAs a gate reads. `latest` is `[b"latest", gate_key]`, `export` is
/// `[b"export", latest.export_id]`, `issuer` is `[b"issuer", issuer_did_hash]`, `config` is `[b"config"]`.
pub struct GateAccounts<'a, 'info> {
    pub config: &'a AccountInfo<'info>,
    pub latest: &'a AccountInfo<'info>,
    pub export: &'a AccountInfo<'info>,
    pub issuer: &'a AccountInfo<'info>,
}

/// Where each PDA for this check lives, so a client can build the account list.
pub fn gate_addresses(holder: &[u8; 32], credential_type_hash: &[u8; 32], issuer_did_hash: &[u8; 32]) -> (Pubkey, Pubkey, Pubkey) {
    let gk = codec::gate_key(holder, credential_type_hash, issuer_did_hash);
    (
        pda(&[CONFIG_SEED]),
        pda(&[LATEST_SEED, &gk]),
        pda(&[ISSUER_SEED, issuer_did_hash]),
    )
}

pub fn export_address(export_id: &[u8; 32]) -> Pubkey {
    pda(&[EXPORT_SEED, export_id])
}

fn pda(seeds: &[&[u8]]) -> Pubkey {
    Pubkey::find_program_address(seeds, &solidus_mirror::ID).0
}

/// Load `T` only if `acc` is exactly the mirror-owned PDA at `expected`.
fn load<T: AccountDeserialize>(acc: &AccountInfo, expected: &Pubkey) -> Option<T> {
    if acc.key != expected || acc.owner != &solidus_mirror::ID {
        return None;
    }
    let data = acc.try_borrow_data().ok()?;
    if data.is_empty() {
        return None;
    }
    T::try_deserialize(&mut &data[..]).ok()
}

/// The entry point.
pub fn check(
    accounts: GateAccounts,
    holder: [u8; 32],
    credential_type_hash: [u8; 32],
    issuer_did_hash: [u8; 32],
    max_age: u64,
    now: i64,
) -> GateReason {
    let (config_key, latest_key, issuer_key) = gate_addresses(&holder, &credential_type_hash, &issuer_did_hash);
    let latest: Option<LatestExport> = load(accounts.latest, &latest_key);
    let export: Option<ExportRecord> = latest
        .as_ref()
        .and_then(|l| load(accounts.export, &export_address(&l.export_id)));
    let issuer: Option<IssuerRecord> = load(accounts.issuer, &issuer_key);
    let heartbeat_ts = load::<MirrorConfig>(accounts.config, &config_key).map(|c| c.heartbeat_ts).unwrap_or(0);
    check_records(latest.as_ref(), export.as_ref(), issuer.as_ref(), heartbeat_ts, max_age, now)
}

/// The decision on already-loaded records. Separate so the order can be tested without accounts.
///
/// ⛔ THE ORDER IS PART OF THE ANSWER (as on EVM): the first thing wrong is the thing reported, most
/// actionable first.
pub fn check_records(
    latest: Option<&LatestExport>,
    export: Option<&ExportRecord>,
    issuer: Option<&IssuerRecord>,
    heartbeat_ts: u64,
    max_age: u64,
    now: i64,
) -> GateReason {
    let Some(_) = latest else { return GateReason::NoExport };
    // A latest pointer whose export record cannot be read is treated as no export: fail closed.
    let Some(r) = export else { return GateReason::NoExport };
    if r.status != codec::ExportStatus::Active as u8 {
        return GateReason::NotActive;
    }
    if !issuer.map(|i| i.accredited).unwrap_or(false) {
        return GateReason::IssuerNotAccredited;
    }
    let now = if now < 0 { 0u64 } else { now as u64 };
    // `valid_until == 0` is "no expiry".
    if r.valid_until != 0 && r.valid_until <= now {
        return GateReason::Expired;
    }
    // ⚠ WRITTEN AS AN ADDITION, as on EVM: a heartbeat ahead of this chain's clock is normal, and the
    // subtraction form would underflow on it. Saturating so a huge max_age cannot wrap.
    if heartbeat_ts == 0 || heartbeat_ts.saturating_add(max_age) < now {
        return GateReason::Stale;
    }
    GateReason::Ok
}
