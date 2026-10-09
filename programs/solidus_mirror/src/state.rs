use anchor_lang::prelude::*;

/// The most validators a mirror can be initialised with. Sizes the config account; four today.
pub const MAX_VALIDATORS: usize = 16;

/// `MirrorConfig`. Seeds `[b"config"]`.
///
/// ⚠ NO `bridge_module_sender`. An earlier draft named one; it was a leftover of a mailbox design
/// that was dropped. There is no mailbox program.
#[account]
pub struct MirrorConfig {
    pub solidus_chain_id: u64,
    pub solidus_domain: u32,
    pub local_domain: u32,
    pub validators: Vec<[u8; 20]>,
    pub threshold: u8,
    pub next_domain_seq: u64,
    pub heartbeat_ts: u64,
    pub heartbeat_height: u64,
    pub global_root: [u8; 32],
    pub bump: u8,
}

impl MirrorConfig {
    pub const SPACE: usize = 8 + 8 + 4 + 4 + (4 + 20 * MAX_VALIDATORS) + 1 + 8 + 8 + 8 + 32 + 1;
}

/// Seeds `[b"export", export_id]`. The same fields as the EVM `ExportRecord`.
#[account]
pub struct ExportRecord {
    pub issuer_did_hash: [u8; 32],
    pub credential_type_hash: [u8; 32],
    pub holder: [u8; 32],
    pub status: u8,
    pub valid_until: u64,
    pub solidus_height: u64,
    pub bump: u8,
}

impl ExportRecord {
    pub const SPACE: usize = 8 + 32 * 3 + 1 + 8 + 8 + 1;
}

/// Seeds `[b"latest", gate_key]`. Moves only to an ACTIVE export, as on EVM.
#[account]
pub struct LatestExport {
    pub export_id: [u8; 32],
    pub bump: u8,
}

impl LatestExport {
    pub const SPACE: usize = 8 + 32 + 1;
}

/// Seeds `[b"issuer", issuer_did_hash]`.
#[account]
pub struct IssuerRecord {
    pub accredited: bool,
    pub bump: u8,
}

impl IssuerRecord {
    pub const SPACE: usize = 8 + 1 + 1;
}
