//! The Solidus credential mirror on Solana.
//!
//! It applies Solidus bridge messages that at least `threshold` configured validators signed, in
//! strict per-domain order, with the same rules and error names as the EVM
//! `SolidusCredentialMirror`. Anyone may submit: the signatures are the authority, not the payer.
//!
//! ⛔ THE ORDER OF CHECKS IS THE EVM ORDER AND IT IS NOT COSMETIC: decode, sequence, digest, count,
//! recover (low-s, ascending, known), increment, apply. The transaction is atomic, so a message that
//! fails any check consumes no sequence number.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{program::invoke_signed, system_instruction};
use solidus_bridge_codec as codec;

pub mod errors;
pub mod state;

use errors::MirrorError;
use state::*;

declare_id!("2MWe3EHixse6MGx5gBjqdY54Xn3SZ2bmkaSXnXp6tg7u");

pub const CONFIG_SEED: &[u8] = b"config";
pub const EXPORT_SEED: &[u8] = b"export";
pub const LATEST_SEED: &[u8] = b"latest";
pub const ISSUER_SEED: &[u8] = b"issuer";

/// secp256k1 n / 2. A signature with a larger `s` is the same signature with a flipped `v` (EIP-2).
const HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

#[program]
pub mod solidus_mirror {
    use super::*;

    /// ⛔ ONLY THE UPGRADE AUTHORITY MAY INITIALISE. An open `initialize` lets anyone front-run the
    /// deploy and install their own validator set. The EVM mirror takes its validators in the
    /// constructor for the same reason. After this runs, the deploy makes the program immutable,
    /// which is the Solana form of the EVM mirror's "no owner, no upgrade path".
    pub fn initialize(
        ctx: Context<Initialize>,
        solidus_chain_id: u64,
        solidus_domain: u32,
        local_domain: u32,
        validators: Vec<[u8; 20]>,
        threshold: u8,
    ) -> Result<()> {
        require!(validators.len() <= MAX_VALIDATORS, MirrorError::TooManyValidators);
        require!(
            threshold >= 1 && (threshold as usize) <= validators.len(),
            MirrorError::BadThreshold
        );
        for (i, v) in validators.iter().enumerate() {
            require!(*v != [0u8; 20], MirrorError::ZeroValidator);
            require!(!validators[..i].contains(v), MirrorError::DuplicateValidator);
        }
        let c = &mut ctx.accounts.config;
        c.solidus_chain_id = solidus_chain_id;
        c.solidus_domain = solidus_domain;
        c.local_domain = local_domain;
        c.validators = validators;
        c.threshold = threshold;
        c.next_domain_seq = 1;
        c.heartbeat_ts = 0;
        c.heartbeat_height = 0;
        c.global_root = [0u8; 32];
        c.bump = ctx.bumps.config;
        Ok(())
    }

    /// Apply one attested message. Accounts after `system_program`, by kind:
    /// credential status: `[export, latest, issuer]`; issuer status: `[issuer]`; heartbeat: none.
    pub fn submit<'info>(
        ctx: Context<'info, Submit<'info>>,
        message: Vec<u8>,
        signatures: Vec<[u8; 65]>,
    ) -> Result<()> {
        let msg = codec::decode(&message).map_err(|_| error!(MirrorError::CodecError))?;
        let header = *msg.header();
        let config = &mut ctx.accounts.config;
        require!(header.domain_seq == config.next_domain_seq, MirrorError::OutOfSequence);

        // The attestation digest, built from the codec's preimage so the layout cannot drift; keccak by syscall.
        let message_id = solana_keccak_hasher::hash(&message).to_bytes();
        let preimage = codec::attestation_preimage(
            config.solidus_chain_id,
            config.local_domain,
            header.domain_seq,
            &message_id,
            header.solidus_height,
        );
        let digest = solana_keccak_hasher::hash(&preimage).to_bytes();
        let mut framed = [0u8; 60];
        framed[..28].copy_from_slice(b"\x19Ethereum Signed Message:\n32");
        framed[28..].copy_from_slice(&digest);
        let signed = solana_keccak_hasher::hash(&framed).to_bytes();

        verify_signatures(&signed, &signatures, &config.validators, config.threshold)?;

        config.next_domain_seq = config
            .next_domain_seq
            .checked_add(1)
            .ok_or(error!(MirrorError::OutOfSequence))?;

        let payer = ctx.accounts.payer.to_account_info();
        let system = ctx.accounts.system_program.to_account_info();
        let rest = ctx.remaining_accounts;
        match msg {
            codec::BridgeMessage::CredentialStatus { header, body } => {
                require!(rest.len() >= 3, MirrorError::MissingAccount);
                let (export_acc, latest_acc, issuer_acc) = (&rest[0], &rest[1], &rest[2]);

                let export_bump = expect_pda(export_acc, &[EXPORT_SEED, &body.export_id])?;
                ensure_account(&payer, export_acc, &system, &[EXPORT_SEED, &body.export_id], export_bump, ExportRecord::SPACE)?;
                write(export_acc, &ExportRecord {
                    issuer_did_hash: body.issuer_did_hash,
                    credential_type_hash: body.credential_type_hash,
                    holder: body.holder,
                    status: body.status as u8,
                    valid_until: body.valid_until,
                    solidus_height: header.solidus_height,
                    bump: export_bump,
                })?;

                // ⛔ THE POINTER MOVES ONLY TO AN ACTIVE EXPORT, exactly as on EVM. If it followed
                // every message, revoking a stale export would close the gate on a holder whose
                // current credential is fine.
                let gk = codec::gate_key(&body.holder, &body.credential_type_hash, &body.issuer_did_hash);
                let latest_bump = expect_pda(latest_acc, &[LATEST_SEED, &gk])?;
                if body.status == codec::ExportStatus::Active {
                    ensure_account(&payer, latest_acc, &system, &[LATEST_SEED, &gk], latest_bump, LatestExport::SPACE)?;
                    write(latest_acc, &LatestExport { export_id: body.export_id, bump: latest_bump })?;
                }

                let issuer_bump = expect_pda(issuer_acc, &[ISSUER_SEED, &body.issuer_did_hash])?;
                ensure_account(&payer, issuer_acc, &system, &[ISSUER_SEED, &body.issuer_did_hash], issuer_bump, IssuerRecord::SPACE)?;
                write(issuer_acc, &IssuerRecord { accredited: body.issuer_accredited, bump: issuer_bump })?;

                emit!(CredentialStatusApplied {
                    export_id: body.export_id,
                    holder: body.holder,
                    status: body.status as u8,
                    domain_seq: header.domain_seq,
                    solidus_height: header.solidus_height,
                });
            }
            codec::BridgeMessage::IssuerStatus { header, body } => {
                require!(!rest.is_empty(), MirrorError::MissingAccount);
                let issuer_acc = &rest[0];
                let bump = expect_pda(issuer_acc, &[ISSUER_SEED, &body.issuer_did_hash])?;
                ensure_account(&payer, issuer_acc, &system, &[ISSUER_SEED, &body.issuer_did_hash], bump, IssuerRecord::SPACE)?;
                write(issuer_acc, &IssuerRecord { accredited: body.accredited, bump })?;
                emit!(IssuerStatusApplied {
                    issuer_did_hash: body.issuer_did_hash,
                    accredited: body.accredited,
                    domain_seq: header.domain_seq,
                });
            }
            codec::BridgeMessage::Heartbeat { header, body } => {
                config.heartbeat_ts = body.solidus_timestamp;
                config.heartbeat_height = header.solidus_height;
                config.global_root = body.global_root;
                emit!(HeartbeatApplied {
                    solidus_timestamp: body.solidus_timestamp,
                    solidus_height: header.solidus_height,
                    domain_seq: header.domain_seq,
                });
            }
        }
        Ok(())
    }
}

/// Count first, then recover each: low-s, ascending, a configured validator. The EVM order.
fn verify_signatures(hash: &[u8; 32], sigs: &[[u8; 65]], validators: &[[u8; 20]], threshold: u8) -> Result<()> {
    // ⚠ COUNTED BEFORE ANYTHING IS RECOVERED, as on EVM: a caller who simply sent too few must not
    // be told their first signature was malformed.
    require!(sigs.len() >= threshold as usize, MirrorError::NotEnoughSignatures);
    let mut previous = [0u8; 20];
    for sig in sigs {
        let s: &[u8] = &sig[32..64];
        require!(s <= &HALF_N[..], MirrorError::HighS);
        let v = sig[64];
        let recovery_id = if v >= 27 { v - 27 } else { v };
        let pk = solana_secp256k1_recover::secp256k1_recover(hash, recovery_id, &sig[..64])
            .map_err(|_| error!(MirrorError::BadSignature))?;
        let h = solana_keccak_hasher::hash(&pk.to_bytes()).to_bytes();
        let mut signer = [0u8; 20];
        signer.copy_from_slice(&h[12..]);
        // Ascending order IS the duplicate check: one pass, no set.
        require!(signer > previous, MirrorError::SignersOutOfOrder);
        require!(validators.contains(&signer), MirrorError::UnknownSigner);
        previous = signer;
    }
    Ok(())
}

/// The account must be the PDA these seeds derive; returns its bump.
fn expect_pda(acc: &AccountInfo, seeds: &[&[u8]]) -> Result<u8> {
    let (expected, bump) = Pubkey::find_program_address(seeds, &crate::ID);
    require_keys_eq!(acc.key(), expected, MirrorError::WrongAccount);
    Ok(bump)
}

/// Create the PDA owned by this program if it does not exist yet, paid by the submitter.
///
/// ⚠ A PRE-FUNDED ADDRESS IS HANDLED, NOT REFUSED. Anyone can send lamports to a PDA address
/// before it exists, and `create_account` would then fail, letting a griefer block an export by
/// sending dust. So an address that holds lamports but is still system-owned is topped up,
/// allocated and assigned instead.
fn ensure_account<'info>(
    payer: &AccountInfo<'info>,
    acc: &AccountInfo<'info>,
    system: &AccountInfo<'info>,
    seeds: &[&[u8]],
    bump: u8,
    space: usize,
) -> Result<()> {
    if acc.owner == &crate::ID {
        return Ok(());
    }
    require_keys_eq!(*acc.owner, anchor_lang::system_program::ID, MirrorError::WrongAccount);
    let bump_slice = [bump];
    let mut signer_seeds: Vec<&[u8]> = seeds.to_vec();
    signer_seeds.push(&bump_slice);
    let rent = Rent::get()?.minimum_balance(space);
    if acc.lamports() == 0 {
        invoke_signed(
            &system_instruction::create_account(payer.key, acc.key, rent, space as u64, &crate::ID),
            &[payer.clone(), acc.clone(), system.clone()],
            &[&signer_seeds],
        )?;
    } else {
        let top_up = rent.saturating_sub(acc.lamports());
        if top_up > 0 {
            anchor_lang::solana_program::program::invoke(
                &system_instruction::transfer(payer.key, acc.key, top_up),
                &[payer.clone(), acc.clone(), system.clone()],
            )?;
        }
        invoke_signed(&system_instruction::allocate(acc.key, space as u64), &[acc.clone(), system.clone()], &[&signer_seeds])?;
        invoke_signed(&system_instruction::assign(acc.key, &crate::ID), &[acc.clone(), system.clone()], &[&signer_seeds])?;
    }
    Ok(())
}

fn write<T: AccountSerialize>(acc: &AccountInfo, value: &T) -> Result<()> {
    let mut data = acc.try_borrow_mut_data()?;
    let mut cursor: &mut [u8] = &mut data;
    value.try_serialize(&mut cursor)
}

// The EVM mirror's three events, same fields, so the gateway's `/applied` feed reads both alike.
// ⚠ A watcher must attribute these to THIS program by the invocation stack: any program in the same
// transaction can write a log line that looks like one (gateway `watch-svm.ts`).
#[event]
pub struct CredentialStatusApplied {
    pub export_id: [u8; 32],
    pub holder: [u8; 32],
    pub status: u8,
    pub domain_seq: u64,
    pub solidus_height: u64,
}

#[event]
pub struct IssuerStatusApplied {
    pub issuer_did_hash: [u8; 32],
    pub accredited: bool,
    pub domain_seq: u64,
}

#[event]
pub struct HeartbeatApplied {
    pub solidus_timestamp: u64,
    pub solidus_height: u64,
    pub domain_seq: u64,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(init, payer = authority, space = MirrorConfig::SPACE, seeds = [CONFIG_SEED], bump)]
    pub config: Account<'info, MirrorConfig>,
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ MirrorError::NotUpgradeAuthority)]
    pub program: Program<'info, crate::program::SolidusMirror>,
    #[account(constraint = program_data.upgrade_authority_address == Some(authority.key()) @ MirrorError::NotUpgradeAuthority)]
    pub program_data: Account<'info, ProgramData>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Submit<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, MirrorConfig>,
    pub system_program: Program<'info, System>,
}
