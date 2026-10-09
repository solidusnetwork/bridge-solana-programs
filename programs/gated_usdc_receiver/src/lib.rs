//! USDC over CCTP v2 that only a credentialed recipient can receive: the Solana twin of
//! `GatedUsdcReceiver.sol`.
//!
//! A sender burns on another chain naming this program's `vault` token account as `mintRecipient`
//! and its `authority` PDA as `destinationCaller`, so Circle lets no one else complete the transfer.
//! Anyone then calls `relay`. The gate decides: a credentialed `final_recipient` is paid at once,
//! anyone else's USDC waits in an escrow PDA `[b"escrow", keccak(message)]` until the gate passes
//! (`release`) or the hook's deadline passes (`refund`).
//!
//! ⛔ FOUR THINGS ARE DIFFERENT FROM THE EVM RECEIVER, all measured on Solana:
//!  1. `relay` MUST BE A TOP-LEVEL INSTRUCTION. Its CPI chain is this program (1) → MessageTransmitter (2)
//!     → TokenMessengerMinter (3) → SPL Token (4), against a stack limit of 5.
//!  2. THERE IS NO TRY/CATCH AROUND A CPI. A refused transfer aborts the transaction, Circle's receipt
//!     with it. So EVM's "a refused transfer escrows as reason 6" is a PRE-CHECK: a frozen recipient
//!     token account (the SPL blocklist) escrows before any transfer is attempted.
//!  3. A missing recipient token account is CREATED, idempotently, paid by the relayer. It is not a
//!     reason to escrow: the recipient did nothing wrong by not having one yet.
//!  4. The relay transaction needs an address lookup table: ~1,570 bytes as a legacy transaction.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::solana_program::program::{invoke, invoke_signed};
use anchor_lang::solana_program::system_instruction;
use solidus_bridge_codec as codec;
use solidus_gate::{GateAccounts, GateReason};

declare_id!("567KfnzfZujzHpwuV9pj2EWTmLdHUYgMm2riPktpLdyU");

pub const CONFIG_SEED: &[u8] = b"config";
pub const AUTHORITY_SEED: &[u8] = b"authority";
pub const VAULT_SEED: &[u8] = b"vault";
pub const ESCROW_SEED: &[u8] = b"escrow";

pub const GATE_MAX_AGE: u64 = 86_400;
/// The gate passed but the recipient's token account is frozen. After `GateReason::Stale` (5).
pub const TRANSFER_FAILED: u8 = 6;

pub const HELD: u8 = 1;
pub const RELEASED: u8 = 2;
pub const REFUNDED: u8 = 3;

/// Circle CCTP v2 on Solana (devnet and mainnet share the ids).
pub const MESSAGE_TRANSMITTER_ID: Pubkey = pubkey!("CCTPV2Sm4AdWt5296sk4P66VBZ7bEhcARwFaaS9YPbeC");
pub const TOKEN_PROGRAM_ID: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const ASSOCIATED_TOKEN_PROGRAM_ID: Pubkey = pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
/// `sha256("global:receive_message")[..8]`, matching Circle's Anchor program.
pub const RECEIVE_MESSAGE_DISCRIMINATOR: [u8; 8] = [0x26, 0x90, 0x7f, 0xe1, 0x1f, 0xe1, 0xee, 0x19];

// CCTP v2 offsets in the full message: a 148-byte header, then the burn body.
pub const MINT_RECIPIENT_AT: usize = 148 + 36;
pub const FEE_EXECUTED_AT: usize = 148 + 164;
pub const HOOK_AT: usize = 148 + 228;

// SPL token account layout (165 bytes): mint 0..32, owner 32..64, amount 64..72, state at 108.
const TOKEN_ACCOUNT_LEN: usize = 165;
const TOKEN_STATE_FROZEN: u8 = 2;

#[program]
pub mod gated_usdc_receiver {
    use super::*;

    /// Create the config and the vault token account. Only the program's upgrade authority, so no one
    /// can front-run the deploy with their own mint.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let (authority, authority_bump) = Pubkey::find_program_address(&[AUTHORITY_SEED], &crate::ID);
        let (vault, vault_bump) = Pubkey::find_program_address(&[VAULT_SEED], &crate::ID);
        require_keys_eq!(ctx.accounts.vault.key(), vault, ReceiverError::WrongAccount);

        let rent = Rent::get()?.minimum_balance(TOKEN_ACCOUNT_LEN);
        invoke_signed(
            &system_instruction::create_account(
                ctx.accounts.payer.key,
                &vault,
                rent,
                TOKEN_ACCOUNT_LEN as u64,
                &TOKEN_PROGRAM_ID,
            ),
            &[
                ctx.accounts.payer.to_account_info(),
                ctx.accounts.vault.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
            &[&[VAULT_SEED, &[vault_bump]]],
        )?;
        // InitializeAccount3 (tag 18): owner in the data, so no rent sysvar account is needed.
        let mut data = vec![18u8];
        data.extend_from_slice(authority.as_ref());
        invoke(
            &Instruction {
                program_id: TOKEN_PROGRAM_ID,
                accounts: vec![
                    AccountMeta::new(vault, false),
                    AccountMeta::new_readonly(ctx.accounts.usdc_mint.key(), false),
                ],
                data,
            },
            &[ctx.accounts.vault.to_account_info(), ctx.accounts.usdc_mint.to_account_info()],
        )?;

        let config = &mut ctx.accounts.config;
        config.usdc_mint = ctx.accounts.usdc_mint.key();
        config.vault = vault;
        config.authority_bump = authority_bump;
        config.vault_bump = vault_bump;
        config.bump = ctx.bumps.config;
        Ok(())
    }

    /// Complete a CCTP transfer and pay or escrow. Anyone may call it; Circle enforces that the
    /// `destinationCaller` is our authority PDA, which only this program can sign for.
    pub fn relay<'info>(ctx: Context<'info, Relay<'info>>, message: Vec<u8>, attestation: Vec<u8>) -> Result<()> {
        let a = &ctx.accounts;

        // 1. Shape before Circle, so a message that cannot be ours fails with a reason that names it.
        require!(message.len() >= HOOK_AT, ReceiverError::MessageTooShort);
        require!(
            message[MINT_RECIPIENT_AT..MINT_RECIPIENT_AT + 32] == a.config.vault.to_bytes(),
            ReceiverError::NotForThisReceiver
        );
        let hook = codec::decode_usdc_hook(&message[HOOK_AT..]).map_err(|e| {
            msg!("hook rejected: {:?}", e);
            error!(ReceiverError::BadHook)
        })?;
        require!(hook.refund_address != [0u8; 32], ReceiverError::ZeroRefundAddress);
        require_keys_eq!(a.recipient.key(), Pubkey::new_from_array(hook.final_recipient), ReceiverError::WrongRecipient);
        require_keys_eq!(
            a.recipient_token.key(),
            associated_token_address(&a.recipient.key(), &a.config.usdc_mint),
            ReceiverError::WrongTokenAccount
        );

        let hash = solana_keccak_hasher::hash(&message).to_bytes();
        let escrow_bump = expect_pda(&a.escrow, &[ESCROW_SEED, &hash])?;

        // 2. Circle. Its failure (a used nonce, a bad attestation) aborts everything here.
        let before = token_amount(&a.vault)?;
        cpi_receive_message(&ctx, &message, &attestation)?;

        // 3. ⛔ THE BALANCE DELTA, NOT THE MESSAGE'S AMOUNT. Circle pays `amount - fee` out of custody.
        let amount = token_amount(&a.vault)?.checked_sub(before).ok_or(ReceiverError::NothingMinted)?;
        require!(amount > 0, ReceiverError::NothingMinted);
        let fee = u64_from_be32(&message[FEE_EXECUTED_AT..FEE_EXECUTED_AT + 32]);

        // 4. The gate: the same crate the example program uses, one implementation of the rules.
        let now = Clock::get()?.unix_timestamp;
        let mut reason = solidus_gate::check(
            gate_accounts(&a.mirror_config, &a.mirror_latest, &a.mirror_export, &a.mirror_issuer),
            hook.final_recipient,
            hook.credential_type_hash,
            hook.issuer_did_hash,
            GATE_MAX_AGE,
            now,
        ) as u8;

        if reason == GateReason::Ok as u8 {
            create_ata_idempotent(&a.payer, &a.recipient_token, &a.recipient, &a.usdc_mint, &a.system_program, &a.token_program, &a.associated_token_program)?;
            if token_state(&a.recipient_token)? == TOKEN_STATE_FROZEN {
                reason = TRANSFER_FAILED;
            } else {
                pay(&a.vault, &a.recipient_token, &a.authority, &a.token_program, a.config.authority_bump, amount)?;
                emit!(UsdcDelivered {
                    hash,
                    recipient: a.recipient.key(),
                    amount,
                    fee,
                    referral_code: hook.referral_code,
                });
                return Ok(());
            }
        }

        ensure_account(&a.payer, &a.escrow, &a.system_program, &[ESCROW_SEED, &hash], escrow_bump, 8 + Escrow::INIT_SPACE)?;
        write(
            &a.escrow,
            &Escrow {
                final_recipient: hook.final_recipient,
                refund_address: hook.refund_address,
                amount,
                deadline: hook.deadline,
                credential_type_hash: hook.credential_type_hash,
                issuer_did_hash: hook.issuer_did_hash,
                referral_code: hook.referral_code,
                state: HELD,
                bump: escrow_bump,
            },
        )?;
        emit!(UsdcEscrowed { hash, final_recipient: hook.final_recipient, amount, reason, deadline: hook.deadline });
        Ok(())
    }

    /// Pay a held escrow once the gate passes, before the deadline. Anyone may call it.
    pub fn release(ctx: Context<Release>, hash: [u8; 32]) -> Result<()> {
        let a = &ctx.accounts;
        expect_pda(&a.escrow, &[ESCROW_SEED, &hash])?;
        let mut e = read_escrow(&a.escrow)?;
        require!(e.state == HELD, ReceiverError::NotHeld);
        let now = Clock::get()?.unix_timestamp;
        require!(now <= e.deadline as i64, ReceiverError::DeadlinePassed);
        require_keys_eq!(a.recipient.key(), Pubkey::new_from_array(e.final_recipient), ReceiverError::WrongRecipient);
        require_keys_eq!(
            a.recipient_token.key(),
            associated_token_address(&a.recipient.key(), &a.config.usdc_mint),
            ReceiverError::WrongTokenAccount
        );
        let reason = solidus_gate::check(
            gate_accounts(&a.mirror_config, &a.mirror_latest, &a.mirror_export, &a.mirror_issuer),
            e.final_recipient,
            e.credential_type_hash,
            e.issuer_did_hash,
            GATE_MAX_AGE,
            now,
        ) as u8;
        if reason != GateReason::Ok as u8 {
            msg!("GateStillFails reason={}", reason);
            return err!(ReceiverError::GateStillFails);
        }

        // Effects before the interaction. A frozen account makes the transfer fail and the whole
        // instruction revert, which leaves the escrow held, the same as the EVM `release`.
        e.state = RELEASED;
        write(&a.escrow, &e)?;
        create_ata_idempotent(&a.payer, &a.recipient_token, &a.recipient, &a.usdc_mint, &a.system_program, &a.token_program, &a.associated_token_program)?;
        pay(&a.vault, &a.recipient_token, &a.authority, &a.token_program, a.config.authority_bump, e.amount)?;
        emit!(UsdcReleased { hash, recipient: a.recipient.key(), amount: e.amount });
        Ok(())
    }

    /// Return a held escrow to its refund address after the deadline. Anyone may call it.
    pub fn refund(ctx: Context<Refund>, hash: [u8; 32]) -> Result<()> {
        let a = &ctx.accounts;
        expect_pda(&a.escrow, &[ESCROW_SEED, &hash])?;
        let mut e = read_escrow(&a.escrow)?;
        require!(e.state == HELD, ReceiverError::NotHeld);
        let now = Clock::get()?.unix_timestamp;
        require!(now > e.deadline as i64, ReceiverError::DeadlineNotPassed);
        require_keys_eq!(a.refund_owner.key(), Pubkey::new_from_array(e.refund_address), ReceiverError::WrongRecipient);
        require_keys_eq!(
            a.refund_token.key(),
            associated_token_address(&a.refund_owner.key(), &a.config.usdc_mint),
            ReceiverError::WrongTokenAccount
        );

        e.state = REFUNDED;
        write(&a.escrow, &e)?;
        create_ata_idempotent(&a.payer, &a.refund_token, &a.refund_owner, &a.usdc_mint, &a.system_program, &a.token_program, &a.associated_token_program)?;
        pay(&a.vault, &a.refund_token, &a.authority, &a.token_program, a.config.authority_bump, e.amount)?;
        emit!(UsdcRefunded { hash, refund_address: a.refund_owner.key(), amount: e.amount });
        Ok(())
    }
}

// ------------------------------------------------------------------ Circle CPI

/// `receive_message` on MessageTransmitterV2, signed by our authority PDA as `caller`.
///
/// The remaining accounts are Circle's own, in Circle's order, from `authority_pda` onwards.
/// They are not trusted: Circle's program checks every one of them, and the
/// balance delta on OUR vault is the only thing this program believes afterwards.
fn cpi_receive_message<'info>(ctx: &Context<'info, Relay<'info>>, message: &[u8], attestation: &[u8]) -> Result<()> {
    let a = &ctx.accounts;
    let mut data = RECEIVE_MESSAGE_DISCRIMINATOR.to_vec();
    data.extend_from_slice(&(message.len() as u32).to_le_bytes());
    data.extend_from_slice(message);
    data.extend_from_slice(&(attestation.len() as u32).to_le_bytes());
    data.extend_from_slice(attestation);

    let mut metas = vec![AccountMeta::new(a.payer.key(), true), AccountMeta::new_readonly(a.authority.key(), true)];
    let mut infos = vec![a.payer.to_account_info(), a.authority.to_account_info()];
    for acc in ctx.remaining_accounts.iter() {
        metas.push(if acc.is_writable { AccountMeta::new(*acc.key, false) } else { AccountMeta::new_readonly(*acc.key, false) });
        infos.push(acc.clone());
    }
    infos.push(a.message_transmitter_program.to_account_info());
    invoke_signed(
        &Instruction { program_id: MESSAGE_TRANSMITTER_ID, accounts: metas, data },
        &infos,
        &[&[AUTHORITY_SEED, &[a.config.authority_bump]]],
    )?;
    Ok(())
}

// ------------------------------------------------------------------ token helpers

pub fn associated_token_address(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[owner.as_ref(), TOKEN_PROGRAM_ID.as_ref(), mint.as_ref()], &ASSOCIATED_TOKEN_PROGRAM_ID).0
}

fn token_amount(acc: &AccountInfo) -> Result<u64> {
    require_keys_eq!(*acc.owner, TOKEN_PROGRAM_ID, ReceiverError::WrongTokenAccount);
    let d = acc.try_borrow_data()?;
    require!(d.len() == TOKEN_ACCOUNT_LEN, ReceiverError::WrongTokenAccount);
    Ok(u64::from_le_bytes(d[64..72].try_into().unwrap()))
}

fn token_state(acc: &AccountInfo) -> Result<u8> {
    require_keys_eq!(*acc.owner, TOKEN_PROGRAM_ID, ReceiverError::WrongTokenAccount);
    let d = acc.try_borrow_data()?;
    require!(d.len() == TOKEN_ACCOUNT_LEN, ReceiverError::WrongTokenAccount);
    Ok(d[108])
}

/// `CreateIdempotent` (tag 1) on the associated token program: a no-op when the account exists.
fn create_ata_idempotent<'info>(
    payer: &AccountInfo<'info>,
    ata: &AccountInfo<'info>,
    owner: &AccountInfo<'info>,
    mint: &AccountInfo<'info>,
    system: &AccountInfo<'info>,
    token: &AccountInfo<'info>,
    ata_program: &AccountInfo<'info>,
) -> Result<()> {
    invoke(
        &Instruction {
            program_id: ASSOCIATED_TOKEN_PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(*payer.key, true),
                AccountMeta::new(*ata.key, false),
                AccountMeta::new_readonly(*owner.key, false),
                AccountMeta::new_readonly(*mint.key, false),
                AccountMeta::new_readonly(*system.key, false),
                AccountMeta::new_readonly(*token.key, false),
            ],
            data: vec![1],
        },
        &[payer.clone(), ata.clone(), owner.clone(), mint.clone(), system.clone(), token.clone(), ata_program.clone()],
    )?;
    Ok(())
}

/// SPL `Transfer` (tag 3) out of the vault, signed by the authority PDA.
fn pay<'info>(
    vault: &AccountInfo<'info>,
    to: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    token: &AccountInfo<'info>,
    authority_bump: u8,
    amount: u64,
) -> Result<()> {
    let mut data = vec![3u8];
    data.extend_from_slice(&amount.to_le_bytes());
    invoke_signed(
        &Instruction {
            program_id: TOKEN_PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(*vault.key, false),
                AccountMeta::new(*to.key, false),
                AccountMeta::new_readonly(*authority.key, true),
            ],
            data,
        },
        &[vault.clone(), to.clone(), authority.clone(), token.clone()],
        &[&[AUTHORITY_SEED, &[authority_bump]]],
    )?;
    Ok(())
}

// ------------------------------------------------------------------ account helpers

fn gate_accounts<'a, 'info>(
    config: &'a AccountInfo<'info>,
    latest: &'a AccountInfo<'info>,
    export: &'a AccountInfo<'info>,
    issuer: &'a AccountInfo<'info>,
) -> GateAccounts<'a, 'info> {
    GateAccounts { config, latest, export, issuer }
}

fn u64_from_be32(b: &[u8]) -> u64 {
    // Circle's fee is a uint256; any value that does not fit in u64 is far beyond USDC's supply.
    u64::from_be_bytes(b[24..32].try_into().unwrap())
}

fn expect_pda(acc: &AccountInfo, seeds: &[&[u8]]) -> Result<u8> {
    let (expected, bump) = Pubkey::find_program_address(seeds, &crate::ID);
    require_keys_eq!(acc.key(), expected, ReceiverError::WrongAccount);
    Ok(bump)
}

fn read_escrow(acc: &AccountInfo) -> Result<Escrow> {
    if acc.owner != &crate::ID || acc.data_is_empty() {
        return err!(ReceiverError::NotHeld);
    }
    let data = acc.try_borrow_data()?;
    Escrow::try_deserialize(&mut &data[..])
}

/// Create the PDA owned by this program, paid by the relayer. A pre-funded address is topped up,
/// allocated and assigned rather than refused, so dust cannot block an escrow (same as the mirror).
fn ensure_account<'info>(
    payer: &AccountInfo<'info>,
    acc: &AccountInfo<'info>,
    system: &AccountInfo<'info>,
    seeds: &[&[u8]],
    bump: u8,
    space: usize,
) -> Result<()> {
    if acc.owner == &crate::ID {
        // Only a replayed message could reach an existing escrow, and Circle's nonce refuses that first.
        return err!(ReceiverError::WrongAccount);
    }
    require_keys_eq!(*acc.owner, anchor_lang::system_program::ID, ReceiverError::WrongAccount);
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
            invoke(&system_instruction::transfer(payer.key, acc.key, top_up), &[payer.clone(), acc.clone(), system.clone()])?;
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

// ------------------------------------------------------------------ state

#[account]
#[derive(InitSpace)]
pub struct ReceiverConfig {
    pub usdc_mint: Pubkey,
    pub vault: Pubkey,
    pub authority_bump: u8,
    pub vault_bump: u8,
    pub bump: u8,
}

/// `Escrow`, field for field with the EVM receiver.
#[account]
#[derive(InitSpace)]
pub struct Escrow {
    pub final_recipient: [u8; 32],
    pub refund_address: [u8; 32],
    pub amount: u64,
    pub deadline: u64,
    pub credential_type_hash: [u8; 32],
    pub issuer_did_hash: [u8; 32],
    pub referral_code: [u8; 8],
    pub state: u8,
    pub bump: u8,
}

// ------------------------------------------------------------------ accounts

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(init, payer = payer, space = 8 + ReceiverConfig::INIT_SPACE, seeds = [CONFIG_SEED], bump)]
    pub config: Account<'info, ReceiverConfig>,
    /// CHECK: created here as the `[b"vault"]` token account; its address is checked in the handler.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: the USDC mint, owned by SPL Token. Stored, then pinned by every later instruction.
    #[account(owner = TOKEN_PROGRAM_ID @ ReceiverError::WrongTokenAccount)]
    pub usdc_mint: UncheckedAccount<'info>,
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ ReceiverError::NotUpgradeAuthority)]
    pub program: Program<'info, crate::program::GatedUsdcReceiver>,
    #[account(constraint = program_data.upgrade_authority_address == Some(payer.key()) @ ReceiverError::NotUpgradeAuthority)]
    pub program_data: Account<'info, ProgramData>,
    /// CHECK: SPL Token program, pinned by address.
    #[account(address = TOKEN_PROGRAM_ID)]
    pub token_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Relay<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, ReceiverConfig>,
    /// CHECK: the `[b"authority"]` PDA; Circle's `destinationCaller`, signed for by this program.
    #[account(seeds = [AUTHORITY_SEED], bump = config.authority_bump)]
    pub authority: UncheckedAccount<'info>,
    /// CHECK: the vault token account, pinned by the config.
    #[account(mut, address = config.vault @ ReceiverError::WrongAccount)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: `[b"escrow", keccak(message)]`, checked in the handler; created only on the escrow path.
    #[account(mut)]
    pub escrow: UncheckedAccount<'info>,
    /// CHECK: must equal the hook's `final_recipient`; checked in the handler.
    pub recipient: UncheckedAccount<'info>,
    /// CHECK: the recipient's associated USDC account; address checked in the handler, created if absent.
    #[account(mut)]
    pub recipient_token: UncheckedAccount<'info>,
    /// CHECK: pinned by the config.
    #[account(address = config.usdc_mint @ ReceiverError::WrongAccount)]
    pub usdc_mint: UncheckedAccount<'info>,
    /// CHECK: mirror accounts; `solidus_gate::check` verifies each address and owner and fails closed.
    pub mirror_config: UncheckedAccount<'info>,
    /// CHECK: see `mirror_config`.
    pub mirror_latest: UncheckedAccount<'info>,
    /// CHECK: see `mirror_config`.
    pub mirror_export: UncheckedAccount<'info>,
    /// CHECK: see `mirror_config`.
    pub mirror_issuer: UncheckedAccount<'info>,
    /// CHECK: pinned by address.
    #[account(address = TOKEN_PROGRAM_ID)]
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: pinned by address.
    #[account(address = ASSOCIATED_TOKEN_PROGRAM_ID)]
    pub associated_token_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
    /// CHECK: Circle's MessageTransmitterV2, pinned by address.
    #[account(address = MESSAGE_TRANSMITTER_ID)]
    pub message_transmitter_program: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct Release<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, ReceiverConfig>,
    /// CHECK: see `Relay::authority`.
    #[account(seeds = [AUTHORITY_SEED], bump = config.authority_bump)]
    pub authority: UncheckedAccount<'info>,
    /// CHECK: see `Relay::vault`.
    #[account(mut, address = config.vault @ ReceiverError::WrongAccount)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: the escrow PDA for `hash`, checked in the handler.
    #[account(mut)]
    pub escrow: UncheckedAccount<'info>,
    /// CHECK: must equal the escrow's `final_recipient`.
    pub recipient: UncheckedAccount<'info>,
    /// CHECK: the recipient's associated USDC account, checked in the handler.
    #[account(mut)]
    pub recipient_token: UncheckedAccount<'info>,
    /// CHECK: pinned by the config.
    #[account(address = config.usdc_mint @ ReceiverError::WrongAccount)]
    pub usdc_mint: UncheckedAccount<'info>,
    /// CHECK: see `Relay::mirror_config`.
    pub mirror_config: UncheckedAccount<'info>,
    /// CHECK: see `Relay::mirror_config`.
    pub mirror_latest: UncheckedAccount<'info>,
    /// CHECK: see `Relay::mirror_config`.
    pub mirror_export: UncheckedAccount<'info>,
    /// CHECK: see `Relay::mirror_config`.
    pub mirror_issuer: UncheckedAccount<'info>,
    /// CHECK: pinned by address.
    #[account(address = TOKEN_PROGRAM_ID)]
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: pinned by address.
    #[account(address = ASSOCIATED_TOKEN_PROGRAM_ID)]
    pub associated_token_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Refund<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, ReceiverConfig>,
    /// CHECK: see `Relay::authority`.
    #[account(seeds = [AUTHORITY_SEED], bump = config.authority_bump)]
    pub authority: UncheckedAccount<'info>,
    /// CHECK: see `Relay::vault`.
    #[account(mut, address = config.vault @ ReceiverError::WrongAccount)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: the escrow PDA for `hash`, checked in the handler.
    #[account(mut)]
    pub escrow: UncheckedAccount<'info>,
    /// CHECK: must equal the escrow's `refund_address`.
    pub refund_owner: UncheckedAccount<'info>,
    /// CHECK: the refund owner's associated USDC account, checked in the handler.
    #[account(mut)]
    pub refund_token: UncheckedAccount<'info>,
    /// CHECK: pinned by the config.
    #[account(address = config.usdc_mint @ ReceiverError::WrongAccount)]
    pub usdc_mint: UncheckedAccount<'info>,
    /// CHECK: pinned by address.
    #[account(address = TOKEN_PROGRAM_ID)]
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: pinned by address.
    #[account(address = ASSOCIATED_TOKEN_PROGRAM_ID)]
    pub associated_token_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

// ------------------------------------------------------------------ events and errors

// The EVM receiver's four events, same fields, so a watcher reads both VMs alike.
#[event]
pub struct UsdcDelivered {
    pub hash: [u8; 32],
    pub recipient: Pubkey,
    pub amount: u64,
    pub fee: u64,
    pub referral_code: [u8; 8],
}

#[event]
pub struct UsdcEscrowed {
    pub hash: [u8; 32],
    pub final_recipient: [u8; 32],
    pub amount: u64,
    pub reason: u8,
    pub deadline: u64,
}

#[event]
pub struct UsdcReleased {
    pub hash: [u8; 32],
    pub recipient: Pubkey,
    pub amount: u64,
}

#[event]
pub struct UsdcRefunded {
    pub hash: [u8; 32],
    pub refund_address: Pubkey,
    pub amount: u64,
}

/// The EVM receiver's errors first, in its order, then the Solana-specific ones.
#[error_code]
pub enum ReceiverError {
    #[msg("no escrow is held under this hash")]
    NotHeld,
    #[msg("the escrow's deadline has passed; only refund remains")]
    DeadlinePassed,
    #[msg("the escrow's deadline has not passed yet")]
    DeadlineNotPassed,
    #[msg("the gate still fails for this recipient; the reason is in the log")]
    GateStillFails,
    #[msg("the message is shorter than a CCTP v2 burn with a hook")]
    MessageTooShort,
    #[msg("the message does not mint to this program's vault")]
    NotForThisReceiver,
    #[msg("the hook does not decode")]
    BadHook,
    #[msg("the hook names no refund address")]
    ZeroRefundAddress,
    #[msg("Circle paid nothing into the vault")]
    NothingMinted,
    #[msg("the account passed is not the one this message requires")]
    WrongAccount,
    #[msg("the recipient passed is not the one the hook or escrow names")]
    WrongRecipient,
    #[msg("the token account is not the owner's associated USDC account")]
    WrongTokenAccount,
    #[msg("only the program's upgrade authority may initialise the receiver")]
    NotUpgradeAuthority,
}
