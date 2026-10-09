//! Example: a vault whose `deposit` requires a Solidus KycL2 credential.
//! The Solana twin of `ExampleGatedVault.sol`: same credential type, same one-day staleness window.

use anchor_lang::prelude::*;
use solidus_gate::{check, GateAccounts, GateReason};

declare_id!("FSssMtBBVvMc3t6Aj1mUJTyu2X3qF4rgC2HHt3oWcocQ");

/// One day, as on EVM.
pub const MAX_AGE: u64 = 86_400;

#[program]
pub mod example_gated {
    use super::*;

    /// Record which issuer this vault trusts. Example only: the first caller sets it.
    pub fn initialize(ctx: Context<Initialize>, issuer_did_hash: [u8; 32]) -> Result<()> {
        ctx.accounts.vault.issuer_did_hash = issuer_did_hash;
        ctx.accounts.vault.bump = ctx.bumps.vault;
        Ok(())
    }

    /// Move `amount` lamports into the vault, only for a holder the gate passes.
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let holder = ctx.accounts.depositor.key().to_bytes();
        let kyc_l2 = solidus_bridge_codec::credential_type_hash("KycL2");
        let reason = check(
            GateAccounts {
                config: &ctx.accounts.mirror_config,
                latest: &ctx.accounts.latest,
                export: &ctx.accounts.export,
                issuer: &ctx.accounts.issuer,
            },
            holder,
            kyc_l2,
            ctx.accounts.vault.issuer_did_hash,
            MAX_AGE,
            Clock::get()?.unix_timestamp,
        );
        if reason != GateReason::Ok {
            msg!("CredentialRequired reason={}", reason as u8);
            return err!(ExampleError::CredentialRequired);
        }
        anchor_lang::system_program::transfer(
            CpiContext::new(
                anchor_lang::system_program::ID,
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.depositor.to_account_info(),
                    to: ctx.accounts.vault.to_account_info(),
                },
            ),
            amount,
        )?;
        ctx.accounts.vault.deposits = ctx.accounts.vault.deposits.saturating_add(1);
        Ok(())
    }
}

#[account]
pub struct Vault {
    pub issuer_did_hash: [u8; 32],
    pub deposits: u64,
    pub bump: u8,
}

#[error_code]
pub enum ExampleError {
    #[msg("a Solidus credential is required (see the logged reason)")]
    CredentialRequired,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(init, payer = payer, space = 8 + 32 + 8 + 1, seeds = [b"vault"], bump)]
    pub vault: Account<'info, Vault>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub depositor: Signer<'info>,
    #[account(mut, seeds = [b"vault"], bump = vault.bump)]
    pub vault: Account<'info, Vault>,
    /// CHECK: verified by solidus_gate::check (PDA and owner).
    pub mirror_config: UncheckedAccount<'info>,
    /// CHECK: verified by solidus_gate::check (PDA and owner).
    pub latest: UncheckedAccount<'info>,
    /// CHECK: verified by solidus_gate::check (PDA and owner).
    pub export: UncheckedAccount<'info>,
    /// CHECK: verified by solidus_gate::check (PDA and owner).
    pub issuer: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}
