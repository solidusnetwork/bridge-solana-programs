//! The mirror fixture: the built program in LiteSVM, initialised with four known validators and
//! threshold 3, plus helpers that build real messages with the shared codec and sign them through
//! the same EIP-191 path the chain's validators use.
#![allow(dead_code)]

use anchor_lang::{
    prelude::Pubkey,
    solana_program::{instruction::{AccountMeta, Instruction}, system_program},
    AccountDeserialize, InstructionData, ToAccountMetas,
};
use k256::ecdsa::SigningKey;
use litesvm::LiteSVM;
use sha3::{Digest, Keccak256};
use solana_keypair::Keypair;
use solana_message::{Message, VersionedMessage};
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solidus_bridge_codec as codec;
use solidus_mirror::{state::*, CONFIG_SEED, EXPORT_SEED, ISSUER_SEED, LATEST_SEED};

pub const SOLIDUS_CHAIN_ID: u64 = 50_002;
pub const SOLIDUS_DOMAIN: u32 = 50_002;
/// The registry's Solana devnet domain.
pub const LOCAL_DOMAIN: u32 = 1_399_811_151;
const UPGRADEABLE_LOADER: Pubkey = anchor_lang::solana_program::bpf_loader_upgradeable::ID;

pub fn keccak(b: &[u8]) -> [u8; 32] {
    Keccak256::digest(b).into()
}

/// Name `authority` as a deployed program's upgrade authority. LiteSVM deploys through the
/// upgradeable loader with NO authority; ProgramData metadata is u32 tag 3, u64 slot, then
/// Option<Pubkey> (1-byte tag, 32 bytes).
pub fn set_upgrade_authority(svm: &mut LiteSVM, program: &Pubkey, authority: &Pubkey) {
    let pd = Pubkey::find_program_address(&[program.as_ref()], &UPGRADEABLE_LOADER).0;
    let mut acc = svm.get_account(&pd).unwrap();
    acc.data[12] = 1;
    acc.data[13..45].copy_from_slice(authority.as_ref());
    svm.set_account(pd, acc).unwrap();
}

pub fn program_data(program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[program.as_ref()], &UPGRADEABLE_LOADER).0
}

pub struct Validator {
    pub key: SigningKey,
    pub address: [u8; 20],
}

pub fn validator(seed: u8) -> Validator {
    let key = SigningKey::from_bytes(&[seed; 32].into()).unwrap();
    let point = key.verifying_key().to_encoded_point(false);
    let h = keccak(&point.as_bytes()[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&h[12..]);
    Validator { key, address }
}

pub struct MirrorFixture {
    pub svm: LiteSVM,
    pub payer: Keypair,
    pub authority: Keypair,
    pub validators: Vec<Validator>,
}

/// An Anchor error code for a `MirrorError` variant, as it appears in a failed transaction.
pub fn code(e: solidus_mirror::errors::MirrorError) -> u32 {
    anchor_lang::error::ERROR_CODE_OFFSET + e as u32
}

pub fn pda(seeds: &[&[u8]]) -> Pubkey {
    Pubkey::find_program_address(seeds, &solidus_mirror::ID).0
}

impl MirrorFixture {
    /// Deployed but NOT initialised, with `authority` as the program's upgrade authority.
    pub fn deployed() -> Self {
        let mut svm = LiteSVM::new();
        let bytes = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../target/deploy/solidus_mirror.so"));
        svm.add_program(solidus_mirror::ID, bytes).unwrap();
        let authority = Keypair::new();
        // LiteSVM deploys through the upgradeable loader with NO authority. Name one, so the
        // `initialize` restriction is exercised for real. ProgramData metadata: u32 tag 3, u64
        // slot, then Option<Pubkey> (1-byte tag, 32 bytes).
        let pd = Pubkey::find_program_address(&[solidus_mirror::ID.as_ref()], &UPGRADEABLE_LOADER).0;
        let mut acc = svm.get_account(&pd).unwrap();
        acc.data[12] = 1;
        acc.data[13..45].copy_from_slice(authority.pubkey().as_ref());
        svm.set_account(pd, acc).unwrap();
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
        svm.airdrop(&authority.pubkey(), 100_000_000_000).unwrap();
        let validators = (1..=4).map(validator).collect();
        Self { svm, payer, authority, validators }
    }

    pub fn new() -> Self {
        let mut f = Self::deployed();
        let addrs: Vec<[u8; 20]> = f.validators.iter().map(|v| v.address).collect();
        let signer = f.authority.insecure_clone();
        f.initialize(&signer, addrs, 3).expect("initialize");
        f
    }

    pub fn initialize(&mut self, signer: &Keypair, validators: Vec<[u8; 20]>, threshold: u8) -> Result<(), String> {
        let pd = Pubkey::find_program_address(&[solidus_mirror::ID.as_ref()], &UPGRADEABLE_LOADER).0;
        let ix = Instruction::new_with_bytes(
            solidus_mirror::ID,
            &solidus_mirror::instruction::Initialize {
                solidus_chain_id: SOLIDUS_CHAIN_ID,
                solidus_domain: SOLIDUS_DOMAIN,
                local_domain: LOCAL_DOMAIN,
                validators,
                threshold,
            }
            .data(),
            solidus_mirror::accounts::Initialize {
                authority: signer.pubkey(),
                config: pda(&[CONFIG_SEED]),
                program: solidus_mirror::ID,
                program_data: pd,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
        );
        self.send(ix, signer)
    }

    fn send(&mut self, ix: Instruction, signer: &Keypair) -> Result<(), String> {
        self.send_logs(ix, signer).map(|_| ())
    }

    fn send_logs(&mut self, ix: Instruction, signer: &Keypair) -> Result<Vec<String>, String> {
        self.svm.expire_blockhash();
        let msg = Message::new_with_blockhash(&[ix], Some(&signer.pubkey()), &self.svm.latest_blockhash());
        let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[signer]).unwrap();
        self.svm.send_transaction(tx).map(|m| m.logs).map_err(|e| format!("{:?}", e.err))
    }

    /// Deliver and return the transaction's log lines.
    pub fn deliver_logs(&mut self, message: &[u8]) -> Result<Vec<String>, String> {
        let sigs = self.sign(message, &[0, 1, 2]);
        let mut metas = solidus_mirror::accounts::Submit {
            payer: self.payer.pubkey(),
            config: pda(&[CONFIG_SEED]),
            system_program: system_program::ID,
        }
        .to_account_metas(None);
        metas.extend(Self::accounts_for(message));
        let ix = Instruction::new_with_bytes(
            solidus_mirror::ID,
            &solidus_mirror::instruction::Submit { message: message.to_vec(), signatures: sigs }.data(),
            metas,
        );
        let payer = self.payer.insecure_clone();
        self.send_logs(ix, &payer)
    }

    pub fn config(&self) -> MirrorConfig {
        let acc = self.svm.get_account(&pda(&[CONFIG_SEED])).unwrap();
        MirrorConfig::try_deserialize(&mut acc.data.as_slice()).unwrap()
    }

    pub fn account<T: AccountDeserialize>(&self, key: &Pubkey) -> Option<T> {
        let acc = self.svm.get_account(key)?;
        if acc.data.is_empty() {
            return None;
        }
        T::try_deserialize(&mut acc.data.as_slice()).ok()
    }

    /// Signatures over `message` for `local_domain` by the validators at `idx`, sorted ascending.
    pub fn sign_for(&self, message: &[u8], idx: &[usize], chain_id: u64, local_domain: u32) -> Vec<[u8; 65]> {
        let h = codec::decode(message).map(|m| *m.header()).unwrap_or(codec::Header {
            version: 1,
            kind: codec::MessageKind::Heartbeat,
            domain_seq: u64::from_be_bytes(message[2..10].try_into().unwrap()),
            solidus_height: u64::from_be_bytes(message[10..18].try_into().unwrap()),
        });
        let digest = codec::attestation_digest(chain_id, local_domain, h.domain_seq, &keccak(message), h.solidus_height);
        let signed = codec::eth_signed_message_hash(&digest);
        let mut out: Vec<([u8; 20], [u8; 65])> = idx
            .iter()
            .map(|&i| {
                let v = &self.validators[i];
                let (sig, rid) = v.key.sign_prehash_recoverable(&signed).unwrap();
                let mut b = [0u8; 65];
                b[..64].copy_from_slice(&sig.to_bytes());
                b[64] = rid.to_byte() + 27;
                (v.address, b)
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out.into_iter().map(|(_, s)| s).collect()
    }

    pub fn sign(&self, message: &[u8], idx: &[usize]) -> Vec<[u8; 65]> {
        self.sign_for(message, idx, SOLIDUS_CHAIN_ID, LOCAL_DOMAIN)
    }

    /// The PDAs a message needs, derived from its body exactly as a submitter would.
    pub fn accounts_for(message: &[u8]) -> Vec<AccountMeta> {
        match codec::decode(message) {
            Ok(codec::BridgeMessage::CredentialStatus { body, .. }) => {
                let gk = codec::gate_key(&body.holder, &body.credential_type_hash, &body.issuer_did_hash);
                vec![
                    AccountMeta::new(pda(&[EXPORT_SEED, &body.export_id]), false),
                    AccountMeta::new(pda(&[LATEST_SEED, &gk]), false),
                    AccountMeta::new(pda(&[ISSUER_SEED, &body.issuer_did_hash]), false),
                ]
            }
            Ok(codec::BridgeMessage::IssuerStatus { body, .. }) => {
                vec![AccountMeta::new(pda(&[ISSUER_SEED, &body.issuer_did_hash]), false)]
            }
            _ => vec![],
        }
    }

    pub fn submit_with(&mut self, message: &[u8], sigs: Vec<[u8; 65]>, accounts: Vec<AccountMeta>) -> Result<(), String> {
        let mut metas = solidus_mirror::accounts::Submit {
            payer: self.payer.pubkey(),
            config: pda(&[CONFIG_SEED]),
            system_program: system_program::ID,
        }
        .to_account_metas(None);
        metas.extend(accounts);
        let ix = Instruction::new_with_bytes(
            solidus_mirror::ID,
            &solidus_mirror::instruction::Submit { message: message.to_vec(), signatures: sigs }.data(),
            metas,
        );
        let payer = self.payer.insecure_clone();
        self.send(ix, &payer)
    }

    /// Sign with validators 0, 1 and 2 (three of four) and submit.
    pub fn deliver(&mut self, message: &[u8]) -> Result<(), String> {
        let sigs = self.sign(message, &[0, 1, 2]);
        let accounts = Self::accounts_for(message);
        self.submit_with(message, sigs, accounts)
    }
}

pub fn heartbeat(seq: u64, height: u64, ts: u64) -> Vec<u8> {
    codec::encode(&codec::BridgeMessage::heartbeat(seq, height, codec::HeartbeatBody { solidus_timestamp: ts, global_root: [7u8; 32] }))
}

pub fn credential_status(seq: u64, export_id: [u8; 32], status: codec::ExportStatus) -> Vec<u8> {
    codec::encode(&codec::BridgeMessage::credential_status(
        seq,
        100 + seq,
        codec::CredentialStatusBody {
            export_id,
            issuer_did_hash: [0x11; 32],
            credential_type_hash: [0x22; 32],
            holder: [0x33; 32],
            status,
            valid_until: 2_000_000_000,
            issuer_accredited: true,
        },
    ))
}

pub fn issuer_status(seq: u64, accredited: bool) -> Vec<u8> {
    codec::encode(&codec::BridgeMessage::issuer_status(seq, 100 + seq, codec::IssuerStatusBody { issuer_did_hash: [0x11; 32], accredited }))
}
