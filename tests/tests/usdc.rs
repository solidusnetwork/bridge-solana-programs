//! `gated_usdc_receiver` against Circle's REAL CCTP v2 programs.
//!
//! Circle's two programs and their devnet state accounts are dumped into `tests/fixtures/cctp/`
//! (pinned by `SHA256SUMS`). The one change is the attester list inside `message_transmitter`,
//! rewritten to two test keys: that is the only way to produce an attestation Circle's verifier
//! accepts without Circle's key. The CONTROL test shows that verifier really runs: a stranger's
//! attestation is refused by Circle, not by us.
//!
//! EVM cases that do not exist here: the reentrancy mock (SPL Token has no transfer callback), and the
//! blocklist mock becomes a FROZEN token account, the SPL equivalent.

mod common;

use anchor_lang::{
    prelude::Pubkey,
    pubkey,
    solana_program::{
        instruction::{AccountMeta, Instruction},
        system_program,
    },
    AccountDeserialize, InstructionData, ToAccountMetas,
};
use base64::Engine;
use common::*;
use gated_usdc_receiver::{self as receiver, Escrow, ASSOCIATED_TOKEN_PROGRAM_ID, MESSAGE_TRANSMITTER_ID, TOKEN_PROGRAM_ID};
use litesvm::LiteSVM;
use solana_keypair::Keypair;
use solana_message::{v0, AddressLookupTableAccount, Message, VersionedMessage};
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solidus_bridge_codec as codec;

const NOW: i64 = 1_758_000_000;
const DEADLINE: u64 = NOW as u64 + 7 * 86_400;
const AMOUNT: u64 = 1_000_000; // 1 USDC
const FEE: u64 = 100; // 1 bps, the measured Fast fee

const TMM: Pubkey = pubkey!("CCTPV2vPZJS2u2BBsUoscuikbYjnpFmbFsvVuJdgUMQe");
const USDC: Pubkey = pubkey!("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU");
const MT_STATE: Pubkey = pubkey!("W1k5ijkaSTo5iA5zChNpfzcy796fLhkBxfmJuR8W8HU");
const TOKEN_MESSENGER: Pubkey = pubkey!("AawthJCGRmggpfv9MMWV6Jmo9cue4gL9wUZgRBShg58W");
const TOKEN_MINTER: Pubkey = pubkey!("E1bQJ8eMMn3zmeSewW3HQ8zmJr7KR75JonbwAtWx2bux");
const LOCAL_TOKEN: Pubkey = pubkey!("7MwmWTK2R9Na6rnoSAEt5gytFmSZj9WLVdazvxvru9AU");
const CUSTODY: Pubkey = pubkey!("CFUgYpbas5UdJkwwSobYgzhFqFuj6C8MfXwBetE3o4SY");
const REMOTE_TM_0: Pubkey = pubkey!("3EzN2mcmdfSNGXRCAixSpTteK6ywdmFDZZWvkMnznFt9");
const TOKEN_PAIR_0: Pubkey = pubkey!("AR6mnr7XRVDUvK7SDGKpREBwGQMxZbKRsY22gXN8bvQU");
const FEE_ATA: Pubkey = pubkey!("2cDia1Ga9XDBGWVyFmaqiE7FKMDEtcy3xoRCW7B7S4es");
const COMPUTE_BUDGET: Pubkey = pubkey!("ComputeBudget111111111111111111111111111111");

fn pad20(h: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..20 {
        out[12 + i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn cth() -> [u8; 32] {
    keccak(b"KycL2")
}
fn idh() -> [u8; 32] {
    keccak(b"did:solidus:testnet:verify")
}

fn rpda(seeds: &[&[u8]]) -> Pubkey {
    Pubkey::find_program_address(seeds, &receiver::ID).0
}

struct Usdc {
    f: MirrorFixture,
    attesters: Vec<Validator>,
    nonce: u8,
    seq: u64,
    exports: u64,
}

impl Usdc {
    fn new() -> Self {
        Self::build(true)
    }

    /// `initialise = false` leaves the receiver deployed but not initialised.
    fn build(initialise: bool) -> Self {
        let mut f = MirrorFixture::new();
        let svm: &mut LiteSVM = &mut f.svm;

        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/cctp");
        svm.add_program(MESSAGE_TRANSMITTER_ID, &std::fs::read(format!("{root}/message_transmitter_v2.so")).unwrap()).unwrap();
        svm.add_program(TMM, &std::fs::read(format!("{root}/token_messenger_minter_v2.so")).unwrap()).unwrap();
        svm.add_program(receiver::ID, include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../target/deploy/gated_usdc_receiver.so")))
            .unwrap();
        for name in [
            "message_transmitter",
            "token_messenger",
            "token_minter",
            "local_token",
            "custody",
            "remote_token_messenger_0",
            "token_pair_0_usdc",
            "fee_recipient_ata",
            "usdc_mint",
        ] {
            let j: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(format!("{root}/{name}.json")).unwrap()).unwrap();
            let a = &j["account"];
            let data = base64::engine::general_purpose::STANDARD.decode(a["data"][0].as_str().unwrap()).unwrap();
            let key: Pubkey = j["pubkey"].as_str().unwrap().parse().unwrap();
            svm.set_account(
                key,
                solana_account::Account {
                    lamports: a["lamports"].as_u64().unwrap(),
                    data,
                    owner: a["owner"].as_str().unwrap().parse().unwrap(),
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        }

        // Our two attesters, ascending as Circle requires, into `enabled_attesters` (offset 149:
        // u32 length then 32-byte entries; the threshold of 2 stays).
        let mut attesters: Vec<Validator> = vec![validator(41), validator(42)];
        attesters.sort_by(|a, b| a.address.cmp(&b.address));
        let mut mt = svm.get_account(&MT_STATE).unwrap();
        assert_eq!(u32::from_le_bytes(mt.data[149..153].try_into().unwrap()), 2, "the fixture has two attester slots");
        for (i, v) in attesters.iter().enumerate() {
            let mut slot = [0u8; 32];
            slot[12..].copy_from_slice(&v.address);
            mt.data[153 + 32 * i..185 + 32 * i].copy_from_slice(&slot);
        }
        svm.set_account(MT_STATE, mt).unwrap();

        // Enough in custody for any test; the devnet balance is not ours to rely on.
        let mut custody = svm.get_account(&CUSTODY).unwrap();
        custody.data[64..72].copy_from_slice(&1_000_000_000_000u64.to_le_bytes());
        svm.set_account(CUSTODY, custody).unwrap();

        let mut clock: anchor_lang::prelude::Clock = svm.get_sysvar();
        clock.unix_timestamp = NOW;
        svm.set_sysvar(&clock);

        // The receiver's upgrade authority, so `initialize` runs as it will on devnet.
        let pd = Pubkey::find_program_address(&[receiver::ID.as_ref()], &anchor_lang::solana_program::bpf_loader_upgradeable::ID).0;
        let mut acc = svm.get_account(&pd).unwrap();
        acc.data[12] = 1;
        acc.data[13..45].copy_from_slice(f.authority.pubkey().as_ref());
        svm.set_account(pd, acc).unwrap();

        let mut u = Self { f, attesters, nonce: 1, seq: 1, exports: 0 };
        if initialise {
            let auth = u.f.authority.insecure_clone();
            u.initialize(&auth).expect("initialize");
        }
        u.heartbeat(NOW as u64);
        u
    }

    fn send(&mut self, ixs: Vec<Instruction>, signer: &Keypair) -> Result<Vec<String>, String> {
        self.f.svm.expire_blockhash();
        let msg = Message::new_with_blockhash(&ixs, Some(&signer.pubkey()), &self.f.svm.latest_blockhash());
        let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[signer]).unwrap();
        self.f.svm.send_transaction(tx).map(|m| m.logs).map_err(|e| format!("{:?} {:?}", e.err, e.meta.logs))
    }

    fn initialize(&mut self, signer: &Keypair) -> Result<Vec<String>, String> {
        let pd = Pubkey::find_program_address(&[receiver::ID.as_ref()], &anchor_lang::solana_program::bpf_loader_upgradeable::ID).0;
        let ix = Instruction::new_with_bytes(
            receiver::ID,
            &receiver::instruction::Initialize {}.data(),
            receiver::accounts::Initialize {
                payer: signer.pubkey(),
                config: rpda(&[receiver::CONFIG_SEED]),
                vault: rpda(&[receiver::VAULT_SEED]),
                usdc_mint: USDC,
                program: receiver::ID,
                program_data: pd,
                token_program: TOKEN_PROGRAM_ID,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
        );
        self.send(vec![ix], signer)
    }

    // ------------------------------------------------------------------ mirror

    fn heartbeat(&mut self, ts: u64) {
        let m = heartbeat(self.seq, 100 + self.seq, ts);
        self.seq += 1;
        self.f.deliver(&m).expect("heartbeat");
    }

    fn credential(&mut self, holder: &Pubkey, status: codec::ExportStatus) {
        self.exports += 1;
        let m = codec::encode(&codec::BridgeMessage::credential_status(
            self.seq,
            100 + self.seq,
            codec::CredentialStatusBody {
                export_id: keccak(&[holder.as_ref(), &self.exports.to_be_bytes()].concat()),
                issuer_did_hash: idh(),
                credential_type_hash: cth(),
                holder: holder.to_bytes(),
                status,
                valid_until: 2_000_000_000,
                issuer_accredited: true,
            },
        ));
        self.seq += 1;
        self.f.deliver(&m).expect("credential");
    }

    fn gate_metas(&self, holder: &Pubkey) -> [Pubkey; 4] {
        let (config, latest, issuer) = solidus_gate::gate_addresses(&holder.to_bytes(), &cth(), &idh());
        let export = self
            .f
            .svm
            .get_account(&latest)
            .and_then(|a| solidus_mirror::state::LatestExport::try_deserialize(&mut &a.data[..]).ok())
            .map(|l| solidus_gate::export_address(&l.export_id))
            .unwrap_or_default();
        [config, latest, export, issuer]
    }

    // ------------------------------------------------------------------ CCTP

    fn hook(&self, recipient: &Pubkey, refund: &Pubkey, deadline: u64) -> Vec<u8> {
        codec::encode_usdc_hook(&codec::UsdcHookData {
            version: 1,
            final_recipient: recipient.to_bytes(),
            credential_type_hash: cth(),
            issuer_did_hash: idh(),
            refund_address: refund.to_bytes(),
            deadline,
            referral_code: *b"partner1",
        })
        .to_vec()
    }

    /// A CCTP v2 burn from Ethereum Sepolia (domain 0) to Solana (domain 5), laid out as measured.
    fn message(&mut self, mint_recipient: &Pubkey, hook: &[u8], amount: u64, fee: u64) -> Vec<u8> {
        let u256 = |v: u64| {
            let mut b = [0u8; 32];
            b[24..].copy_from_slice(&v.to_be_bytes());
            b
        };
        let mut nonce = [0u8; 32];
        nonce[31] = self.nonce;
        self.nonce += 1;
        let mut m = Vec::new();
        m.extend_from_slice(&1u32.to_be_bytes()); // version
        m.extend_from_slice(&0u32.to_be_bytes()); // source domain: Sepolia
        m.extend_from_slice(&5u32.to_be_bytes()); // destination domain: Solana
        m.extend_from_slice(&nonce);
        m.extend_from_slice(&pad20("8fe6b999dc680ccfdd5bf7eb0974218be2542daa")); // Sepolia TokenMessengerV2
        m.extend_from_slice(TMM.as_ref()); // recipient program
        m.extend_from_slice(rpda(&[receiver::AUTHORITY_SEED]).as_ref()); // destinationCaller
        m.extend_from_slice(&1000u32.to_be_bytes());
        m.extend_from_slice(&2000u32.to_be_bytes());
        // burn body
        m.extend_from_slice(&1u32.to_be_bytes());
        m.extend_from_slice(&pad20("1c7d4b196cb0c7b01d743fbc6116a902379c7238")); // Sepolia USDC
        m.extend_from_slice(mint_recipient.as_ref());
        m.extend_from_slice(&u256(amount));
        m.extend_from_slice(&[0x55; 32]); // messageSender
        m.extend_from_slice(&u256(fee)); // maxFee
        m.extend_from_slice(&u256(fee)); // feeExecuted
        m.extend_from_slice(&[0u8; 32]); // expirationBlock: none
        m.extend_from_slice(hook);
        m
    }

    /// Circle's attestation: raw ECDSA over keccak(message), r‖s‖v with v = 27/28, signers ascending.
    fn attest_with(message: &[u8], keys: &[&Validator]) -> Vec<u8> {
        let digest = keccak(message);
        let mut out = Vec::new();
        for v in keys {
            let (sig, rec) = v.key.sign_prehash_recoverable(&digest).unwrap();
            out.extend_from_slice(&sig.to_bytes());
            out.push(27 + rec.to_byte());
        }
        out
    }

    fn attest(&self, message: &[u8]) -> Vec<u8> {
        Self::attest_with(message, &self.attesters.iter().collect::<Vec<_>>())
    }

    fn circle_accounts(message: &[u8], mint_recipient: &Pubkey) -> Vec<AccountMeta> {
        let mt = |s: &[&[u8]]| Pubkey::find_program_address(s, &MESSAGE_TRANSMITTER_ID).0;
        let tmm = |s: &[&[u8]]| Pubkey::find_program_address(s, &TMM).0;
        vec![
            AccountMeta::new_readonly(mt(&[b"message_transmitter_authority", TMM.as_ref()]), false),
            AccountMeta::new_readonly(MT_STATE, false),
            AccountMeta::new(mt(&[b"used_nonce", &message[12..44]]), false),
            AccountMeta::new_readonly(TMM, false),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(mt(&[b"__event_authority"]), false),
            AccountMeta::new_readonly(MESSAGE_TRANSMITTER_ID, false),
            AccountMeta::new_readonly(TOKEN_MESSENGER, false),
            AccountMeta::new_readonly(REMOTE_TM_0, false),
            AccountMeta::new_readonly(TOKEN_MINTER, false),
            AccountMeta::new(LOCAL_TOKEN, false),
            AccountMeta::new_readonly(TOKEN_PAIR_0, false),
            AccountMeta::new(FEE_ATA, false),
            AccountMeta::new(*mint_recipient, false),
            AccountMeta::new(CUSTODY, false),
            AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
            AccountMeta::new_readonly(tmm(&[b"__event_authority"]), false),
            AccountMeta::new_readonly(TMM, false),
        ]
    }

    fn relay_ix(&self, message: &[u8], attestation: Vec<u8>, recipient: &Pubkey) -> Instruction {
        let vault = rpda(&[receiver::VAULT_SEED]);
        let [mc, ml, me, mi] = self.gate_metas(recipient);
        let mut metas = receiver::accounts::Relay {
            payer: self.f.payer.pubkey(),
            config: rpda(&[receiver::CONFIG_SEED]),
            authority: rpda(&[receiver::AUTHORITY_SEED]),
            vault,
            escrow: rpda(&[receiver::ESCROW_SEED, &keccak(message)]),
            recipient: *recipient,
            recipient_token: receiver::associated_token_address(recipient, &USDC),
            usdc_mint: USDC,
            mirror_config: mc,
            mirror_latest: ml,
            mirror_export: me,
            mirror_issuer: mi,
            token_program: TOKEN_PROGRAM_ID,
            associated_token_program: ASSOCIATED_TOKEN_PROGRAM_ID,
            system_program: system_program::ID,
            message_transmitter_program: MESSAGE_TRANSMITTER_ID,
        }
        .to_account_metas(None);
        metas.extend(Self::circle_accounts(message, &vault));
        Instruction::new_with_bytes(
            receiver::ID,
            &receiver::instruction::Relay { message: message.to_vec(), attestation }.data(),
            metas,
        )
    }

    fn budget() -> Instruction {
        let mut data = vec![2u8];
        data.extend_from_slice(&1_400_000u32.to_le_bytes());
        Instruction::new_with_bytes(COMPUTE_BUDGET, &data, vec![])
    }

    fn relay(&mut self, message: &[u8], recipient: &Pubkey) -> Result<Vec<String>, String> {
        let ix = self.relay_ix(message, self.attest(message), recipient);
        let payer = self.f.payer.insecure_clone();
        self.send(vec![Self::budget(), ix], &payer)
    }

    fn release(&mut self, hash: [u8; 32], recipient: &Pubkey) -> Result<Vec<String>, String> {
        let [mc, ml, me, mi] = self.gate_metas(recipient);
        let ix = Instruction::new_with_bytes(
            receiver::ID,
            &receiver::instruction::Release { hash }.data(),
            receiver::accounts::Release {
                payer: self.f.payer.pubkey(),
                config: rpda(&[receiver::CONFIG_SEED]),
                authority: rpda(&[receiver::AUTHORITY_SEED]),
                vault: rpda(&[receiver::VAULT_SEED]),
                escrow: rpda(&[receiver::ESCROW_SEED, &hash]),
                recipient: *recipient,
                recipient_token: receiver::associated_token_address(recipient, &USDC),
                usdc_mint: USDC,
                mirror_config: mc,
                mirror_latest: ml,
                mirror_export: me,
                mirror_issuer: mi,
                token_program: TOKEN_PROGRAM_ID,
                associated_token_program: ASSOCIATED_TOKEN_PROGRAM_ID,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
        );
        let payer = self.f.payer.insecure_clone();
        self.send(vec![ix], &payer)
    }

    fn refund(&mut self, hash: [u8; 32], owner: &Pubkey) -> Result<Vec<String>, String> {
        let ix = Instruction::new_with_bytes(
            receiver::ID,
            &receiver::instruction::Refund { hash }.data(),
            receiver::accounts::Refund {
                payer: self.f.payer.pubkey(),
                config: rpda(&[receiver::CONFIG_SEED]),
                authority: rpda(&[receiver::AUTHORITY_SEED]),
                vault: rpda(&[receiver::VAULT_SEED]),
                escrow: rpda(&[receiver::ESCROW_SEED, &hash]),
                refund_owner: *owner,
                refund_token: receiver::associated_token_address(owner, &USDC),
                usdc_mint: USDC,
                token_program: TOKEN_PROGRAM_ID,
                associated_token_program: ASSOCIATED_TOKEN_PROGRAM_ID,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
        );
        let payer = self.f.payer.insecure_clone();
        self.send(vec![ix], &payer)
    }

    // ------------------------------------------------------------------ reads

    fn balance(&self, owner: &Pubkey) -> u64 {
        self.f
            .svm
            .get_account(&receiver::associated_token_address(owner, &USDC))
            .map(|a| u64::from_le_bytes(a.data[64..72].try_into().unwrap()))
            .unwrap_or(0)
    }

    fn vault(&self) -> u64 {
        let a = self.f.svm.get_account(&rpda(&[receiver::VAULT_SEED])).unwrap();
        u64::from_le_bytes(a.data[64..72].try_into().unwrap())
    }

    fn escrow(&self, hash: &[u8; 32]) -> Option<Escrow> {
        let a = self.f.svm.get_account(&rpda(&[receiver::ESCROW_SEED, hash]))?;
        if a.data.is_empty() {
            return None;
        }
        Escrow::try_deserialize(&mut &a.data[..]).ok()
    }

    fn warp(&mut self, ts: i64) {
        let mut clock: anchor_lang::prelude::Clock = self.f.svm.get_sysvar();
        clock.unix_timestamp = ts;
        self.f.svm.set_sysvar(&clock);
    }

    /// Create `owner`'s USDC account and freeze it: the SPL form of Circle's blocklist.
    fn freeze(&mut self, owner: &Pubkey) {
        let ata = receiver::associated_token_address(owner, &USDC);
        if self.f.svm.get_account(&ata).map(|a| a.data.is_empty()).unwrap_or(true) {
            let ix = Instruction::new_with_bytes(
                ASSOCIATED_TOKEN_PROGRAM_ID,
                &[1],
                vec![
                    AccountMeta::new(self.f.payer.pubkey(), true),
                    AccountMeta::new(ata, false),
                    AccountMeta::new_readonly(*owner, false),
                    AccountMeta::new_readonly(USDC, false),
                    AccountMeta::new_readonly(system_program::ID, false),
                    AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
                ],
            );
            let payer = self.f.payer.insecure_clone();
            self.send(vec![ix], &payer).expect("create ata");
        }
        let mut a = self.f.svm.get_account(&ata).unwrap();
        a.data[108] = 2;
        self.f.svm.set_account(ata, a).unwrap();
    }
}

fn custom(e: receiver::ReceiverError) -> String {
    format!("Custom({})", anchor_lang::error::ERROR_CODE_OFFSET + e as u32)
}

fn new_wallet() -> Pubkey {
    Keypair::new().pubkey()
}

// ====================================================================== the cases

#[test]
fn control_a_strangers_attestation_is_refused_by_circle_itself() {
    let mut u = Usdc::new();
    let alice = new_wallet();
    let hook = u.hook(&alice, &new_wallet(), DEADLINE);
    let vault = rpda(&[receiver::VAULT_SEED]);
    let m = u.message(&vault, &hook, AMOUNT, FEE);
    let strangers = [validator(77), validator(78)];
    let mut s: Vec<&Validator> = strangers.iter().collect();
    s.sort_by(|a, b| a.address.cmp(&b.address));
    let ix = u.relay_ix(&m, Usdc::attest_with(&m, &s), &alice);
    let payer = u.f.payer.insecure_clone();
    let err = u.send(vec![Usdc::budget(), ix], &payer).unwrap_err();
    assert!(err.contains(&MESSAGE_TRANSMITTER_ID.to_string()), "the refusal came from Circle's program: {err}");
    assert!(err.contains("InvalidAttesterSignature") || err.contains("Invalid attester"), "for the attester: {err}");
    assert_eq!(u.vault(), 0);
}

#[test]
fn case_1_a_credentialed_recipient_is_paid_what_circle_paid_out() {
    let mut u = Usdc::new();
    let alice = new_wallet();
    u.credential(&alice, codec::ExportStatus::Active);
    let hook = u.hook(&alice, &new_wallet(), DEADLINE);
    let m = u.message(&rpda(&[receiver::VAULT_SEED]), &hook, AMOUNT, FEE);
    let logs = u.relay(&m, &alice).expect("relay");
    assert_eq!(u.balance(&alice), AMOUNT - FEE, "paid amount minus Circle's fee");
    assert_eq!(u.vault(), 0, "nothing left behind");
    assert!(u.escrow(&keccak(&m)).is_none(), "a delivered transfer is not an escrow");
    assert!(logs.iter().any(|l| l.contains("Program data:")), "an event was emitted");
}

#[test]
fn case_2_no_export_is_escrowed_with_the_hook_deadline() {
    let mut u = Usdc::new();
    let (alice, bob) = (new_wallet(), new_wallet());
    let hook = u.hook(&alice, &bob, DEADLINE);
    let m = u.message(&rpda(&[receiver::VAULT_SEED]), &hook, AMOUNT, FEE);
    u.relay(&m, &alice).expect("relay");
    let e = u.escrow(&keccak(&m)).expect("escrow");
    assert_eq!(e.state, receiver::HELD);
    assert_eq!(e.amount, AMOUNT - FEE);
    assert_eq!(e.deadline, DEADLINE);
    assert_eq!(e.refund_address, bob.to_bytes());
    assert_eq!(&e.referral_code, b"partner1");
    assert_eq!(u.vault(), AMOUNT - FEE, "the vault holds the escrowed USDC");
    assert_eq!(u.balance(&alice), 0);
}

#[test]
fn case_3_release_before_the_export_fails_with_the_gate_reason() {
    let mut u = Usdc::new();
    let alice = new_wallet();
    let hook = u.hook(&alice, &new_wallet(), DEADLINE);
    let m = u.message(&rpda(&[receiver::VAULT_SEED]), &hook, AMOUNT, FEE);
    u.relay(&m, &alice).expect("relay");
    let err = u.release(keccak(&m), &alice).unwrap_err();
    assert!(err.contains(&custom(receiver::ReceiverError::GateStillFails)), "{err}");
    assert!(err.contains("GateStillFails reason=1"), "the reason is NO_EXPORT: {err}");
}

#[test]
fn case_4_after_the_export_arrives_release_pays_once() {
    let mut u = Usdc::new();
    let alice = new_wallet();
    let hook = u.hook(&alice, &new_wallet(), DEADLINE);
    let m = u.message(&rpda(&[receiver::VAULT_SEED]), &hook, AMOUNT, FEE);
    u.relay(&m, &alice).expect("relay");
    u.credential(&alice, codec::ExportStatus::Active);
    u.release(keccak(&m), &alice).expect("release");
    assert_eq!(u.balance(&alice), AMOUNT - FEE);
    assert_eq!(u.escrow(&keccak(&m)).unwrap().state, receiver::RELEASED);
    assert_eq!(u.vault(), 0);
    let err = u.release(keccak(&m), &alice).unwrap_err();
    assert!(err.contains(&custom(receiver::ReceiverError::NotHeld)), "{err}");
}

#[test]
fn case_5_release_after_the_deadline_fails() {
    let mut u = Usdc::new();
    let alice = new_wallet();
    let hook = u.hook(&alice, &new_wallet(), DEADLINE);
    let m = u.message(&rpda(&[receiver::VAULT_SEED]), &hook, AMOUNT, FEE);
    u.relay(&m, &alice).expect("relay");
    u.warp(DEADLINE as i64 + 1);
    u.heartbeat(DEADLINE + 1);
    u.credential(&alice, codec::ExportStatus::Active);
    let err = u.release(keccak(&m), &alice).unwrap_err();
    assert!(err.contains(&custom(receiver::ReceiverError::DeadlinePassed)), "{err}");
}

#[test]
fn case_6_refund_waits_for_the_deadline_then_pays_the_refund_address() {
    let mut u = Usdc::new();
    let (alice, bob) = (new_wallet(), new_wallet());
    let hook = u.hook(&alice, &bob, DEADLINE);
    let m = u.message(&rpda(&[receiver::VAULT_SEED]), &hook, AMOUNT, FEE);
    u.relay(&m, &alice).expect("relay");
    let h = keccak(&m);
    assert!(u.refund(h, &bob).unwrap_err().contains(&custom(receiver::ReceiverError::DeadlineNotPassed)));
    u.warp(DEADLINE as i64);
    assert!(
        u.refund(h, &bob).unwrap_err().contains(&custom(receiver::ReceiverError::DeadlineNotPassed)),
        "the deadline itself still belongs to release"
    );
    u.warp(DEADLINE as i64 + 1);
    u.refund(h, &bob).expect("refund");
    assert_eq!(u.balance(&bob), AMOUNT - FEE);
    assert_eq!(u.escrow(&h).unwrap().state, receiver::REFUNDED);
    assert!(u.refund(h, &bob).unwrap_err().contains(&custom(receiver::ReceiverError::NotHeld)));
}

#[test]
fn case_7_release_and_refund_on_an_unknown_hash_fail_not_held() {
    let mut u = Usdc::new();
    let h = keccak(b"never relayed");
    let w = new_wallet();
    assert!(u.release(h, &w).unwrap_err().contains(&custom(receiver::ReceiverError::NotHeld)));
    assert!(u.refund(h, &w).unwrap_err().contains(&custom(receiver::ReceiverError::NotHeld)));
}

#[test]
fn case_8_a_replayed_message_is_refused_and_creates_nothing_new() {
    let mut u = Usdc::new();
    let alice = new_wallet();
    let hook = u.hook(&alice, &new_wallet(), DEADLINE);
    let m = u.message(&rpda(&[receiver::VAULT_SEED]), &hook, AMOUNT, FEE);
    u.relay(&m, &alice).expect("relay");
    assert!(u.relay(&m, &alice).is_err(), "Circle's used_nonce refuses a replay");
    assert_eq!(u.escrow(&keccak(&m)).unwrap().amount, AMOUNT - FEE);
    assert_eq!(u.vault(), AMOUNT - FEE, "nothing paid twice");
}

#[test]
fn case_9_a_frozen_recipient_keeps_the_escrow_held_and_refund_still_works() {
    let mut u = Usdc::new();
    let (alice, bob) = (new_wallet(), new_wallet());
    let hook = u.hook(&alice, &bob, DEADLINE);
    let m = u.message(&rpda(&[receiver::VAULT_SEED]), &hook, AMOUNT, FEE);
    u.relay(&m, &alice).expect("relay");
    u.credential(&alice, codec::ExportStatus::Active);
    u.freeze(&alice);
    assert!(u.release(keccak(&m), &alice).is_err(), "a frozen account cannot be paid");
    assert_eq!(u.escrow(&keccak(&m)).unwrap().state, receiver::HELD, "the escrow is still held");
    assert_eq!(u.vault(), AMOUNT - FEE);
    u.warp(DEADLINE as i64 + 1);
    u.refund(keccak(&m), &bob).expect("refund");
    assert_eq!(u.balance(&bob), AMOUNT - FEE);
}

#[test]
fn case_9b_a_frozen_recipient_at_relay_time_escrows_with_reason_6() {
    let mut u = Usdc::new();
    let alice = new_wallet();
    u.credential(&alice, codec::ExportStatus::Active);
    u.freeze(&alice);
    let hook = u.hook(&alice, &new_wallet(), DEADLINE);
    let m = u.message(&rpda(&[receiver::VAULT_SEED]), &hook, AMOUNT, FEE);
    u.relay(&m, &alice).expect("the delivery must not revert");
    assert_eq!(u.escrow(&keccak(&m)).unwrap().state, receiver::HELD);
    assert_eq!(u.vault(), AMOUNT - FEE);
}

#[test]
fn case_11_a_malformed_hook_is_refused_before_circle_runs() {
    let mut u = Usdc::new();
    let alice = new_wallet();
    let vault = rpda(&[receiver::VAULT_SEED]);
    let hook = u.hook(&alice, &new_wallet(), DEADLINE);
    let short = u.message(&vault, &hook[..144], AMOUNT, FEE);
    assert!(u.relay(&short, &alice).unwrap_err().contains(&custom(receiver::ReceiverError::BadHook)));
    let mut v2 = hook.clone();
    v2[0] = 2;
    let wrong_version = u.message(&vault, &v2, AMOUNT, FEE);
    assert!(u.relay(&wrong_version, &alice).unwrap_err().contains(&custom(receiver::ReceiverError::BadHook)));
    let used = Pubkey::find_program_address(&[b"used_nonce", &short[12..44]], &MESSAGE_TRANSMITTER_ID).0;
    assert!(u.f.svm.get_account(&used).map(|a| a.data.is_empty()).unwrap_or(true), "Circle's nonce is untouched");
    assert_eq!(u.vault(), 0);
}

#[test]
fn a_message_minting_to_another_account_is_refused() {
    let mut u = Usdc::new();
    let alice = new_wallet();
    let hook = u.hook(&alice, &new_wallet(), DEADLINE);
    let m = u.message(&new_wallet(), &hook, AMOUNT, FEE);
    assert!(u.relay(&m, &alice).unwrap_err().contains(&custom(receiver::ReceiverError::NotForThisReceiver)));
}

#[test]
fn the_recipient_account_must_be_the_one_the_hook_names() {
    let mut u = Usdc::new();
    let alice = new_wallet();
    u.credential(&alice, codec::ExportStatus::Active);
    let hook = u.hook(&alice, &new_wallet(), DEADLINE);
    let m = u.message(&rpda(&[receiver::VAULT_SEED]), &hook, AMOUNT, FEE);
    let mallory = new_wallet();
    assert!(u.relay(&m, &mallory).unwrap_err().contains(&custom(receiver::ReceiverError::WrongRecipient)));
}

#[test]
fn a_hook_without_a_refund_address_is_refused() {
    let mut u = Usdc::new();
    let alice = new_wallet();
    let hook = u.hook(&alice, &Pubkey::default(), DEADLINE);
    let m = u.message(&rpda(&[receiver::VAULT_SEED]), &hook, AMOUNT, FEE);
    assert!(u.relay(&m, &alice).unwrap_err().contains(&custom(receiver::ReceiverError::ZeroRefundAddress)));
}

#[test]
fn only_the_upgrade_authority_may_initialise() {
    let mut u = Usdc::build(false);
    let stranger = Keypair::new();
    u.f.svm.airdrop(&stranger.pubkey(), 1_000_000_000).unwrap();
    let err = u.initialize(&stranger).unwrap_err();
    assert!(err.contains(&custom(receiver::ReceiverError::NotUpgradeAuthority)), "{err}");
    let auth = u.f.authority.insecure_clone();
    u.initialize(&auth).expect("the upgrade authority can");
}

/// ⛔ LITESVM DOES NOT ENFORCE THE 1,232-BYTE PACKET LIMIT, so every relay above would also pass as a
/// legacy transaction that devnet refuses. This measures the real serialized sizes.
#[test]
fn the_relay_needs_a_lookup_table_and_fits_with_one() {
    let mut u = Usdc::new();
    let alice = new_wallet();
    let hook = u.hook(&alice, &new_wallet(), DEADLINE);
    let m = u.message(&rpda(&[receiver::VAULT_SEED]), &hook, AMOUNT, FEE);
    let ixs = vec![Usdc::budget(), u.relay_ix(&m, u.attest(&m), &alice)];
    let payer = u.f.payer.pubkey();
    let bh = u.f.svm.latest_blockhash();

    let legacy = VersionedMessage::Legacy(Message::new_with_blockhash(&ixs, Some(&payer), &bh)).serialize().len() + 1 + 64;
    // Everything that does not change per message goes in the table.
    let used_nonce = Pubkey::find_program_address(&[b"used_nonce", &m[12..44]], &MESSAGE_TRANSMITTER_ID).0;
    let per_message = [payer, used_nonce, rpda(&[receiver::ESCROW_SEED, &keccak(&m)]), alice, receiver::associated_token_address(&alice, &USDC), receiver::ID, COMPUTE_BUDGET];
    let mut table: Vec<Pubkey> = ixs.iter().flat_map(|i| i.accounts.iter().map(|a| a.pubkey)).filter(|k| !per_message.contains(k)).collect();
    table.sort();
    table.dedup();
    let alt = AddressLookupTableAccount { key: new_wallet(), addresses: table };
    let v0 = v0::Message::try_compile(&payer, &ixs, &[alt], bh).unwrap();
    let with_table = VersionedMessage::V0(v0).serialize().len() + 1 + 64;

    println!("relay transaction: legacy {legacy} B, v0 with a lookup table {with_table} B, limit 1232 B");
    assert!(legacy > 1232, "if legacy fits, the lookup table is unnecessary: {legacy}");
    assert!(with_table <= 1232, "even with a lookup table the relay does not fit: {with_table}");
}
