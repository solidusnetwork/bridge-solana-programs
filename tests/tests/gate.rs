//! The twin of SolidusGate.t.sol: every reason, in order, and the heartbeat arithmetic. Then the
//! same check end to end through `example_gated` on a real mirror, and a forged account.

mod common;

use anchor_lang::{
    prelude::Pubkey,
    solana_program::{instruction::Instruction, system_program},
    InstructionData, ToAccountMetas,
};
use common::*;
use solana_keypair::Keypair;
use solana_message::{Message, VersionedMessage};
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solidus_bridge_codec::{self as codec, ExportStatus};
use solidus_gate::{check_records, export_address, gate_addresses, GateReason as R};
use solidus_mirror::state::{ExportRecord, IssuerRecord, LatestExport};

const NOW: i64 = 1_800_000_000;
const DAY: u64 = 86_400;

fn export(status: ExportStatus, valid_until: u64) -> ExportRecord {
    ExportRecord {
        issuer_did_hash: [1; 32],
        credential_type_hash: [2; 32],
        holder: [3; 32],
        status: status as u8,
        valid_until,
        solidus_height: 1,
        bump: 0,
    }
}
fn latest() -> LatestExport {
    LatestExport { export_id: [9; 32], bump: 0 }
}
fn issuer(accredited: bool) -> IssuerRecord {
    IssuerRecord { accredited, bump: 0 }
}

#[test]
fn reasons_in_order() {
    let (l, ok_e, ok_i) = (latest(), export(ExportStatus::Active, 0), issuer(true));
    let hb = NOW as u64;
    assert_eq!(check_records(None, Some(&ok_e), Some(&ok_i), hb, DAY, NOW), R::NoExport);
    assert_eq!(check_records(Some(&l), None, Some(&ok_i), hb, DAY, NOW), R::NoExport);
    assert_eq!(check_records(Some(&l), Some(&export(ExportStatus::Revoked, 0)), Some(&ok_i), hb, DAY, NOW), R::NotActive);
    assert_eq!(check_records(Some(&l), Some(&ok_e), Some(&issuer(false)), hb, DAY, NOW), R::IssuerNotAccredited);
    assert_eq!(check_records(Some(&l), Some(&ok_e), None, hb, DAY, NOW), R::IssuerNotAccredited);
    assert_eq!(check_records(Some(&l), Some(&export(ExportStatus::Active, NOW as u64)), Some(&ok_i), hb, DAY, NOW), R::Expired);
    assert_eq!(check_records(Some(&l), Some(&ok_e), Some(&ok_i), hb, DAY, NOW), R::Ok);
}

#[test]
fn the_first_thing_wrong_is_the_thing_reported() {
    // Revoked AND issuer not accredited AND expired AND stale: NotActive wins.
    let r = check_records(Some(&latest()), Some(&export(ExportStatus::Revoked, 1)), Some(&issuer(false)), 0, DAY, NOW);
    assert_eq!(r, R::NotActive);
}

#[test]
fn staleness_including_a_mirror_that_never_saw_a_heartbeat() {
    let (l, e, i) = (latest(), export(ExportStatus::Active, 0), issuer(true));
    assert_eq!(check_records(Some(&l), Some(&e), Some(&i), 0, DAY, NOW), R::Stale);
    assert_eq!(check_records(Some(&l), Some(&e), Some(&i), NOW as u64 - DAY - 1, DAY, NOW), R::Stale);
    // CONTROL: exactly at the window edge is still fresh (strict `<`, as on EVM).
    assert_eq!(check_records(Some(&l), Some(&e), Some(&i), NOW as u64 - DAY, DAY, NOW), R::Ok);
}

#[test]
fn a_heartbeat_from_the_future_does_not_underflow() {
    let (l, e, i) = (latest(), export(ExportStatus::Active, 0), issuer(true));
    assert_eq!(check_records(Some(&l), Some(&e), Some(&i), NOW as u64 + 3_600, DAY, NOW), R::Ok);
    assert_eq!(check_records(Some(&l), Some(&e), Some(&i), u64::MAX, u64::MAX, NOW), R::Ok);
}

// ------------------------------------------------------------------ end to end

fn holder_status(seq: u64, holder: [u8; 32], status: ExportStatus) -> Vec<u8> {
    codec::encode(&codec::BridgeMessage::credential_status(
        seq,
        100 + seq,
        codec::CredentialStatusBody {
            export_id: [0xee; 32],
            issuer_did_hash: [0x11; 32],
            credential_type_hash: codec::credential_type_hash("KycL2"),
            holder,
            status,
            valid_until: 0,
            issuer_accredited: true,
        },
    ))
}

fn deposit(f: &mut MirrorFixture, who: &Keypair, issuer_override: Option<Pubkey>) -> Result<(), String> {
    let holder = who.pubkey().to_bytes();
    let (config, latest, issuer) = gate_addresses(&holder, &codec::credential_type_hash("KycL2"), &[0x11; 32]);
    let ix = Instruction::new_with_bytes(
        example_gated::ID,
        &example_gated::instruction::Deposit { amount: 1_000 }.data(),
        example_gated::accounts::Deposit {
            depositor: who.pubkey(),
            vault: Pubkey::find_program_address(&[b"vault"], &example_gated::ID).0,
            mirror_config: config,
            latest,
            export: export_address(&[0xee; 32]),
            issuer: issuer_override.unwrap_or(issuer),
            system_program: system_program::ID,
        }
        .to_account_metas(None),
    );
    f.svm.expire_blockhash();
    let msg = Message::new_with_blockhash(&[ix], Some(&who.pubkey()), &f.svm.latest_blockhash());
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[who]).unwrap();
    f.svm.send_transaction(tx).map(|_| ()).map_err(|e| format!("{:?} {:?}", e.err, e.meta.logs))
}

fn with_example() -> (MirrorFixture, Keypair) {
    let mut f = MirrorFixture::new();
    let bytes = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../target/deploy/example_gated.so"));
    f.svm.add_program(example_gated::ID, bytes).unwrap();
    let mut clock: anchor_lang::prelude::Clock = f.svm.get_sysvar();
    clock.unix_timestamp = NOW;
    f.svm.set_sysvar(&clock);
    let init = Instruction::new_with_bytes(
        example_gated::ID,
        &example_gated::instruction::Initialize { issuer_did_hash: [0x11; 32] }.data(),
        example_gated::accounts::Initialize {
            payer: f.payer.pubkey(),
            vault: Pubkey::find_program_address(&[b"vault"], &example_gated::ID).0,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
    );
    let payer = f.payer.insecure_clone();
    let msg = Message::new_with_blockhash(&[init], Some(&payer.pubkey()), &f.svm.latest_blockhash());
    f.svm.send_transaction(VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[&payer]).unwrap()).unwrap();
    let user = Keypair::new();
    f.svm.airdrop(&user.pubkey(), 10_000_000_000).unwrap();
    (f, user)
}

#[test]
fn deposit_is_refused_until_the_holder_is_credentialed_then_allowed() {
    let (mut f, user) = with_example();
    let refused = deposit(&mut f, &user, None).unwrap_err();
    assert!(refused.contains("CredentialRequired reason=1"), "no export yet: {refused}");

    f.deliver(&holder_status(1, user.pubkey().to_bytes(), ExportStatus::Active)).unwrap();
    let stale = deposit(&mut f, &user, None).unwrap_err();
    assert!(stale.contains("CredentialRequired reason=5"), "no heartbeat yet: {stale}");

    f.deliver(&heartbeat(2, 102, NOW as u64)).unwrap();
    deposit(&mut f, &user, None).expect("credentialed, fresh: the deposit passes");

    // Revocation reaches the gate.
    f.deliver(&holder_status(3, user.pubkey().to_bytes(), ExportStatus::Revoked)).unwrap();
    let revoked = deposit(&mut f, &user, None).unwrap_err();
    assert!(revoked.contains("CredentialRequired reason=2"), "revoked: {revoked}");
}

#[test]
fn another_holders_credential_does_not_open_the_gate() {
    let (mut f, user) = with_example();
    let other = Keypair::new();
    f.deliver(&holder_status(1, other.pubkey().to_bytes(), ExportStatus::Active)).unwrap();
    f.deliver(&heartbeat(2, 102, NOW as u64)).unwrap();
    let r = deposit(&mut f, &user, None).unwrap_err();
    assert!(r.contains("CredentialRequired reason=1"), "{r}");
}

#[test]
fn another_issuers_pda_in_the_issuer_slot_fails_closed() {
    let (mut f, user) = with_example();
    f.deliver(&holder_status(1, user.pubkey().to_bytes(), ExportStatus::Active)).unwrap();
    f.deliver(&heartbeat(2, 102, NOW as u64)).unwrap();
    // The vault's issuer (0x11) loses accreditation; an unrelated issuer (0x12) holds it.
    let issuer_msg = |seq: u64, h: [u8; 32], acc: bool| {
        codec::encode(&codec::BridgeMessage::issuer_status(seq, 100 + seq, codec::IssuerStatusBody { issuer_did_hash: h, accredited: acc }))
    };
    f.deliver(&issuer_msg(3, [0x11; 32], false)).unwrap();
    f.deliver(&issuer_msg(4, [0x12; 32], true)).unwrap();
    // ⛔ A genuine, accredited mirror PDA, but for the WRONG issuer. Only the address check stops it.
    let wrong = pda(&[solidus_mirror::ISSUER_SEED, &[0x12; 32]]);
    let r = deposit(&mut f, &user, Some(wrong)).unwrap_err();
    assert!(r.contains("CredentialRequired reason=3"), "{r}");
    // CONTROL: re-accredit the vault's issuer and the real PDA passes.
    f.deliver(&issuer_msg(5, [0x11; 32], true)).unwrap();
    deposit(&mut f, &user, None).unwrap();
}
