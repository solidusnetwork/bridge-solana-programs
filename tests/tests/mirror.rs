//! The Solana mirror must behave exactly like the EVM mirror. Every test here has a twin in
//! bridge/contracts/evm/test/SolidusCredentialMirror.t.sol, plus the Solana-only cases: who may
//! initialise, accounts that do not match the message, and a pre-funded PDA address.

mod common;

use common::*;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solidus_bridge_codec::{self as codec, ExportStatus};
use solidus_mirror::{errors::MirrorError as E, state::*, CONFIG_SEED, EXPORT_SEED, ISSUER_SEED, LATEST_SEED};

fn fails_with(r: Result<(), String>, e: E) {
    let want = format!("Custom({})", code(e));
    match r {
        Ok(()) => panic!("expected {:?}, the transaction succeeded", e as u32),
        Err(s) => assert!(s.contains(&want), "expected {want}, got {s}"),
    }
}

#[test]
fn initial_state() {
    let f = MirrorFixture::new();
    let c = f.config();
    assert_eq!(c.solidus_chain_id, SOLIDUS_CHAIN_ID);
    assert_eq!(c.solidus_domain, SOLIDUS_DOMAIN);
    assert_eq!(c.local_domain, LOCAL_DOMAIN);
    assert_eq!(c.next_domain_seq, 1);
    assert_eq!(c.threshold, 3);
    assert_eq!(c.validators, f.validators.iter().map(|v| v.address).collect::<Vec<_>>());
}

#[test]
fn only_the_upgrade_authority_may_initialise() {
    let mut f = MirrorFixture::deployed();
    let stranger = Keypair::new();
    f.svm.airdrop(&stranger.pubkey(), 10_000_000_000).unwrap();
    let addrs: Vec<[u8; 20]> = f.validators.iter().map(|v| v.address).collect();
    fails_with(f.initialize(&stranger, addrs.clone(), 3), E::NotUpgradeAuthority);
    // CONTROL: the authority succeeds through the identical path.
    let auth = f.authority.insecure_clone();
    f.initialize(&auth, addrs, 3).unwrap();
}

#[test]
fn initialise_refuses_a_bad_validator_set() {
    let auth = |f: &MirrorFixture| f.authority.insecure_clone();
    let mut f = MirrorFixture::deployed();
    let a = f.validators[0].address;
    let b = f.validators[1].address;
    let s = auth(&f);
    fails_with(f.initialize(&s, vec![a, b], 3), E::BadThreshold);
    fails_with(f.initialize(&s, vec![a, b], 0), E::BadThreshold);
    fails_with(f.initialize(&s, vec![a, a], 1), E::DuplicateValidator);
    fails_with(f.initialize(&s, vec![a, [0u8; 20]], 1), E::ZeroValidator);
}

#[test]
fn anyone_may_submit_but_only_with_enough_valid_signatures() {
    let mut f = MirrorFixture::new();
    let m = heartbeat(1, 10, 1_000);
    let two = f.sign(&m, &[0, 1]);
    fails_with(f.submit_with(&m, two, vec![]), E::NotEnoughSignatures);
    assert_eq!(f.config().next_domain_seq, 1, "a refused message consumes no sequence number");
    // An arbitrary payer (the fixture's, unrelated to any validator) succeeds with three.
    f.deliver(&m).unwrap();
    assert_eq!(f.config().next_domain_seq, 2);
}

#[test]
fn all_four_signatures_are_accepted_too() {
    let mut f = MirrorFixture::new();
    let m = heartbeat(1, 10, 1_000);
    let four = f.sign(&m, &[0, 1, 2, 3]);
    f.submit_with(&m, four, vec![]).unwrap();
}

#[test]
fn the_digest_binds_the_chain_and_this_destination() {
    let mut f = MirrorFixture::new();
    let m = heartbeat(1, 10, 1_000);
    // Signed for another destination domain: recovers to addresses nobody configured.
    let other_domain = f.sign_for(&m, &[0, 1, 2], SOLIDUS_CHAIN_ID, 11_155_111);
    fails_with(f.submit_with(&m, other_domain, vec![]), E::UnknownSigner);
    // Signed for another Solidus chain id: the same.
    let other_chain = f.sign_for(&m, &[0, 1, 2], 1, LOCAL_DOMAIN);
    fails_with(f.submit_with(&m, other_chain, vec![]), E::UnknownSigner);
}

#[test]
fn a_stranger_signature_is_refused() {
    let mut f = MirrorFixture::new();
    let m = heartbeat(1, 10, 1_000);
    let stranger = validator(9);
    // Replace validator 2 with a stranger who signs correctly.
    f.validators[2] = stranger;
    let sigs = f.sign(&m, &[0, 1, 2]);
    fails_with(f.submit_with(&m, sigs, vec![]), E::UnknownSigner);
}

#[test]
fn sequence_is_strict_in_both_directions() {
    let mut f = MirrorFixture::new();
    let m1 = heartbeat(1, 10, 1_000);
    let m2 = heartbeat(2, 11, 1_001);
    fails_with(f.deliver(&m2), E::OutOfSequence);
    f.deliver(&m1).unwrap();
    f.deliver(&m2).unwrap();
    // A replay of 1, correctly signed, is refused.
    fails_with(f.deliver(&m1), E::OutOfSequence);
    assert_eq!(f.config().next_domain_seq, 3);
}

#[test]
fn a_malformed_message_does_not_consume_a_sequence_number() {
    let mut f = MirrorFixture::new();
    let mut m = heartbeat(1, 10, 1_000);
    m.pop(); // 57 bytes: a heartbeat must be 58
    let sigs = f.sign(&m, &[0, 1, 2]);
    fails_with(f.submit_with(&m, sigs, vec![]), E::CodecError);
    assert_eq!(f.config().next_domain_seq, 1);
}

#[test]
fn a_duplicate_signer_and_a_descending_pair_are_refused() {
    let mut f = MirrorFixture::new();
    let m = heartbeat(1, 10, 1_000);
    let mut sigs = f.sign(&m, &[0, 1, 2]);
    // Duplicate: one validator's signature counted twice.
    let dup = vec![sigs[0], sigs[0], sigs[1]];
    fails_with(f.submit_with(&m, dup, vec![]), E::SignersOutOfOrder);
    // Descending: the right three, wrong order.
    sigs.reverse();
    fails_with(f.submit_with(&m, sigs, vec![]), E::SignersOutOfOrder);
}

#[test]
fn a_high_s_signature_is_refused() {
    let mut f = MirrorFixture::new();
    let m = heartbeat(1, 10, 1_000);
    let mut sigs = f.sign(&m, &[0, 1, 2]);
    // s' = n - s with v flipped is the same signature in the upper half (EIP-2).
    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
    ];
    let s = &sigs[0][32..64];
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = N[i] as i16 - s[i] as i16 - borrow;
        borrow = if d < 0 { 1 } else { 0 };
        out[i] = (d + if d < 0 { 256 } else { 0 }) as u8;
    }
    sigs[0][32..64].copy_from_slice(&out);
    sigs[0][64] ^= 1; // 27 <-> 28
    fails_with(f.submit_with(&m, sigs, vec![]), E::HighS);
}

#[test]
fn credential_status_is_stored_and_indexed_by_gate_key() {
    let mut f = MirrorFixture::new();
    let id = [0xe1; 32];
    f.deliver(&credential_status(1, id, ExportStatus::Active)).unwrap();
    let rec: ExportRecord = f.account(&pda(&[EXPORT_SEED, &id])).expect("export record");
    assert_eq!(rec.status, ExportStatus::Active as u8);
    assert_eq!(rec.holder, [0x33; 32]);
    assert_eq!(rec.valid_until, 2_000_000_000);
    assert_eq!(rec.solidus_height, 101);
    let gk = codec::gate_key(&[0x33; 32], &[0x22; 32], &[0x11; 32]);
    let latest: LatestExport = f.account(&pda(&[LATEST_SEED, &gk])).expect("latest pointer");
    assert_eq!(latest.export_id, id);
    let issuer: IssuerRecord = f.account(&pda(&[ISSUER_SEED, &[0x11; 32]])).expect("issuer record");
    assert!(issuer.accredited);
}

#[test]
fn latest_export_follows_active_only() {
    let mut f = MirrorFixture::new();
    let old = [0x0a; 32];
    let new = [0x0b; 32];
    f.deliver(&credential_status(1, old, ExportStatus::Active)).unwrap();
    f.deliver(&credential_status(2, new, ExportStatus::Active)).unwrap();
    // Revoking the OLDER export must not hide the newer active one.
    f.deliver(&credential_status(3, old, ExportStatus::Revoked)).unwrap();
    let gk = codec::gate_key(&[0x33; 32], &[0x22; 32], &[0x11; 32]);
    let latest: LatestExport = f.account(&pda(&[LATEST_SEED, &gk])).unwrap();
    assert_eq!(latest.export_id, new);
    let rec: ExportRecord = f.account(&pda(&[EXPORT_SEED, &old])).unwrap();
    assert_eq!(rec.status, ExportStatus::Revoked as u8);
}

#[test]
fn issuer_status_is_recorded() {
    let mut f = MirrorFixture::new();
    f.deliver(&issuer_status(1, true)).unwrap();
    f.deliver(&issuer_status(2, false)).unwrap();
    let issuer: IssuerRecord = f.account(&pda(&[ISSUER_SEED, &[0x11; 32]])).unwrap();
    assert!(!issuer.accredited);
}

#[test]
fn heartbeat_is_recorded() {
    let mut f = MirrorFixture::new();
    f.deliver(&heartbeat(1, 42, 1_700_000_000)).unwrap();
    let c = f.config();
    assert_eq!(c.heartbeat_ts, 1_700_000_000);
    assert_eq!(c.heartbeat_height, 42);
    assert_eq!(c.global_root, [7u8; 32]);
}

#[test]
fn accounts_that_do_not_match_the_message_are_refused() {
    let mut f = MirrorFixture::new();
    let m = credential_status(1, [0xe1; 32], ExportStatus::Active);
    let sigs = f.sign(&m, &[0, 1, 2]);
    let mut accounts = MirrorFixture::accounts_for(&m);
    // Point the export write at another export's PDA.
    accounts[0] = anchor_lang::solana_program::instruction::AccountMeta::new(pda(&[EXPORT_SEED, &[0xff; 32]]), false);
    fails_with(f.submit_with(&m, sigs.clone(), accounts), E::WrongAccount);
    fails_with(f.submit_with(&m, sigs, vec![]), E::MissingAccount);
    assert_eq!(f.config().next_domain_seq, 1);
}

#[test]
fn a_pre_funded_pda_address_cannot_block_an_export() {
    let mut f = MirrorFixture::new();
    let id = [0xe1; 32];
    // A griefer sends dust to the export PDA's address before it exists.
    f.svm.airdrop(&pda(&[EXPORT_SEED, &id]), 1_000).unwrap();
    f.deliver(&credential_status(1, id, ExportStatus::Active)).unwrap();
    let rec: ExportRecord = f.account(&pda(&[EXPORT_SEED, &id])).expect("export record despite dust");
    assert_eq!(rec.status, ExportStatus::Active as u8);
    let _ = CONFIG_SEED;
}

/// The gateway's `/applied` feed reads these; they must carry the sequence, as on EVM.
#[test]
fn every_applied_message_emits_its_event_with_the_sequence() {
    use anchor_lang::{AnchorDeserialize, Discriminator};
    let mut f = MirrorFixture::new();
    let decode = |logs: &[String]| -> Vec<Vec<u8>> {
        logs.iter()
            .filter_map(|l| l.strip_prefix("Program data: "))
            .map(|b| anchor_lang::__private::base64::decode(b).unwrap())
            .collect()
    };
    let hb = decode(&f.deliver_logs(&heartbeat(1, 42, 1_700_000_000)).unwrap());
    assert_eq!(hb.len(), 1);
    assert_eq!(&hb[0][..8], solidus_mirror::HeartbeatApplied::DISCRIMINATOR);
    let e = solidus_mirror::HeartbeatApplied::deserialize(&mut &hb[0][8..]).unwrap();
    assert_eq!((e.domain_seq, e.solidus_height, e.solidus_timestamp), (1, 42, 1_700_000_000));

    let cs = decode(&f.deliver_logs(&credential_status(2, [0xe1; 32], ExportStatus::Active)).unwrap());
    assert_eq!(&cs[0][..8], solidus_mirror::CredentialStatusApplied::DISCRIMINATOR);
    let e = solidus_mirror::CredentialStatusApplied::deserialize(&mut &cs[0][8..]).unwrap();
    assert_eq!((e.domain_seq, e.export_id, e.status), (2, [0xe1; 32], ExportStatus::Active as u8));

    let is = decode(&f.deliver_logs(&issuer_status(3, false)).unwrap());
    assert_eq!(&is[0][..8], solidus_mirror::IssuerStatusApplied::DISCRIMINATOR);
    let e = solidus_mirror::IssuerStatusApplied::deserialize(&mut &is[0][8..]).unwrap();
    assert_eq!((e.domain_seq, e.accredited), (3, false));
}
