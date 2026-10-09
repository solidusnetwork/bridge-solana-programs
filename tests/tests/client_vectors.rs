//! Values the TypeScript gateway client pins in its own test, so the
//! hand-written Anchor encoding there cannot drift from the program.

use anchor_lang::{Discriminator, prelude::Pubkey};

#[test]
fn print_client_vectors() {
    let hexs = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    println!("SUBMIT_DISC={}", hexs(solidus_mirror::instruction::Submit::DISCRIMINATOR));
    println!("CONFIG_DISC={}", hexs(solidus_mirror::state::MirrorConfig::DISCRIMINATOR));
    println!("EV_CREDENTIAL={}", hexs(solidus_mirror::CredentialStatusApplied::DISCRIMINATOR));
    println!("EV_ISSUER={}", hexs(solidus_mirror::IssuerStatusApplied::DISCRIMINATOR));
    println!("EV_HEARTBEAT={}", hexs(solidus_mirror::HeartbeatApplied::DISCRIMINATOR));
    let export = Pubkey::find_program_address(&[b"export", &[0xe1u8; 32]], &solidus_mirror::ID).0;
    println!("EXPORT_PDA_E1={export}");
    let config = Pubkey::find_program_address(&[b"config"], &solidus_mirror::ID).0;
    println!("CONFIG_PDA={config}");
}
