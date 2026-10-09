//! The bytes a validator signs. `no_std`, so the phase 8 ZK guest links the same code.
//!
//! ⛔ FOUR IMPLEMENTATIONS RECOVER FROM THIS. Solidity `ecrecover` takes the eth-signed hash;
//! Anchor's `secp256k1_recover` takes the digest itself; the SDK checks both. None of them
//! re-derives the field order from prose — they are all tested against
//! `test-fixtures/bridge/attestation-v2.json`, which this crate generates.

use crate::keccak256;
use alloc::vec::Vec;

pub const ATTESTATION_DOMAIN: &[u8] = b"SOLIDUS_BRIDGE_ATTESTATION_V1";

/// domain ‖ chain_id ‖ destination domain ‖ domain_seq ‖ message_id ‖ solidus_height, all big-endian.
///
/// Every field is in the digest for a reason a reviewer should be able to state:
/// the chain id so a devnet signature is not a testnet one, the DESTINATION domain so a Sepolia
/// signature is not a Fuji one, the sequence so a signature cannot be replayed at another slot,
/// the message id so the body cannot be swapped, and the height so the claim is anchored.
pub fn attestation_preimage(
    chain_id: u64,
    domain: u32,
    domain_seq: u64,
    message_id: &[u8; 32],
    solidus_height: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(ATTESTATION_DOMAIN.len() + 8 + 4 + 8 + 32 + 8);
    out.extend_from_slice(ATTESTATION_DOMAIN);
    out.extend_from_slice(&chain_id.to_be_bytes());
    out.extend_from_slice(&domain.to_be_bytes());
    out.extend_from_slice(&domain_seq.to_be_bytes());
    out.extend_from_slice(message_id);
    out.extend_from_slice(&solidus_height.to_be_bytes());
    out
}

pub fn attestation_digest(
    chain_id: u64,
    domain: u32,
    domain_seq: u64,
    message_id: &[u8; 32],
    solidus_height: u64,
) -> [u8; 32] {
    keccak256(&attestation_preimage(
        chain_id,
        domain,
        domain_seq,
        message_id,
        solidus_height,
    ))
}

/// EIP-191 personal-sign framing, so `ecrecover` in Solidity takes the same hash.
pub fn eth_signed_message_hash(digest: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 28 + 32];
    buf[..28].copy_from_slice(b"\x19Ethereum Signed Message:\n32");
    buf[28..].copy_from_slice(digest);
    keccak256(&buf)
}

/// Inbound (phase 4): what the origin chain's signers attest about a message bound FOR Solidus.
///
/// ⛔ ITS OWN DOMAIN TAG. A validator key that signs outbound attestations may also sign inbound ones;
/// with a different leading tag, no outbound signature can ever verify as an inbound approval, and the
/// reverse. Fields: the Solidus NETWORK name, length-prefixed as bridge governance binds it (a devnet
/// approval is not a testnet one; the executor has the name, not the numeric chain id), the ORIGIN domain
/// (a Sepolia approval is not a Fuji one; the signer set is looked up by it), and the message id.
pub const INBOUND_DOMAIN: &[u8] = b"SOLIDUS_BRIDGE_INBOUND_V1";

pub fn inbound_preimage(network: &str, origin_domain: u32, message_id: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(INBOUND_DOMAIN.len() + 8 + network.len() + 4 + 32);
    out.extend_from_slice(INBOUND_DOMAIN);
    out.extend_from_slice(&(network.len() as u64).to_be_bytes());
    out.extend_from_slice(network.as_bytes());
    out.extend_from_slice(&origin_domain.to_be_bytes());
    out.extend_from_slice(message_id);
    out
}

/// The digest an inbound signer signs with EIP-191 framing (`eth_signed_message_hash`), as outbound.
pub fn inbound_digest(network: &str, origin_domain: u32, message_id: &[u8; 32]) -> [u8; 32] {
    keccak256(&inbound_preimage(network, origin_domain, message_id))
}

/// The TOKEN channel's attestation (phase 4): the outbound preimage's fields under its own tag, so a
/// signature over a credential-channel slot can never verify on the token channel, or the reverse.
pub const TOKEN_ATTESTATION_DOMAIN: &[u8] = b"SOLIDUS_BRIDGE_TOKEN_V1";

pub fn token_attestation_digest(
    chain_id: u64,
    domain: u32,
    token_seq: u64,
    message_id: &[u8; 32],
    solidus_height: u64,
) -> [u8; 32] {
    let mut out = Vec::with_capacity(TOKEN_ATTESTATION_DOMAIN.len() + 8 + 4 + 8 + 32 + 8);
    out.extend_from_slice(TOKEN_ATTESTATION_DOMAIN);
    out.extend_from_slice(&chain_id.to_be_bytes());
    out.extend_from_slice(&domain.to_be_bytes());
    out.extend_from_slice(&token_seq.to_be_bytes());
    out.extend_from_slice(message_id);
    out.extend_from_slice(&solidus_height.to_be_bytes());
    keccak256(&out)
}
