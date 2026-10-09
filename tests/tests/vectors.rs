//! The shared vectors, read on the Solana side. The Solidity and TypeScript suites read the same
//! files; this is what keeps three implementations from drifting apart.

use solidus_bridge_codec as codec;

fn fixture(name: &str) -> serde_json::Value {
    let p = format!("{}/fixtures/bridge/{}", env!("CARGO_MANIFEST_DIR"), name);
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))).unwrap()
}

fn bytes(h: &str) -> Vec<u8> {
    let h = h.trim_start_matches("0x");
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn b32(h: &str) -> [u8; 32] {
    bytes(h).try_into().unwrap()
}

#[test]
fn every_message_vector_decodes_to_its_fields_and_reencodes_byte_for_byte() {
    let v = fixture("messages-v1.json");
    let cases = v["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for c in cases {
        let raw = bytes(c["hex"].as_str().unwrap());
        let msg = codec::decode(&raw).unwrap_or_else(|e| panic!("{}: {e:?}", c["fields"]));
        let f = &c["fields"];
        assert_eq!(msg.header().domain_seq.to_string(), f["domainSeq"].as_str().unwrap());
        assert_eq!(msg.header().solidus_height.to_string(), f["solidusHeight"].as_str().unwrap());
        if let codec::BridgeMessage::CredentialStatus { body, .. } = msg {
            assert_eq!(body.export_id, b32(f["exportId"].as_str().unwrap()));
            assert_eq!(body.holder, b32(f["holder"].as_str().unwrap()));
            assert_eq!(body.status as u64, f["status"].as_u64().unwrap());
        }
        assert_eq!(codec::encode(&msg), raw, "re-encoding must reproduce the vector exactly");
    }
}

#[test]
fn every_negative_vector_is_refused() {
    let v = fixture("messages-v1.json");
    let neg = v["negative"].as_array().unwrap();
    assert!(!neg.is_empty());
    for c in neg {
        assert!(codec::decode(&bytes(c["hex"].as_str().unwrap())).is_err(), "{} must not decode", c["name"]);
    }
}

#[test]
fn ids_match_the_vectors() {
    let v = fixture("ids-v1.json");
    for c in v["exportId"].as_array().unwrap() {
        let got = codec::export_id(c["credentialId"].as_str().unwrap(), c["domain"].as_u64().unwrap() as u32, &b32(c["holder"].as_str().unwrap()));
        assert_eq!(got, b32(c["expected"].as_str().unwrap()));
    }
    for c in v["gateKey"].as_array().unwrap() {
        let got = codec::gate_key(
            &b32(c["holder"].as_str().unwrap()),
            &b32(c["credentialTypeHash"].as_str().unwrap()),
            &b32(c["issuerDidHash"].as_str().unwrap()),
        );
        assert_eq!(got, b32(c["expected"].as_str().unwrap()));
    }
    for c in v["issuerDidHash"].as_array().unwrap() {
        assert_eq!(codec::issuer_did_hash(c["issuerDid"].as_str().unwrap()), b32(c["expected"].as_str().unwrap()));
    }
    for c in v["credentialTypeHash"].as_array().unwrap() {
        assert_eq!(codec::credential_type_hash(c["serdeName"].as_str().unwrap()), b32(c["expected"].as_str().unwrap()));
    }
}
