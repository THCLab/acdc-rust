//! Testator - a person who has made a will or given a legacy.

pub mod attestation;
pub mod datum;
pub mod error;
pub mod identifier;
pub mod signed_attestation;

use crate::error::Error;
use crate::signed_attestation::{KeyType, Proof, SignedAttestation};
use crate::{
    attestation::Attestation,
    attestation::{AttestationId, ObjectType},
    datum::Message,
    identifier::{Identifier, BasicIdentifier},
};
use std::str::FromStr;

#[test]
pub fn test_create_attestation() -> Result<(), Error> {
    let attestation_str = r#"{"i":"did:D5bw5KrpU2xRc3Oi4rsyBK9By6aotmXU0fNEybJbja1Q/attestationId/1234","s":["did:keri:DoQa-mkiBs5kDaSjbONUpryZKAJ4zGFn9EMHJPXykDA0/attestationId/sourceID"],"x":"123","d":{"message":"Witam"}}"#;
    let signature = r#"proof":{"signature":"byfYjUug5s0fgwhQuzX4C03G6BwWYi7BMrd-ZoJC8AAuDEYg8duM1iNFn6_ZaTwlAW1QrMWbpGO9_hBvSAF4DQ=="}}"#;
    let testator_id = Identifier::Basic(BasicIdentifier {
        id: "did:D5bw5KrpU2xRc3Oi4rsyBK9By6aotmXU0fNEybJbja1Q".into(),
    });
    let attestation_id = "did:D5bw5KrpU2xRc3Oi4rsyBK9By6aotmXU0fNEybJbja1Q/attestationId/1234".parse::<AttestationId>()?;
    let datum = Message {
        message: "Witam".into(),
    };
    let s_a: Attestation<ObjectType, Message, ObjectType> = Attestation::new(
        attestation_id,
        None,
        vec!["did:keri:DoQa-mkiBs5kDaSjbONUpryZKAJ4zGFn9EMHJPXykDA0/attestationId/sourceID".parse::<AttestationId>()?],
        ObjectType::SAI("123".to_string()),
        datum,
        None,
    );
    let j = serde_json::to_string(&s_a).unwrap();
    assert_eq!(attestation_str, j);
    Ok(())
}

#[test]
pub fn test_attestation_id_serialization() -> Result<(), Error> {
    let testator_id = Identifier::Basic(BasicIdentifier {
        id: "did:D5bw5KrpU2xRc3Oi4rsyBK9By6aotmXU0fNEybJbja1Q".into(),
    });
    let attestation_id = "did:D5bw5KrpU2xRc3Oi4rsyBK9By6aotmXU0fNEybJbja1Q/attestationId/123".parse::<AttestationId>()?;
    
    assert_eq!(
        attestation_id.testator_id,
        testator_id
    );
    assert_eq!(attestation_id.id, "did:D5bw5KrpU2xRc3Oi4rsyBK9By6aotmXU0fNEybJbja1Q/attestationId/123");

    assert_eq!(
        serde_json::to_string(&attestation_id).unwrap(),
        "\"did:D5bw5KrpU2xRc3Oi4rsyBK9By6aotmXU0fNEybJbja1Q/attestationId/123\""
    );

    Ok(())
}

#[test]
pub fn test_parse_signed_datum() -> Result<(), Error> {
    use crate::signed_attestation::SignedAttestation;
    let sd_str = r#"{"i":"did:DnhytOmpuUc1oD1jvZDBaRBZdSgsvq-rT3Hwvk_5Epko/attestationId/1234","s":["did:DoQa-mkiBs5kDaSjbONUpryZKAJ4zGFn9EMHJPXykDA0/attestationId/sourceID"],"x":"123","d":{"message":"Witam"}}--IYyv8y0FQpamU5IfB1KENJnsDRYg0g9YirrmD5BqszOFfI7YoMriW4ZZslOEJ3DTeq-SegKKQfsHOFoNZs7hBg=="#;
    let sd: SignedAttestation<String, Message, String> =
        sd_str.parse::<SignedAttestation<String, Message, String>>()?;
    assert_eq!(sd.to_string(), sd_str);

    Ok(())
}
fn create() {}

fn verify() {}
