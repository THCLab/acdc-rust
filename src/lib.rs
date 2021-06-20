//! Testator - a person who has made a will or given a legacy.

pub mod attestation;
pub mod datum;
pub mod error;
pub mod identifier;
pub mod signed_attestation;
pub mod source;

use crate::error::Error;
use crate::source::{ExternalSource, Source};
use crate::{
    attestation::Attestation,
    attestation::{AttestationId, ObjectType},
    datum::Message,
    identifier::{BasicIdentifier, Identifier},
};
use std::str::FromStr;

#[test]
pub fn test_create_attestation() -> Result<(), Error> {
    let attestation_str = r#"{"i":"did:D5bw5KrpU2xRc3Oi4rsyBK9By6aotmXU0fNEybJbja1Q/attestationId/1234","s":["did:keri:DoQa-mkiBs5kDaSjbONUpryZKAJ4zGFn9EMHJPXykDA0/attestationId/sourceID"],"x":"123","d":{"message":"Witam"}}"#;
    let signature = r#"proof":{"signature":"byfYjUug5s0fgwhQuzX4C03G6BwWYi7BMrd-ZoJC8AAuDEYg8duM1iNFn6_ZaTwlAW1QrMWbpGO9_hBvSAF4DQ=="}}"#;
    let testator_id = Identifier::Basic(BasicIdentifier {
        id: "did:D5bw5KrpU2xRc3Oi4rsyBK9By6aotmXU0fNEybJbja1Q".into(),
    });
    let attestation_id = AttestationId::new(testator_id, "attestationId/1234");
    let datum = Message {
        message: "Witam".into(),
    };
    let s_a: Attestation<ObjectType, Message, ObjectType> = Attestation::new(
        attestation_id,
        None,
        vec![AttestationId::new(
            Identifier::Basic(BasicIdentifier {
                id: "did:keri:DoQa-mkiBs5kDaSjbONUpryZKAJ4zGFn9EMHJPXykDA0".to_string(),
            }),
            "attestationId/sourceID",
        )],
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
    let msg_str = "hi there";
    let datum = Message {
        message: msg_str.into(),
    };
    let ad = Attestation::new(
        AttestationId::new(testator_id, "attestationId/123"),
        Some(Identifier::Basic(BasicIdentifier { id: "123".into() })),
        vec![],
        ObjectType::SAI("123".to_string()),
        datum,
        Some(ObjectType::SAI("4124".to_string())),
    );

    let id = ad.id;
    let ser_id = serde_json::to_string(&id).unwrap();
    assert_eq!(
        ser_id,
        "\"did:D5bw5KrpU2xRc3Oi4rsyBK9By6aotmXU0fNEybJbja1Q/attestationId/123\""
    );

    let aid = serde_json::from_str(&ser_id).unwrap();
    let deser_attestation_id = AttestationId::from_str(aid).unwrap();
    assert_eq!(
        deser_attestation_id.testator_id.get_id(),
        id.testator_id.get_id()
    );
    assert_eq!(deser_attestation_id.id, id.id);

    Ok(())
}

#[test]
pub fn test_signed_datum_serialization() -> Result<(), Error> {
    use crate::signed_attestation::SignedAttestation;
    let sd_str = r#"{"AttestationId":"did:keri:DoQa-mkiBs5kDaSjbONUpryZKAJ4zGFn9EMHJPXykDA0/attestationId/vPjipY4kdlyt9e-p5SM7N_X6DQQD2VEuIfF9Wnrx3w4=","AttestedDatumSources":["did:keri:DoQa-mkiBs5kDaSjbONUpryZKAJ4zGFn9EMHJPXykDA0/attestationId/sourceID"],"Datum":{"issuer":"DoQa-mkiBs5kDaSjbONUpryZKAJ4zGFn9EMHJPXykDA0","message":"Some vc"},"proof":{"signature":"byfYjUug5s0fgwhQuzX4C03G6BwWYi7BMrd-ZoJC8AAuDEYg8duM1iNFn6_ZaTwlAW1QrMWbpGO9_hBvSAF4DQ=="}}"#;
    let sd = SignedAttestation::deserialize(sd_str)?;
    assert_eq!(sd.serialize().unwrap(), sd_str);

    Ok(())
}
fn create() {}

fn verify() {}
