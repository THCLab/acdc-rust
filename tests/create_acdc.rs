use acdc::{attributes::InlineAttributes, error::Error, Attestation};
use said::{
    derivation::{HashFunction, HashFunctionCode},
    sad::{SerializationFormats, SAD},
    version::Encode,
};

#[test]
pub fn test_new_targeted_public_attestation() -> Result<(), Error> {
    let mut attributes = InlineAttributes::default();
    attributes.insert("greetings".to_string(), "Hello".into());

    let attestation = Attestation::new_public_targeted(
        "issuer",
        "target",
        "".to_string(),
        HashFunction::from(HashFunctionCode::Blake3_256)
            .derive(&[0; 30])
            .to_string(),
        attributes,
        &SerializationFormats::JSON,
        &HashFunctionCode::Blake3_256,
    );

    let digest = attestation.digest.clone().unwrap();
    let derivation_data =
        attestation.derivation_data(&HashFunctionCode::Blake3_256, &SerializationFormats::JSON);
    assert!(digest.verify_binding(&derivation_data));
    println!(
        "{}",
        String::from_utf8(
            attestation
                .encode(&HashFunctionCode::Blake3_256, &SerializationFormats::JSON)
                .unwrap()
        )
        .unwrap()
    );

    Ok(())
}

#[test]
pub fn test_new_untargeted_public_attestation() -> Result<(), Error> {
    let mut attributes = InlineAttributes::default();
    attributes.insert("greetings".to_string(), "Hello".into());

    let attestation = Attestation::new_public_untargeted(
        "issuer",
        "".to_string(),
        HashFunction::from(HashFunctionCode::Blake3_256)
            .derive(&[0; 30])
            .to_string(),
        attributes,
        &SerializationFormats::JSON,
        &HashFunctionCode::Blake3_256,
    );

    let digest = attestation.digest.clone().unwrap();
    let derivation_data =
        attestation.derivation_data(&HashFunctionCode::Blake3_256, &SerializationFormats::JSON);
    assert!(digest.verify_binding(&derivation_data));
    println!(
        "{}",
        String::from_utf8(
            attestation
                .encode(&HashFunctionCode::Blake3_256, &SerializationFormats::JSON)
                .unwrap()
        )
        .unwrap()
    );

    Ok(())
}

#[test]
pub fn test_new_untargeted_private_attestation() -> Result<(), Error> {
    let mut attributes = InlineAttributes::default();
    attributes.insert("greetings".to_string(), "Hello".into());

    let attestation = Attestation::new_private_untargeted(
        "issuer",
        "".to_string(),
        HashFunction::from(HashFunctionCode::Blake3_256)
            .derive(&[0; 30])
            .to_string(),
        attributes,
        &SerializationFormats::JSON,
        &HashFunctionCode::Blake3_256,
    );

    let digest = attestation.digest.clone().unwrap();
    let derivation_data =
        attestation.derivation_data(&HashFunctionCode::Blake3_256, &SerializationFormats::JSON);
    assert!(digest.verify_binding(&derivation_data));
    println!(
        "{}",
        String::from_utf8(
            attestation
                .encode(&HashFunctionCode::Blake3_256, &SerializationFormats::JSON)
                .unwrap()
        )
        .unwrap()
    );
    let parsed: Attestation = serde_json::from_slice(
        &attestation
            .encode(&HashFunctionCode::Blake3_256, &SerializationFormats::JSON)
            .unwrap(),
    )
    .unwrap();
    println!(
        "{}",
        String::from_utf8(
            parsed
                .encode(&HashFunctionCode::Blake3_256, &SerializationFormats::JSON)
                .unwrap()
        )
        .unwrap()
    );

    Ok(())
}

#[test]
pub fn test_new_targeted_private_attestation() -> Result<(), Error> {
    let mut attributes = InlineAttributes::default();
    attributes.insert("greetings".to_string(), "Hello".into());

    let attestation = Attestation::new_private_targeted(
        "issuer",
        "target",
        "".to_string(),
        HashFunction::from(HashFunctionCode::Blake3_256)
            .derive(&[0; 30])
            .to_string(),
        attributes,
        &SerializationFormats::JSON,
        &HashFunctionCode::Blake3_256,
    );

    let digest = attestation.digest.clone().unwrap();
    let derivation_data =
        attestation.derivation_data(&HashFunctionCode::Blake3_256, &SerializationFormats::JSON);
    assert!(digest.verify_binding(&derivation_data));
    println!(
        "{}",
        String::from_utf8(
            attestation
                .encode(&HashFunctionCode::Blake3_256, &SerializationFormats::JSON)
                .unwrap()
        )
        .unwrap()
    );

    Ok(())
}
