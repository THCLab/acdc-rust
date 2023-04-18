//! ACDC Attestation.
//!
//! See: [`Attestation`]

use indexmap::IndexMap;
use said::{
    derivation::HashFunction,
    derivation::HashFunctionCode,
    sad::{sad_macros::SAD, SAD},
    SelfAddressingIdentifier,
};
use serde::{Deserialize, Serialize};
use version::serialization_info::{SerializationFormats, SerializationInfo};

use crate::{error::Error, Authored};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, SAD)]
pub struct Attestation {
    /// Version string of ACDC.
    #[serde(rename = "v")]
    pub version: SerializationInfo,

    /// Digest of attestation
    #[said]
    #[serde(rename = "d")]
    pub digest: Option<SelfAddressingIdentifier>,

    /// Attributable source identifier (Issuer, Testator).
    #[serde(rename = "i")]
    pub issuer: String,

    /// Issuance and/or revocation, transfer, or retraction registry for ACDC
    /// derived from Issuer Identifier.
    #[serde(rename = "ri")]
    pub registry_identifier: String,

    /// Schema SAID.
    #[serde(rename = "s")]
    pub schema: String,

    /// Attributes.
    #[serde(rename = "a")]
    pub attrs: Attributes,
    // /// Provenance chain.
    // #[serde(rename = "p")]
    // pub prov_chain: Vec<String>,

    // /// Rules rules/delegation/consent/license/data agreement under which data are shared.
    // #[serde(rename = "r")]
    // pub rules: Vec<serde_json::Value>,
}

/// Attestation attributes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Attributes {
    /// Inlined attributes as a JSON object.
    Inline(IndexMap<String, String>),
    /// External attributes identified by their [`SelfAddressingIdentifier`].
    External(SelfAddressingIdentifier),
}

impl Attestation {
    /// Encodes attestation according to serialization type specified by version
    /// string: JSON, CBOR or MGPK.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        Ok(self.version.kind.encode(self)?)
    }

    /// Creates attestation with default digest field and set version field.
    fn compute_version(
        serialization_format: SerializationFormats,
        derivation_type: &HashFunctionCode,
        registry_id: String,
        issuer_id: String,
        schema_sai: String,
        attributes: Attributes,
    ) -> Self {
        let version = SerializationInfo::new("ACDC".to_string(), serialization_format, 0);
        let mut att = Self {
            version,
            digest: None,
            registry_identifier: registry_id,
            issuer: issuer_id,
            schema: schema_sai.to_string(),
            attrs: attributes,
            // prov_chain: Vec::new(),
            // rules: Vec::new(),
        };
        // Update encoded len. It was set to 0 before.
        let acdc_len = att
            .derivation_data(derivation_type, &serialization_format)
            .len();
        att.version.size = acdc_len;
        att
    }

    /// Creates a new attestation.
    #[must_use]
    pub fn new(issuer: &str, schema: String, derivation: HashFunction, attr: Attributes) -> Self {
        let hash_function_code = derivation.into();
        let serialization_format = SerializationFormats::JSON;
        let acdc = Self::compute_version(
            serialization_format,
            &hash_function_code,
            "".to_string(),
            issuer.to_string(),
            schema.to_string(),
            attr,
        );
        // Compute digest and replace `d` field with SAID.
        acdc.compute_digest(hash_function_code, serialization_format)
    }
}

impl Authored for Attestation {
    fn get_author_id(&self) -> &str {
        &self.issuer
    }
}

#[test]
pub fn test_new_attestation() -> Result<(), Error> {
    let mut data = IndexMap::new();
    data.insert("greetings".to_string(), "Hello".to_string());
    let attributes = Attributes::Inline(data);

    let attestation = Attestation::new(
        "issuer",
        HashFunction::from(HashFunctionCode::Blake3_256)
            .derive(&[0; 30])
            .to_string(),
        HashFunction::from(HashFunctionCode::Blake3_256),
        attributes,
    );
    assert_eq!(
        &attestation.encode().unwrap().len(),
        &attestation.version.size
    );

    let digest = attestation.digest.clone().unwrap();
    let derivation_data =
        attestation.derivation_data(&HashFunctionCode::Blake3_256, &SerializationFormats::JSON);
    assert!(digest.verify_binding(&derivation_data));

    Ok(())
}

#[test]
pub fn test_attributes_order() -> Result<(), Error> {
    let mut data = IndexMap::new();
    data.insert("name".to_string(), "Hella".to_string());
    data.insert("species".to_string(), "cat".to_string());
    data.insert("health".to_string(), "great".to_string());
    let attributes = Attributes::Inline(data);

    let attestation = Attestation::new(
        "issuer",
        HashFunction::from(HashFunctionCode::Blake3_256)
            .derive(&[0; 30])
            .to_string(),
        HashFunction::from(HashFunctionCode::Blake3_256),
        attributes,
    );
    let encoded = attestation.encode().unwrap();
    let deserialized_attestation: Attestation = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(
        &attestation.encode().unwrap(),
        &deserialized_attestation.encode().unwrap()
    );

    Ok(())
}
