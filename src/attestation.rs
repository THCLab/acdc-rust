//! ACDC Attestation.
//!
//! See: [`Attestation`]

use std::collections::HashMap;

use said::{derivation::HashFunction, derivation::HashFunctionCode, SelfAddressingIdentifier};
use serde::{Deserialize, Serialize, Serializer};
use version::serialization_info::{SerializationFormats, SerializationInfo};

use crate::{error::Error, Authored};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attestation {
    /// Version string of ACDC.
    #[serde(rename = "v")]
    pub version: SerializationInfo,

    /// Digest of attestaion
    #[serde(rename = "d", serialize_with = "dummy_serialize")]
    pub digest: SelfAddressingIdentifier,

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

fn dummy_serialize<S>(x: &SelfAddressingIdentifier, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if x.eq(&x.derivation.derive(&[])) {
        let dummy = "#".repeat(x.derivation.get_len());
        s.serialize_str(&dummy)
    } else {
        x.serialize(s)
    }
}

/// Attestation attributes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Attributes {
    /// Inlined attributes as a JSON object.
    Inline(HashMap<String, String>),
    /// External attributes identified by their [`SelfAddressingIdentifier`].
    External(SelfAddressingIdentifier),
}

impl Attestation {
    /// Encodes attestation according to serialization type specified by version
    /// string: JSON, CBOR or MGPK.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        Ok(self.version.kind.encode(self)?)
    }

    /// Creates attestation with default digest field, that is replaced by dummy
    /// string during serialization. It is used to compute proper digest later.
    fn dummy_attestation(
        serialization_format: SerializationFormats,
        derivation_type: HashFunction,
        registry_id: String,
        issuer_id: String,
        schema_sai: String,
        attributes: Attributes,
    ) -> Self {
        // Digest is initially setup as digest of empty data, to save derivation type.
        let digest = derivation_type.derive(&[]);
        let version = SerializationInfo::new("ACDC".to_string(), serialization_format, 0);
        let mut att = Self {
            version,
            digest,
            registry_identifier: registry_id,
            issuer: issuer_id,
            schema: schema_sai.to_string(),
            attrs: attributes,
            // prov_chain: Vec::new(),
            // rules: Vec::new(),
        };
        // Update encoded len. It was set to 0 before.
        let acdc_len = att.encode().unwrap().len();
        att.version.size = acdc_len;
        att
    }

    /// Creates a new attestation.
    #[must_use]
    pub fn new(issuer: &str, schema: String, derivation: HashFunction, attr: Attributes) -> Self {
        let mut acdc = Self::dummy_attestation(
            SerializationFormats::JSON,
            HashFunction::from(HashFunctionCode::Blake3_256),
            "".to_string(),
            issuer.to_string(),
            schema.to_string(),
            attr,
        );

        // Update encoded size
        let digest = derivation.derive(&acdc.encode().unwrap());
        acdc.digest = digest;

        acdc
    }
}

impl Authored for Attestation {
    fn get_author_id(&self) -> &str {
        &self.issuer
    }
}

#[test]
pub fn test_new_attestation() -> Result<(), Error> {
    let mut data = HashMap::new();
    data.insert("greetings".to_string(), "hello".to_string());
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

    let digest = attestation.digest.clone();
    let dummy = Attestation {
        digest: HashFunction::from(HashFunctionCode::Blake3_256).derive(&[]),
        ..attestation.clone()
    };
    assert_eq!(dummy.version, attestation.version);
    assert_eq!(dummy.issuer, attestation.issuer);
    assert_eq!(dummy.schema, attestation.schema);
    assert_eq!(dummy.attrs, attestation.attrs);
    assert_ne!(dummy.digest, attestation.digest);
    assert!(digest.verify_binding(&dummy.encode().unwrap()));

    Ok(())
}
