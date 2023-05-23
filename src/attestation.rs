//! ACDC Attestation.
//!
//! See: [`Attestation`]

use said::version::{format::SerializationFormats, SerializationInfo};
use said::{sad::SAD, SelfAddressingIdentifier};
use serde::{Deserialize, Serialize};

use crate::attributes::InlineAttributes;
use crate::{Attributes, Authored};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, SAD)]
#[version(protocol = "ACDC", major = 1, minor = 0)]
#[said(code = "E", format = "JSON")]
pub struct Attestation {
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

impl Attestation {
    /// Creates a new attestation.
    #[must_use]
    pub fn new(issuer: &str, schema: String, attr: Attributes) -> Self {
        let mut acdc = Self {
            digest: None,
            registry_identifier: "".to_string(),
            issuer: issuer.to_string(),
            schema,
            attrs: attr,
            // prov_chain: Vec::new(),
            // rules: Vec::new(),
        };
        // Compute digest and replace `d` field with SAID.
        acdc.compute_digest();
        acdc
    }

    pub fn new_public_targeted(
        issuer: &str,
        target_id: &str,
        schema: String,
        attr: InlineAttributes,
    ) -> Self {
        let mut acdc = Self {
            digest: None,
            registry_identifier: "".to_string(),
            issuer: issuer.to_string(),
            schema,
            attrs: attr.to_targeted_public_block(target_id.to_string()),
            // prov_chain: Vec::new(),
            // rules: Vec::new(),
        };
        // Compute digest and replace `d` field with SAID.
        acdc.compute_digest();
        acdc
    }

    pub fn new_public_untargeted(issuer: &str, schema: String, attr: InlineAttributes) -> Self {
        let mut acdc = Self {
            digest: None,
            registry_identifier: "".to_string(),
            issuer: issuer.to_string(),
            schema,
            attrs: attr.to_untargeted_public_block(),
            // prov_chain: Vec::new(),
            // rules: Vec::new(),
        };
        // Compute digest and replace `d` field with SAID.
        acdc.compute_digest();
        acdc
    }
}

impl Authored for Attestation {
    fn get_author_id(&self) -> &str {
        &self.issuer
    }
}

#[cfg(test)]
mod tests {
    use said::{
        derivation::{HashFunction, HashFunctionCode},
        sad::SAD,
        version::Encode,
    };

    use crate::{
        attributes::{AttributesBlock, InlineAttributes},
        error::Error,
        Attestation, Attributes,
    };
    #[test]
    pub fn test_new_targeted_public_attestation() -> Result<(), Error> {
        let mut attributes = InlineAttributes::default();
        attributes.insert("greetings".to_string(), "Hello".into());

        let attestation = Attestation::new_public_targeted(
            "issuer",
            "target",
            HashFunction::from(HashFunctionCode::Blake3_256)
                .derive(&[0; 30])
                .to_string(),
            attributes,
        );

        let digest = attestation.digest.clone().unwrap();
        let derivation_data = attestation.derivation_data();
        assert!(digest.verify_binding(&derivation_data));
        println!(
            "{}",
            String::from_utf8(attestation.encode().unwrap()).unwrap()
        );

        Ok(())
    }

    #[test]
    pub fn test_new_untargeted_public_attestation() -> Result<(), Error> {
        let mut attributes = InlineAttributes::default();
        attributes.insert("greetings".to_string(), "Hello".into());

        let attestation = Attestation::new_public_untargeted(
            "issuer",
            HashFunction::from(HashFunctionCode::Blake3_256)
                .derive(&[0; 30])
                .to_string(),
            attributes,
        );

        let digest = attestation.digest.clone().unwrap();
        let derivation_data = attestation.derivation_data();
        assert!(digest.verify_binding(&derivation_data));
        println!(
            "{}",
            String::from_utf8(attestation.encode().unwrap()).unwrap()
        );

        Ok(())
    }

    #[test]
    pub fn test_attributes_order() -> Result<(), Error> {
        let mut data = InlineAttributes::default();
        data.insert("name".to_string(), "Hella".into());
        data.insert("species".to_string(), "cat".into());
        data.insert("health".to_string(), "great".into());
        let attributes = data.to_untargeted_public_block();

        let attestation = Attestation::new(
            "issuer",
            HashFunction::from(HashFunctionCode::Blake3_256)
                .derive(&[0; 30])
                .to_string(),
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
}
