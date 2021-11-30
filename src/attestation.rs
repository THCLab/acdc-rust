//! ACDC Attestation.
//!
//! See: [`Attestation`]

use std::collections::HashMap;

use said::prefix::SelfAddressingPrefix;
use serde::{Deserialize, Serialize};

use crate::Authored;

/// ACDC Attestation.
///
/// # Examples
///
/// ```
/// # use std::collections::HashMap;
/// use acdc::{Attestation, Hashed, Signed};
/// use ed25519_dalek::{Keypair, Signer};
///
/// // create some attestation
/// let mut attest: Attestation = Attestation::new(
///     "did:keri:EmkPreYpZfFk66jpf3uFv7vklXKhzBrAqjsKAn2EDIPM",
///     "E46jrVPTzlSkUPqGGeIZ8a8FWS7a6s4reAXRZOkogZ2A"
///         .parse()
///         .unwrap(),
/// );
///
/// // Add digest field to attestation
/// let attest: Hashed<Attestation> = Hashed::new(attest);
///
/// // compute the signature of the attestation
/// let mut rng = rand::rngs::OsRng {};
/// let keypair = Keypair::generate(&mut rng);
/// let sig = keypair.sign(&Signed::get_json_bytes(&attest));
///
/// // create new signed instance with the attestation and the signature
/// let attest: Signed<Hashed<Attestation>> =
///     Signed::new_with_ed25519(attest, &sig.to_bytes()).unwrap();
///
/// // serialize to signed json
/// dbg!(attest.to_signed_json()); // {"v":"ACDC10JSON00011c_",…}-SIGNATURE
///
/// // verify the signature
/// let mut pub_keys = HashMap::new();
/// pub_keys.insert(
///     "did:keri:EmkPreYpZfFk66jpf3uFv7vklXKhzBrAqjsKAn2EDIPM".to_string(),
///     keypair.public.to_bytes().to_vec(),
/// );
/// attest.verify(&pub_keys).unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attestation {
    /// Version string of ACDC.
    #[serde(rename = "v")]
    pub version: Version,

    /// Attributable source identifier (Issuer, Testator).
    #[serde(rename = "i")]
    pub issuer: String,

    /// Schema SAID.
    #[serde(rename = "s")]
    pub schema: said::prefix::SelfAddressingPrefix,

    /// Attributes.
    #[serde(rename = "a")]
    pub attrs: Attributes,

    /// Provenance chain.
    #[serde(rename = "p")]
    pub prov_chain: Vec<String>,

    /// Rules rules/delegation/consent/license/data agreement under which data are shared.
    #[serde(rename = "r")]
    pub rules: Vec<serde_json::Value>,
}

/// Attestation version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Version {
    /// Initial version.
    #[serde(rename = "ACDC10JSON00011c_")]
    ACDC1,
}

/// Attestation attributes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Attributes {
    /// Inlined attributes as a JSON object.
    Inline(HashMap<String, String>),
    /// External attributes identified by their [`SelfAddressingPrefix`].
    External(SelfAddressingPrefix),
}

impl Attestation {
    /// Creates a new attestation with given issuer and schema.
    #[must_use]
    pub fn new(issuer: &str, schema: said::prefix::SelfAddressingPrefix) -> Self {
        Self {
            version: Version::ACDC1,
            issuer: issuer.to_string(),
            schema,
            attrs: Attributes::Inline(HashMap::new()),
            prov_chain: Vec::new(),
            rules: Vec::new(),
        }
    }
}

impl Authored for Attestation {
    fn get_author_id(&self) -> &str {
        &self.issuer
    }
}
