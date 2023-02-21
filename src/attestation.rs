//! ACDC Attestation.
//!
//! See: [`Attestation`]

use std::collections::HashMap;

#[cfg(feature = "cesrox")]
use cesrox::payload::Payload;
use sai::{derivation::SelfAddressing, SelfAddressingPrefix};
use serde::{Deserialize, Serialize, Serializer};
use version::serialization_info::{SerializationFormats, SerializationInfo};

use crate::{error::Error, Authored};

/// ACDC Attestation.
///
/// # Examples
///
/// ```
/// # use std::collections::HashMap;
/// use acdc::{Attestation, Hashed, PubKey, Signed};
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
///     PubKey::ED25519(keypair.public.to_bytes().to_vec()),
/// );
/// attest.verify(&pub_keys).unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attestation {
    /// Version string of ACDC.
    #[serde(rename = "v")]
    pub version: SerializationInfo,

    /// Digest of attestaion
    #[serde(rename = "d", serialize_with = "dummy_serialize")]
    pub digest: SelfAddressingPrefix,

    /// Attributable source identifier (Issuer, Testator).
    #[serde(rename = "i")]
    pub issuer: String,

    /// Issuance and/or revocation, transfer, or retraction registry for ACDC
    /// derived from Issuer Identifier.
    #[serde(rename = "ri")]
    pub registry_identifier: String,

    /// Schema SAID.
    #[serde(rename = "s")]
    pub schema: SelfAddressingPrefix,

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

fn dummy_serialize<S>(x: &SelfAddressingPrefix, s: S) -> Result<S::Ok, S::Error>
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
    /// External attributes identified by their [`SelfAddressingPrefix`].
    External(SelfAddressingPrefix),
}

impl Attestation {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        Ok(self.version.kind.encode(self)?)
    }

    /// Creates a new attestation with given issuer and schema.
    #[must_use]
    pub fn new(issuer: &str, schema: SelfAddressingPrefix, derivation: SelfAddressing, data: HashMap<String, String>) -> Self {
        let version = SerializationInfo::new("ACDCOCA".to_string(), SerializationFormats::JSON, 0);
        let digest = derivation.derive(&[]);
        let mut acdc = Self {
            version,
            digest,
            registry_identifier: "".to_string(),
            issuer: issuer.to_string(),
            schema,
            attrs: Attributes::Inline(data),
            // prov_chain: Vec::new(),
            // rules: Vec::new(),
        };
        let acdc_len = acdc.encode().unwrap().len();
        acdc.version.size = acdc_len;
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

#[cfg(feature = "cesrox")]
impl From<Attestation> for Payload {
    fn from(value: Attestation) -> Self {
        match &value.version.kind {
            SerializationFormats::JSON => Payload::JSON(value.encode().unwrap()),
            SerializationFormats::MGPK => Payload::MGPK(value.encode().unwrap()),
            SerializationFormats::CBOR => Payload::CBOR(value.encode().unwrap()),
        }
    }
}

#[test]
pub fn test() -> Result<(), Error> {
    let mut data = HashMap::new();
    data.insert("greetings".to_string(), "hello".to_string());

    let attestation = Attestation::new(
        "issuer",
        SelfAddressingPrefix::new(SelfAddressing::Blake3_256, vec![]),
        SelfAddressing::Blake3_256,
        data,
    );
    println!(
        "att: {} ",
        String::from_utf8((attestation.encode().unwrap())).unwrap()
    );

    Ok(())
}
