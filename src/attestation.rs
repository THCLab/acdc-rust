use std::{collections::HashMap, convert::TryFrom};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(into = "AttestationData")]
pub struct Attestation {
    /// Version string of ACDC.
    #[serde(rename = "v")]
    pub version: String,

    /// Attributable source identifier (Issuer, Testator).
    #[serde(rename = "i")]
    pub issuer: String,

    /// Schema SAID.
    #[serde(rename = "s")]
    pub schema: String,

    /// Attributes.
    #[serde(rename = "a")]
    pub attrs: HashMap<String, String>,

    /// Provenance chain.
    #[serde(rename = "p")]
    pub prov_chain: Vec<String>,

    /// Rules rules/delegation/consent/license/data agreement under which data are shared.
    #[serde(rename = "r")]
    pub rules: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct AttestationData {
    #[serde(flatten)]
    attest: Attestation,

    /// SAID of ACDC.
    #[serde(rename = "d")]
    pub digest: said::prefix::SelfAddressingPrefix,
}

impl Attestation {
    pub fn new(issuer: &str, schema: &str) -> Self {
        Self {
            version: "ACDC10JSON00011c_".to_string(),
            issuer: issuer.to_string(),
            schema: schema.to_string(),
            attrs: HashMap::new(),
            prov_chain: Vec::new(),
            rules: Vec::new(),
        }
    }
}

impl ToString for Attestation {
    fn to_string(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

impl TryFrom<AttestationData> for Attestation {
    type Error = ();

    fn try_from(value: AttestationData) -> Result<Self, Self::Error> {
        Ok(value.attest)
    }
}

impl From<Attestation> for AttestationData {
    fn from(val: Attestation) -> Self {
        let mut json = serde_json::to_value(&val).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("d".to_string(), serde_json::Value::String("#".repeat(32)));
        let json = serde_json::to_string(&json).unwrap();
        let digest = said::derivation::SelfAddressing::Blake3_256.derive(json.as_bytes());
        AttestationData {
            attest: val,
            digest,
        }
    }
}
