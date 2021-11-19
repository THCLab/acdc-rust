use std::{collections::HashMap};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attestation {
    /// Version string of ACDC.
    #[serde(rename = "v")]
    pub version: String,

    /// SAID of ACDC.
    #[serde(rename = "d")]
    pub digest: said::prefix::SelfAddressingPrefix,

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

impl Attestation {
    pub fn new(issuer: &str, schema: &str) -> Self {
        let mut this = Self {
            version: "ACDC10JSON00011c_".to_string(),
            digest: said::prefix::SelfAddressingPrefix::new(
                said::derivation::SelfAddressing::Blake3_256,
                b"################################".to_vec(),
            ),
            issuer: issuer.to_string(),
            schema: schema.to_string(),
            attrs: HashMap::new(),
            prov_chain: Vec::new(),
            rules: Vec::new(),
        };
        let json = serde_json::to_string(&this).unwrap();
        let digest = said::derivation::SelfAddressing::Blake3_256.derive(json.as_bytes());
        this.digest = digest;
        this
    }
}

impl ToString for Attestation {
    fn to_string(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}
