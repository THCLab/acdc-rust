use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::Authored;

/// ACDC Attestation.
///
/// See: <https://github.com/trustoverip/TSS0033-technology-stack-acdc/blob/main/docs/index.md>
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Version {
    #[serde(rename = "ACDC10JSON00011c_")]
    ACDC1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Attributes {
    Inline(HashMap<String, String>),
    External(said::prefix::SelfAddressingPrefix),
}

impl Attestation {
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
