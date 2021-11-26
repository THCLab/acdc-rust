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

impl Authored for Attestation {
    fn get_author_id(&self) -> &str {
        &self.issuer
    }
}
