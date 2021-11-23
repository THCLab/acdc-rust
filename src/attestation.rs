use std::collections::HashMap;

use serde::{ser::SerializeMap, Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Deserialize)]
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

impl Serialize for Attestation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let json = json!({
            "v": self.version,
            "d": "#".repeat(32),
            "i": self.issuer,
            "s": self.schema,
            "a": self.attrs,
            "p": self.prov_chain,
            "r": self.rules,
        });
        let json = serde_json::to_string(&json).unwrap();
        let digest = said::derivation::SelfAddressing::Blake3_256.derive(json.as_bytes());
        let mut m = serializer.serialize_map(Some(7))?;
        m.serialize_entry("v", &self.version)?;
        m.serialize_entry("d", &digest)?;
        m.serialize_entry("i", &self.issuer)?;
        m.serialize_entry("s", &self.schema)?;
        m.serialize_entry("a", &self.attrs)?;
        m.serialize_entry("p", &self.prov_chain)?;
        m.serialize_entry("r", &self.rules)?;
        m.end()
    }
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
