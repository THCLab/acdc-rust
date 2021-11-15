use std::{collections::HashMap, convert::TryFrom, fmt, str::FromStr};

use serde::{de, Deserialize, Serialize, Serializer};
use uriparse::URI;

use crate::{
    error::Error,
    identifier::{BasicIdentifier, Identifier},
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attestation {
    /// Version string of ACDC.
    #[serde(rename = "v")]
    pub version: String,

    /// SAID of ACDC.
    #[serde(rename = "d")]
    pub digest: String,

    /// Attributable source identifier (Issuer, Testator).
    #[serde(rename = "i")]
    pub issuer: String,

    /// Schema SAID.
    #[serde(rename = "s")]
    pub schema: String,

    /// Attributes.
    #[serde(rename = "a")]
    pub attrs: HashMap<String, serde_json::Value>,

    /// Provenance chain.
    #[serde(rename = "p")]
    pub prov_chain: Vec<serde_json::Value>,

    /// Rules rules/delegation/consent/license/data agreement under which data are shared.
    #[serde(rename = "r")]
    pub rules: Vec<serde_json::Value>,
}

/// AttestationId - identifier, which can be designated by Testator
/// to uniquely track specific attestation. AttestationID is always within namespace of
/// the Testator Identifier making it always globally unique.
/// example:
///      did:123456789/attestation/d12345
///          ------------          ------
///               |                  |
///            testator did      attestation id
#[derive(Clone, PartialEq)]
pub struct AttestationId {
    pub testator_id: Identifier,
    pub id: String,
}

impl AttestationId {
    pub fn new(testator_id: Identifier, id: &str) -> Self {
        AttestationId {
            testator_id,
            id: id.into(),
        }
    }
}

impl Serialize for AttestationId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AttestationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

impl fmt::Display for AttestationId {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let str = &self.id;
        write!(fmt, "{}", str)
    }
}

impl FromStr for AttestationId {
    type Err = Error;

    // TODO replace that with generic did parser
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uri = URI::try_from(s).unwrap();
        let _attestation_id = uri.path().to_string();
        // In our case the path is the full attestation id, where authority should be
        // testator id. Unfortunately did spec does it wrong and URI cannot parse the authority
        // instead of did:1231e1212 should be did://123e1212/ so authority can be extracted
        // properly
        // TODO find out how to solve it. Already reported to did-core
        // For time being we just take the first method-specific-id by splitting string with path
        // char '/'
        let split_data: Vec<&str> = s.split('/').collect();
        let (_scheme, _authority, _path, _query, _fragment) = uri.into_parts();
        let testator_id = Identifier::Basic(BasicIdentifier {
            id: split_data
                .get(0)
                .ok_or_else(|| Error::Generic("Invalid authority in identifier".into()))?
                .to_string(),
        });
        Ok(AttestationId::new(testator_id, s))
    }
}
