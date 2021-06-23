use std::{fmt, str::FromStr};

use serde::{de, Deserialize, Serialize, Serializer};

use crate::{
    datum::Datum,
    error::Error,
    identifier::{BasicIdentifier, Identifier},
};
use std::convert::TryFrom;
use uriparse::URI;

/// ObjectType is an enum which allows to deal with different object types in the attestation. Any
/// object which can be either object `{}` or SAI (Self-Addressing Identifier) should be using this
/// enum.

/// TODO

#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum ObjectType {
    // TODO replace it with SAI model
    SAI(String),
    OBJECT,
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
            testator_id: testator_id,
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
        let attestation_id = uri.path().to_string();
        // In our case the path is the full attestation id, where authority should be
        // testator id. Unfortunetally did spec does it wrong and URI cannot parse the authority
        // instead of did:1231e1212 should be did://123e1212/ so authority can be extracted
        // properly
        // TODO find out how to solve it. Already reported to did-core
        // For time being we just take the first method-specific-id by spliting string with path
        // char '/'
        let splietted_data: Vec<&str> = s.split('/').collect();
        let (scheme, authority, path, query, fragment) = uri.into_parts();
        let testator_id = Identifier::Basic(BasicIdentifier {
            id: splietted_data
                .get(0)
                .ok_or(Error::Generic("Invalid authority in identifier".into()))?
                .to_string(),
        });
        Ok(AttestationId::new(testator_id, s))
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Attestation<S, D, R> {
    #[serde(rename = "i")]
    pub id: AttestationId,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "t")]
    pub testator_id: Option<Identifier>,
    #[serde(rename = "s")]
    pub sources: Vec<AttestationId>,
    #[serde(rename = "x")]
    pub schema: S,
    #[serde(rename = "d")]
    pub datum: D,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "r")]
    pub rules: Option<R>,
}

impl<S, D: Datum + Clone, R> Attestation<S, D, R> {
    //    pub fn attach_signature(&self, signature: Vec<u8>) -> Result<SignedAttestation, Error> {
    //        let b64_signature = base64::encode_config(signature, URL_SAFE);
    //        let proof = Proof {
    //            signature: b64_signature,
    //        };
    //        Ok(SignedAttestation {
    //            at_datum: self.clone(),
    //            proof,
    //        })
    //    }

    pub fn new(
        attestation_id: AttestationId,
        testator_id: Option<Identifier>,
        sources: Vec<AttestationId>,
        schema: S,
        datum: D,
        rules: Option<R>,
    ) -> Self {
        Attestation {
            id: attestation_id,
            testator_id: testator_id,
            sources,
            schema,
            datum,
            rules,
        }
    }

    pub fn get_datum(&self) -> D {
        self.datum.clone()
    }

    pub fn get_id(&self) -> AttestationId {
        self.id.clone()
    }
}
