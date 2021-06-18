use std::{fmt, str::FromStr};

use serde::{de, Deserialize, Serialize, Serializer};

use crate::{
    datum::Datum,
    error::Error,
    identifier::{BasicIdentifier, Identifier},
    source::Source,
};

/// ObjectType is an enum which allows to deal with different object types in the attestation. Any
/// object which can be either object `{}` or SAI (Self-Addressing Identifier) should be using this
/// enum.

/// TODO

#[derive(Serialize, Deserialize, Clone)]
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
#[derive(Clone)]
pub struct AttestationId {
    pub testator_id: Identifier,
    pub id: String,
}

impl AttestationId {
    pub fn new(testator_id: Identifier, id: &str) -> Self {
        AttestationId {
            // TODO: why we use into() here istead of clone?
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
        let str = [&self.testator_id.get_id(), "/attestation/", &self.id].join("");
        write!(fmt, "{}", str)
    }
}

impl FromStr for AttestationId {
    type Err = Error;

    // TODO replace that with generic did parser

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.replace("\"", "");
        let splietted_data: Vec<&str> = s.split(':').collect();
        let data = splietted_data
            .get(2)
            .ok_or(Error::Generic("Inpropper datum id format".into()))?;
        let splitted: Vec<&str> = data.split("/").collect();
        let testator_id = Identifier::Basic(BasicIdentifier {
            id: splitted
                .get(0)
                .ok_or(Error::Generic("Inpropper datum id format".into()))?
                .to_string(),
        });
        let attestation_id = splitted
            .get(2)
            .ok_or(Error::Generic("Inpropper datum id format".into()))?
            .to_owned();

        Ok(AttestationId::new(testator_id, attestation_id))
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AttestationDatum<D: Datum> {
    #[serde(rename = "i")]
    pub id: AttestationId,
    #[serde(rename = "t")]
    pub testator_id: Option<Identifier>,
    #[serde(rename = "s")]
    pub sources: Vec<Source>,
    #[serde(rename = "x")]
    pub schema: ObjectType,
    #[serde(rename = "d")]
    pub datum: D,
    #[serde(rename = "r")]
    pub rules: Option<ObjectType>,
}

impl<D: Datum + Clone> AttestationDatum<D> {
    //    pub fn attach_signature(&self, signature: Vec<u8>) -> Result<SignedAttestationDatum, Error> {
    //        let b64_signature = base64::encode_config(signature, URL_SAFE);
    //        let proof = Proof {
    //            signature: b64_signature,
    //        };
    //        Ok(SignedAttestationDatum {
    //            at_datum: self.clone(),
    //            proof,
    //        })
    //    }

    pub fn new(
        attestation_id: AttestationId,
        testator_id: Option<Identifier>,
        sources: Vec<Source>,
        schema: Option<ObjectType>,
        datum: D,
        rules: Option<ObjectType>,
    ) -> Self {
        AttestationDatum {
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
