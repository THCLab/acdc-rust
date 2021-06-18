//! Datum - a piece of information, instance of specific data
//! Testator - a person who has made a will or given a legacy.

use std::{fmt, str::FromStr};

use base64::DecodeError;
use base64::URL_SAFE;

use serde::{de, Deserialize, Serialize, Serializer};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Decode64Error(#[from] DecodeError),
    #[error("{0}")]
    Generic(String),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Datum {
    pub message: String,
}

#[derive(Serialize, Deserialize)]
struct Proof {
    signature: String,
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
    testator_id: Identifier,
    id: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Identifier {
    id: String,
}

impl Identifier {
    pub fn new(id: &str) -> Self {
        Identifier { id: id.into() }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExternalSource {
    testator_id: Identifier,
    attestation_id: AttestationId,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum Source {
    External(ExternalSource),
    Internal(AttestationId),
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
        let str = [&self.testator_id.id, "/attestation/", &self.id].join("");
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
        let testator_id = Identifier {
            id: splitted
                .get(0)
                .ok_or(Error::Generic("Inpropper datum id format".into()))?
                .to_string(),
        };
        let attestation_id = splitted
            .get(2)
            .ok_or(Error::Generic("Inpropper datum id format".into()))?
            .to_owned();

        Ok(AttestationId::new(testator_id, attestation_id))
    }
}

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

#[derive(Serialize, Deserialize, Clone)]
pub struct AttestationDatum {
    #[serde(rename = "i")]
    id: AttestationId,
    #[serde(rename = "t")]
    testator_id: Option<Identifier>,
    #[serde(rename = "s")]
    sources: Vec<Source>,
    #[serde(rename = "x")]
    schema: Option<ObjectType>,
    #[serde(rename = "d")]
    datum: Datum,
    #[serde(rename = "r")]
    rules: Option<ObjectType>,
}

impl AttestationDatum {
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
        schema: ObjectType,
        datum: ObjectType,
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

    pub fn get_datum(&self) -> Datum {
        self.datum.clone()
    }

    pub fn get_id(&self) -> AttestationId {
        self.id.clone()
    }
}

#[derive(Serialize, Deserialize)]
pub struct SignedAttestationDatum {
    #[serde(flatten)]
    at_datum: AttestationDatum,
    proof: Proof,
}

impl fmt::Display for SignedAttestationDatum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ad_str = serde_json::to_string(&self.at_datum).unwrap();
        let s = &ad_str[1..ad_str.len() - 1];

        write!(
            f,
            "{{{}, \"proof\": {}}}",
            s,
            serde_json::to_string(&self.proof).unwrap()
        )
    }
}

impl SignedAttestationDatum {
    pub fn get_signature(&self) -> Result<Vec<u8>, Error> {
        base64::decode_config(self.proof.signature.clone(), URL_SAFE)
            .map_err(|e| Error::Decode64Error(e))
    }

    pub fn get_issuer(&self) -> Result<Identifier, Error> {
        Ok(self.at_datum.datum.issuer.clone())
    }

    pub fn get_datum(&self) -> Datum {
        self.at_datum.get_datum()
    }

    pub fn get_attestation_datum(&self) -> Result<String, Error> {
        serde_json::to_string(&self.at_datum).map_err(|_| Error::Generic("serde error".into()))
    }

    pub fn to_formatted_string(&self) -> Result<String, Error> {
        Ok(format!("{}", self))
    }

    pub fn serialize(&self) -> Result<String, Error> {
        serde_json::to_string(&self).map_err(|e| Error::Generic(e.to_string()))
    }

    pub fn deserialize(msg: &str) -> Result<SignedAttestationDatum, Error> {
        serde_json::from_str(msg).map_err(|e| Error::Generic(e.to_string()))
    }
}

#[test]
pub fn test_attestation_id_serialization() -> Result<(), Error> {
    let testator_id = Identifier {
        id: "D5bw5KrpU2xRc3Oi4rsyBK9By6aotmXU0fNEybJbja1Q".into(),
    };
    let msg_str = "hi there";
    let datum = Datum {
        message: msg_str.into(),
        issuer: testator_id.clone(),
    };
    let ad = AttestationDatum::new(
        AttestationId::new(testator_id, "123".into()),
        Some(Identifier { id: "123".into() }),
        vec![],
        Some(ObjectType::SAI("123".to_string())),
        datum,
        Some(ObjectType::SAI("4124".to_string())),
    );
    let id = ad.id;

    let ser_id = serde_json::to_string(&id).unwrap();
    assert_eq!(ser_id, "\"did:keri:D5bw5KrpU2xRc3Oi4rsyBK9By6aotmXU0fNEybJbja1Q/attestationId/jabUza-EpwNOQGALxFtFiMjC6PYdxlJqQtsI9E24uiI=\"");

    let deser_id = AttestationId::from_str(&ser_id).unwrap();
    assert_eq!(deser_id.testator_id.id, id.testator_id.id);
    assert_eq!(deser_id.id, id.id);

    Ok(())
}

#[test]
pub fn test_signed_datum_serialization() -> Result<(), Error> {
    let sd_str = r#"{"AttestationDatumId":"did:keri:DoQa-mkiBs5kDaSjbONUpryZKAJ4zGFn9EMHJPXykDA0/attestationId/vPjipY4kdlyt9e-p5SM7N_X6DQQD2VEuIfF9Wnrx3w4=","AttestedDatumSources":["did:keri:DoQa-mkiBs5kDaSjbONUpryZKAJ4zGFn9EMHJPXykDA0/attestationId/sourceID"],"Datum":{"issuer":"DoQa-mkiBs5kDaSjbONUpryZKAJ4zGFn9EMHJPXykDA0","message":"Some vc"},"proof":{"signature":"byfYjUug5s0fgwhQuzX4C03G6BwWYi7BMrd-ZoJC8AAuDEYg8duM1iNFn6_ZaTwlAW1QrMWbpGO9_hBvSAF4DQ=="}}"#;
    let sd = SignedAttestationDatum::deserialize(sd_str)?;
    assert_eq!(sd.serialize().unwrap(), sd_str);

    Ok(())
}
fn create() {}

fn verify() {}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
