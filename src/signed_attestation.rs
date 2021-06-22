use std::{convert::TryInto, fmt, str::FromStr};

use base64::URL_SAFE;
use ed25519_dalek::{PublicKey, Signature, Verifier};
use serde::{Deserialize, Serialize};

use crate::{
    attestation::Attestation,
    datum::{Datum, Message},
    error::Error,
};

#[derive(Serialize, Deserialize)]
pub struct Proof {
    key_type: KeyType,
    signature: Vec<u8>,
}
impl Proof {
    pub fn new(key_type: KeyType, signature: &[u8]) -> Self {
        Self { key_type, signature: signature.to_vec() }
    } 
}

#[derive(Serialize, Deserialize)]
pub enum KeyType {
    Ed25519,
}

#[derive(Serialize, Deserialize)]
pub struct SignedAttestation<S, D: Datum + Serialize, R> {
    #[serde(flatten)]
    at_datum: Attestation<S, D, R>,
    proof: Proof,
}

impl fmt::Display for SignedAttestation<String, Message, String> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ad_str = serde_json::to_string(&self.at_datum).unwrap();
        let s = &ad_str[1..ad_str.len() - 1];

        write!(
            f,
            "{{{}}}--{}",
            s,
            base64::encode_config(&self.proof.signature, URL_SAFE)
        )
    }
}

impl FromStr for SignedAttestation<String, Message, String> {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let splitted: Vec<_> = s.splitn(2, "--").collect();
        let at_datum: Attestation<String, Message, String> = splitted
            .get(0)
            .map(|ad| {
                serde_json::from_str(ad).map_err(|e| {
                    Error::Generic(format!("Can't parse att datum: {}", e.to_string()))
                })
            })
            .ok_or(Error::Generic("There is no attestaion data".into()))??;
        let signature: Vec<u8> = splitted
            .get(1)
            .map(|sig| base64::decode_config(sig, URL_SAFE).unwrap())
            .ok_or(Error::Generic("There is no attestaion data".into()))?;
        let proof = Proof {
            signature,
            key_type: KeyType::Ed25519,
        };
        Ok(SignedAttestation::new(at_datum, proof))
    }
}

impl<S: Serialize, D: Datum + Serialize, R: Serialize> SignedAttestation<S, D, R> {
    pub fn new(at_datum: Attestation<S, D, R>, proof: Proof) -> Self {
        SignedAttestation {
            at_datum,
            proof,
        }
    }

    pub fn verify(
        &self,
        pk: &[u8],
        sources: &[Attestation<String, Message, String>],
    ) -> Result<bool, Error> {
        // TODO Verify sources.
        match self.proof.key_type {
            KeyType::Ed25519 => {
                let signature = {
                    Signature::new(
                        self.proof
                            .signature
                            .clone()
                            .try_into()
                            .map_err(|e| Error::Generic("Improper signature vec".into()))?,
                    )
                };
                let key = PublicKey::from_bytes(pk)
                    .map_err(|e| Error::Generic("Improper public key vec".into()))?;
                Ok(key
                    .verify(&serde_json::to_vec(&self.at_datum).unwrap(), &signature)
                    .is_ok())
            }
            _ => {
                todo!()
            }
        }
    }
}
