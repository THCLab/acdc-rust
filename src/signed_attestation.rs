use std::{collections::HashMap, convert::TryInto, fmt, str::FromStr};

use base64::URL_SAFE;
use ed25519_dalek::{PublicKey, Signature, Verifier};
use serde::{Deserialize, Serialize};

use crate::{
    attestation::{Attestation, AttestationId},
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
        Self {
            key_type,
            signature: signature.to_vec(),
        }
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
        SignedAttestation { at_datum, proof }
    }

    pub fn get_id(&self) -> AttestationId {
        self.at_datum.id.clone()
    }

    /// Verify signed Attestation
    ///
    /// To verify Attestation we need to provide all SignedAttestaions
    /// corresponding to AttestationId in sources and public keys corresponding
    /// to their testators.
    /// Arguments: 
    ///     sources: vector of SignedAttestations corresponding to AttestaionIds in sources
    ///     keys: dict with testator id as key and his public key vec as value
    pub fn verify(
        &self,
        sources: &[SignedAttestation<String, Message, String>],
        keys: &HashMap<String, Vec<u8>>,
    ) -> Result<bool, Error> {
        if self.at_datum.sources.is_empty() {
            match self.proof.key_type {
                KeyType::Ed25519 => {
                    let signature =
                        {
                            Signature::new(
                                self.proof.signature.clone().try_into().map_err(|_e| {
                                    Error::Generic("Improper signature vec".into())
                                })?,
                            )
                        };
                    let pk = keys.get(&self.at_datum.id.testator_id.get_id()).unwrap();
                    let key = PublicKey::from_bytes(pk)
                        .map_err(|_e| Error::Generic("Improper public key vec".into()))?;
                    return Ok(key
                        .verify(
                            &serde_json::to_vec(&self.at_datum).map_err(|e| {
                                Error::Generic(format!(
                                    "AttestationDatum serialization error: {}",
                                    e.to_string()
                                ))
                            })?,
                            &signature,
                        )
                        .is_ok());
                }
                _ => {
                    // Not suported key type.
                    todo!()
                }
            }
        } else {
            let source = self
                .at_datum
                .sources
                .clone()
                .into_iter()
                .map(|source| {
                    let s = sources.into_iter().find(|sad| sad.at_datum.id == source);
                    match s {
                        Some(s) => s.verify(sources, keys),
                        None => Err(Error::Generic("Missing attestation".into())),
                    }
                })
                .all(|x| x.is_ok());

            return Ok(source);
        }
    }
}
