use std::fmt;

use base64::URL_SAFE;
use serde::{Deserialize, Serialize};

use crate::{
    attestation::Attestation,
    datum::{Datum, Message},
    error::Error,
};

#[derive(Serialize, Deserialize)]
struct Proof {
    signature: String,
}

#[derive(Serialize, Deserialize)]
pub struct SignedAttestation<S, D: Datum, R> {
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
            "{{{}, \"proof\": {}}}",
            s,
            serde_json::to_string(&self.proof).unwrap()
        )
    }
}

impl SignedAttestation<String, Message, String> {
    pub fn get_signature(&self) -> Result<Vec<u8>, Error> {
        base64::decode_config(self.proof.signature.clone(), URL_SAFE)
            .map_err(|e| Error::Decode64Error(e))
    }

    pub fn get_datum(&self) -> Message {
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

    pub fn deserialize(msg: &str) -> Result<SignedAttestation<String, Message, String>, Error> {
        serde_json::from_str(msg).map_err(|e| Error::Generic(e.to_string()))
    }
}
