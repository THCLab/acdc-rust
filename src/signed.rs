use std::{collections::HashMap, convert::TryInto};

use crate::Attestation;

#[derive(Debug, Clone, PartialEq)]
pub struct SignedAttestation {
    pub attest: Attestation,
    pub sig: ed25519_dalek::Signature,
}

impl SignedAttestation {
    pub fn new_with_ed25519(
        attest: Attestation,
        sig: &[u8],
    ) -> Result<Self, ed25519_dalek::ed25519::Error> {
        use std::convert::TryFrom;
        let sig = ed25519_dalek::Signature::try_from(sig)?;
        Ok(Self { attest, sig })
    }

    pub fn serialize(&self) -> String {
        let json = serde_json::to_string(&self.attest).unwrap();
        let sig = base64::encode(self.sig.to_bytes());
        format!("{}-0B{}", json, sig)
    }

    pub fn deserialize(s: &str) -> Result<SignedAttestation, DeserializeError> {
        let de = serde_json::Deserializer::from_str(s);
        let mut stream = de.into_iter::<Attestation>();
        let (data, s) = match stream.next() {
            Some(Ok(data)) => (data, &s[stream.byte_offset()..]),
            Some(Err(err)) => return Err(DeserializeError::DataJSONInvalid(err)),
            None => return Err(DeserializeError::DataMissing),
        };
        let s = match (s.get(..1), s.get(1..)) {
            (Some("-"), Some(s)) => s,
            _ => return Err(DeserializeError::SignatureMissing),
        };
        let sig = match s {
            s if s.starts_with("0B") => (base64::decode(&s[2..])?.as_slice().try_into()?),
            _ => return Err(DeserializeError::SignatureTypeUnknown),
        };
        Ok(Self { attest: data, sig })
    }

    pub fn verify(&self, pub_keys: HashMap<String, Vec<u8>>) -> Result<(), VerifyError> {
        let issuer = &self.attest.issuer;
        let key = match pub_keys.get(issuer) {
            Some(key) => ed25519_dalek::PublicKey::from_bytes(key)?,
            None => return Err(VerifyError::PubKeyNotFound),
        };
        let json = serde_json::to_string(&self.attest).unwrap();
        use ed25519_dalek::Verifier;
        key.verify(json.as_bytes(), &self.sig)
            .map_err(VerifyError::SignatureInvalid)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeserializeError {
    #[error("signed data is missing")]
    DataMissing,
    #[error("signed data is an invalid JSON: {0}")]
    DataJSONInvalid(#[from] serde_json::Error),
    #[error("signature is missing")]
    SignatureMissing,
    #[error("signature is invalid")]
    SignatureInvalid(#[from] ed25519_dalek::ed25519::Error),
    #[error("can't decode signature from base64")]
    SignatureInvalidBase64(#[from] base64::DecodeError),
    #[error("unknown signature type")]
    SignatureTypeUnknown,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("pub key not found")]
    PubKeyNotFound,
    #[error("pub key is invalid")]
    PubKeyInvalid(#[from] ed25519_dalek::ed25519::Error),
    #[error("signature is invalid")]
    SignatureInvalid(ed25519_dalek::ed25519::Error),
}
