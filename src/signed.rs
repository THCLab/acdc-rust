use std::{convert::TryInto, str::FromStr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq)]
pub struct Signed<T> {
    pub data: T,
    pub sig: Signature,
}

impl<'a, T: Serialize + Deserialize<'a>> Signed<T> {
    pub fn serialize(&self) -> String {
        let json = serde_json::to_string(&self.data).unwrap();
        let sig = self.sig.to_string();
        format!("{}-{}", json, sig)
    }

    pub fn deserialize(s: &'a str) -> Result<Signed<T>, Error> {
        let de = serde_json::Deserializer::from_str(s);
        let mut stream = de.into_iter::<T>();
        let (data, s) = match stream.next() {
            Some(Ok(data)) => (data, &s[stream.byte_offset()..]),
            Some(Err(err)) => return Err(Error::DataJSONInvalid(err)),
            None => return Err(Error::DataMissing),
        };
        let s = match (s.get(..1), s.get(1..)) {
            (Some("-"), Some(s)) => s,
            _ => return Err(Error::SignatureMissing),
        };
        let sig = s.parse()?;
        Ok(Self { data, sig })
    }
}

/// https://github.com/decentralized-identity/keri/blob/master/kids/kid0001.md#base64-master-code-table
#[derive(Debug, Clone, PartialEq)]
pub enum Signature {
    /// Ed25519 signature. Self-signing derivation.
    Ed25519(ed25519_dalek::Signature),
}

impl ToString for Signature {
    fn to_string(&self) -> String {
        match self {
            Self::Ed25519(sig) => format!("0B{}", base64::encode(&sig.to_bytes())),
        }
    }
}

impl FromStr for Signature {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            s if s.starts_with("0B") => Ok(Self::Ed25519(
                base64::decode(&s[2..])?.as_slice().try_into()?,
            )),
            _ => Err(Error::SignatureTypeUnknown),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
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
