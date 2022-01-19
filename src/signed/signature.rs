use std::{convert::TryInto, str::FromStr};

#[derive(Debug, Clone, PartialEq)]
pub(super) enum Signature {
    ED25519(ed25519_dalek::Signature),
}

impl ToString for Signature {
    fn to_string(&self) -> String {
        match self {
            Self::ED25519(sig) => format!("0B{}", base64::encode(sig.to_bytes())),
        }
    }
}

impl FromStr for Signature {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sig = match s {
            s if s.starts_with("0B") => Self::ED25519(
                base64::decode(&s[2..])
                    .map_err(ParseError::InvalidBase64)?
                    .as_slice()
                    .try_into()
                    .map_err(|_| ParseError::InvalidBytes)?,
            ),
            _ => return Err(ParseError::TypeUnknown),
        };
        Ok(sig)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// Unknown signature type.
    #[error("unknown signature type")]
    TypeUnknown,

    /// Can't decode signature from base64.
    #[error("can't decode signature from base64")]
    InvalidBase64(base64::DecodeError),

    /// Signature is invalid.
    #[error("signature has invalid bytes")]
    InvalidBytes,
}
