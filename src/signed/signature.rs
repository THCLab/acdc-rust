use std::{convert::TryInto, str::FromStr};

// #[cfg(feature = "cesrox")]
// use keri::event_parsing::{attachment::attachment, Attachment};
#[cfg(feature = "cesrox")]
use keri::prefix::AttachedSignaturePrefix;
use cesrox::primitives::Signature;

#[derive(Debug, Clone, PartialEq)]
pub(super) enum Signature {
    ED25519(ed25519_dalek::Signature),
    #[cfg(feature = "cesrox")]
    KeriSignatures(Vec<AttachedSignaturePrefix>),
}

impl ToString for Signature {
    fn to_string(&self) -> String {
        match self {
            Self::ED25519(sig) => format!("0B{}", base64::encode(sig.to_bytes())),
            #[cfg(feature = "cesrox")]
            Signature::KeriSignatures(sigs) => todo!()
            //     format!(
            //     "0K{}",
            //     Attachment::AttachedSignatures(sigs.to_owned()).to_cesr()
            // ),
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
            #[cfg(feature = "cesrox")]
            s if s.starts_with("0K") => {
                todo!()
                // let att = attachment(&s[2..].as_bytes());
                // if let Ok((_, Attachment::AttachedSignatures(sigs))) = att {
                //     Ok(Self::KeriSignatures(sigs))
                // } else {
                //     Err(ParseError::InvalidBytes)
                // }?
            }
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
