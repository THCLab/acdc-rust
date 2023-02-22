use cesrox::{group::Group, primitives::IndexedSignature};
use sai::SelfAddressingPrefix;

#[derive(Debug, Clone, PartialEq)]
pub(super) enum Signature {
    Transferable(u64, SelfAddressingPrefix, IndexedSignature),
    NonTransferable(String, String),
}

impl Signature {
    pub fn to_attachment(&self) -> Vec<Group> {
        match self {
            Signature::Transferable(sn, sai, sig) => {
                vec![
                    Group::SourceSealCouples(vec![(*sn, sai.into())]),
                    Group::IndexedControllerSignatures(vec![sig.clone()]),
                ]
            }
            Signature::NonTransferable(_, _) => todo!(),
        }
    }
}

impl ToString for Signature {
    fn to_string(&self) -> String {
        let groups = self.to_attachment();
        groups
            .iter()
            .fold(String::new(), |acc, g| [acc, g.to_cesr_str()].join(""))
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
