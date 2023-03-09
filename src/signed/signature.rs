use cesrox::{group::Group, primitives::IndexedSignature};
use keri::prefix::{BasicPrefix, SelfSigningPrefix};
use sai::SelfAddressingPrefix;

use crate::error::Error;

#[derive(Debug, Clone, PartialEq)]
pub(super) enum Signature {
    Transferable(u64, SelfAddressingPrefix, IndexedSignature),
    NonTransferable(BasicPrefix, SelfSigningPrefix),
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
            Signature::NonTransferable(bp, ssp) => vec![Group::NontransReceiptCouples(vec![(
                (bp.clone()).into(),
                (ssp.clone()).into(),
            )])],
        }
    }

    pub fn from_attachment(groups: impl IntoIterator<Item = Group>) -> Result<Signature, Error> {
        let mut group_iterator = groups.into_iter();
        Ok(match group_iterator.next().ok_or(Error::SomeError("empty groups".into()))? {
            Group::NontransReceiptCouples(couplet) => {
                couplet
                    .iter()
                    .map(|(key, sig)| Signature::NonTransferable(key.clone().into(), sig.clone().into()))
                    .collect::<Vec<_>>()
                    [0]
                    .clone()
            },
            Group::SourceSealCouples(seals) => {
                let sigs = group_iterator.next().ok_or(Error::SomeError("empty groups".into()))?;
                if let Group::IndexedControllerSignatures(sigs) = sigs {
                    Signature::Transferable(seals[0].0, seals[0].clone().1.into(), sigs[0].clone())
                } else {
                    return Err(Error::SomeError("Unexpected attachment".into()))
                }
            },
            _ => return Err(Error::SomeError("Unexpected attachment".into()))
        })
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
