//! Type which contains its signature.

mod signature;

use std::str::FromStr;

use cesrox::{group::Group, parse, payload::Payload, ParsedData};
use keri::{
    prefix::{IndexedSignature, SelfSigningPrefix},
    processor::event_storage::EventStorage,
};
use sai::SelfAddressingPrefix;

use crate::{authored::Encode, error::Error, Attestation, Authored};

use self::signature::Signature;

/// Wraps a serializable type and provides methods to verify and convert CESR.
///
#[derive(Debug, Clone, PartialEq)]
pub struct Signed<T: Authored + Encode> {
    /// The signed data.
    pub data: T,
    /// The signature of the data.
    sig: signature::Signature,
}

impl Signed<Attestation> {
    pub fn to_cesr(&self) -> Vec<u8> {
        let parsed = ParsedData {
            payload: self.data.clone().into(),
            attachments: self.sig.to_attachment(),
        };
        parsed.to_cesr().unwrap()
    }
}

impl FromStr for Signed<Attestation> {
    type Err = DeserializeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (_rest, parsed) = parse(s.as_bytes()).unwrap();

        let att = match parsed.payload {
            Payload::JSON(json) => {
                println!("string: {}", String::from_utf8(json.clone()).unwrap());
                serde_json::from_slice(&json).unwrap()
            }
            Payload::CBOR(cbor) => todo!(),
            Payload::MGPK(mgpk) => todo!(),
        };
        let sig = if let Group::SourceSealCouples(seals) = &parsed.attachments[0] {
            let (sn, (code, digest)) = &seals[0];
            if let Group::IndexedControllerSignatures(sigs) = &parsed.attachments[1] {
                let dig = SelfAddressingPrefix {
                    derivation: code.clone().into(),
                    digest: digest.clone(),
                };
                Signature::Transferable(*sn, dig, sigs[0].clone().into())
            } else {
                todo!()
            }
        } else {
            todo!()
        };

        Ok(Self { data: att, sig })
    }
}

impl<T: Authored + Encode> Signed<T> {
    /// Verify signature.
    ///
    /// # Errors
    /// Returns error when the verification fails.
    pub fn verify(&self, storage: &EventStorage) -> Result<(), VerifyError> {
        let issuer = &self.data.get_author_id().parse().unwrap();

        match &self.sig {
            signature::Signature::Transferable(sn, dig, (code, sig)) => {
                let key_conf = storage
                    .get_keys_at_event(issuer, *sn, dig)
                    .map_err(|e| VerifyError::PubKeyNotFound)?
                    .ok_or(VerifyError::PubKeyNotFound)?;

                let sig = SelfSigningPrefix::new(code.code, sig.clone());
                let index = code.index;
                let sig = IndexedSignature {
                    signature: sig,
                    index: index.into(),
                };
                key_conf
                    .verify(&self.data.encode().unwrap(), &[sig])
                    .unwrap()
                    .then_some(())
                    .ok_or(VerifyError::SignatureInvalid)
            }
            signature::Signature::NonTransferable(_, _) => todo!(),
        }
    }
}

/// [Signed] deserialize error.
#[derive(Debug, thiserror::Error)]
pub enum DeserializeError {
    /// Signed data is missing.
    #[error("signed data is missing")]
    DataMissing,

    /// Signed data is an invalid JSON: {0}.
    #[error("signed data is an invalid JSON: {0}")]
    DataJSONInvalid(serde_json::Error),

    /// Signature is missing.
    #[error("signature is missing")]
    SignatureMissing,

    /// Signature is invalid.
    #[error("signature is invalid")]
    SignatureInvalid(signature::ParseError),
}

/// [Signed] verify error.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// Pub key not found.
    #[error("pub key not found")]
    PubKeyNotFound,

    /// Pub key is invalid.
    #[error("pub key is invalid")]
    PubKeyInvalid(ed25519_dalek::SignatureError),

    /// Signature is invalid.
    #[error("signature is invalid")]
    SignatureInvalid,
}

#[cfg(test)]
pub mod test {
    use std::{collections::HashMap, sync::Arc};

    use cesrox::primitives::codes::{
        attached_signature_code::{AttachedSignatureCode, Index},
        self_signing::SelfSigning,
    };
    use controller::{Controller, ControllerConfig};
    use keri::{
        prefix::{BasicPrefix, CesrPrimitive, SelfSigningPrefix},
        signer::{CryptoBox, KeyManager},
    };
    use sai::{derivation::SelfAddressing, SelfAddressingPrefix};
    use tempfile::Builder;

    use crate::{
        error::Error,
        signed::{signature::Signature, VerifyError},
        Attestation, Attributes, Signed,
    };

    #[async_std::test]
    pub async fn test_keri_identifier() -> Result<(), Error> {
        let root = Builder::new().prefix("test-db").tempdir().unwrap();

        // Setup keri database and controller
        let controller = Arc::new(
            Controller::new(ControllerConfig {
                db_path: root.path().to_owned(),
                ..Default::default()
            })
            .unwrap(),
        );
        let km1 = CryptoBox::new().unwrap();

        let identifier1 = {
            let pk = BasicPrefix::Ed25519(km1.public_key());
            let npk = BasicPrefix::Ed25519(km1.next_public_key());

            let icp_event = controller
                .incept(vec![pk], vec![npk], vec![], 0)
                .await
                .unwrap();
            let signature =
                SelfSigningPrefix::Ed25519Sha512(km1.sign(icp_event.as_bytes()).unwrap());

            controller
                .finalize_inception(icp_event.as_bytes(), &signature)
                .await
                .unwrap()
        };
        let state = controller.storage.get_state(&identifier1).unwrap().unwrap();

        // Make attestation
        let mut data = HashMap::new();
        data.insert("greetings".to_string(), "hello".to_string());
        let attributes = Attributes::Inline(data);
        let schema_id = SelfAddressing::Blake3_256.derive("schema id".as_bytes());
        let issuer_id = state.prefix;

        let attestation = Attestation::new(
            &issuer_id.to_str(),
            schema_id,
            SelfAddressing::Blake3_256,
            attributes,
        );

        // Data needed for signature
        let last_dig = state.last_event_digest;
        let dig = SelfAddressingPrefix::new(SelfAddressing::Blake3_256, last_dig.digest);
        let sig = km1.sign(&attestation.encode().unwrap()).unwrap();

        let signature = Signature::Transferable(
            state.sn,
            dig.clone(),
            (
                AttachedSignatureCode::new(SelfSigning::Ed25519Sha512, Index::BothSame(0)),
                sig,
            ),
        );
        let signed = Signed {
            data: attestation.clone(),
            sig: signature,
        };

        println!(
            "signed att = {}",
            String::from_utf8(signed.to_cesr()).unwrap()
        );

        // Verify signed attestation
        assert!(signed.verify(&controller.storage).is_ok());

        // Data needed for signature
        let wrong_sig = km1.sign("wrong data".as_bytes()).unwrap();

        let signature = Signature::Transferable(
            0,
            dig,
            (
                AttachedSignatureCode::new(SelfSigning::Ed25519Sha512, Index::BothSame(0)),
                wrong_sig,
            ),
        );
        let signed = Signed {
            data: attestation,
            sig: signature,
        };

        println!(
            "signed att = {}",
            String::from_utf8(signed.to_cesr()).unwrap()
        );

        // Verify signed attestation
        assert!(matches!(
            signed.verify(&controller.storage),
            Err(VerifyError::SignatureInvalid)
        ));

        Ok(())
    }
}

#[test]
pub fn test_signed_from_str() -> Result<(), Error> {
    let input = r#"{"v":"ACDC10JSON0000d4_","d":"EIsodcx6ax3AA5p9yCoI30xoo4Dcvo6m-HibZ1fdwRG0","i":"EN9DWC88m9-nBdFcw_XZxG6KCu9tEHtbc2FAMox5QD3K","ri":"","s":"EAk_3P3ctK_FQvAdqzYNp_sgBst0yrt0lEU458WICWHD","a":{"greetings":"hello"}}-GAB0AAAAAAAAAAAAAAAAAAAAAAAEN9DWC88m9-nBdFcw_XZxG6KCu9tEHtbc2FAMox5QD3K-AABAABumg9BXrzebndWXWNEFd7lcgRFYJXmihOWcx-xB3g2vtORIrBxQ4iVOrwKUWjDpUZNkI5qTldVnsqE-9w1aiwF"#;
    let signed: Signed<Attestation> = input.parse().unwrap();

    Ok(())
}
