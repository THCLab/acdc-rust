mod tests {
    use std::{collections::HashMap, sync::Arc};

    use controller::{
        config::ControllerConfig, error::ControllerError,
        identifier_controller::IdentifierController, Controller, CryptoBox, SelfSigningPrefix,
    };
    use sai::derivation::SelfAddressing;
    use tempfile::Builder;

    use crate::{error::Error, Attestation, Attributes};

    #[async_std::test]
    pub async fn test_from_cesr_str() -> Result<(), Error> {
        // TODO stream that doesn't have id in attachment, need to get id from attestation.
        // let input = r#"{"v":"ACDC10JSON0000d4_","d":"EIsodcx6ax3AA5p9yCoI30xoo4Dcvo6m-HibZ1fdwRG0","i":"EN9DWC88m9-nBdFcw_XZxG6KCu9tEHtbc2FAMox5QD3K","ri":"","s":"EAk_3P3ctK_FQvAdqzYNp_sgBst0yrt0lEU458WICWHD","a":{"greetings":"hello"}}-GAB0AAAAAAAAAAAAAAAAAAAAAAAEN9DWC88m9-nBdFcw_XZxG6KCu9tEHtbc2FAMox5QD3K-AABAABumg9BXrzebndWXWNEFd7lcgRFYJXmihOWcx-xB3g2vtORIrBxQ4iVOrwKUWjDpUZNkI5qTldVnsqE-9w1aiwF"#;
        let input = r#"{"v":"ACDC10JSON0000d4_","d":"EGzqtlwbkkNAnAVKjdnSeGH2-_1JBFbJXHu-B35bPe7h","i":"EGSEMzS5iOL_nr6dywniXuI-Tjla9lwB00nXPXyFDc2k","ri":"","s":"EAk_3P3ctK_FQvAdqzYNp_sgBst0yrt0lEU458WICWHD","a":{"greetings":"hello"}}-FABEGSEMzS5iOL_nr6dywniXuI-Tjla9lwB00nXPXyFDc2k0AAAAAAAAAAAAAAAAAAAAAAAEGSEMzS5iOL_nr6dywniXuI-Tjla9lwB00nXPXyFDc2k-AABAADvF49TXxBZI7mI8dCBQtB5dZsEShG7aCq8KiV211IGpxEuvAyKW1Cq-DEPXuXwm7svdUiSGv_po4DsiRq4J_IE"#;
        let root = Builder::new()
            .prefix("test-db")
            .tempdir()
            .unwrap()
            .into_path();
        // Setup keri database and controller
        let controller = Controller::new(ControllerConfig {
            db_path: root,
            ..Default::default()
        })
        .unwrap();
        // Error because event of digest from signature doesn't exists in database.
        let result = controller.verify_from_cesr(input);
        assert!(matches!(result, Err(ControllerError::VerificationError(_))));
        match result.err().unwrap() {
            ControllerError::VerificationError(errors) => {
                assert!(matches!(errors[0].0, ControllerError::MissingEventError))
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    async fn setup_controller(km: Arc<CryptoBox>) -> Result<IdentifierController, ControllerError> {
        use controller::{BasicPrefix, KeyManager};
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        let controller = Arc::new(Controller::new(ControllerConfig {
            db_path: root.path().to_owned(),
            ..Default::default()
        })?);

        let identifier1 = {
            let pk = BasicPrefix::Ed25519(km.public_key());
            let npk = BasicPrefix::Ed25519(km.next_public_key());

            let icp_event = controller.incept(vec![pk], vec![npk], vec![], 0).await?;
            let signature = SelfSigningPrefix::Ed25519Sha512(km.sign(icp_event.as_bytes())?);

            let incepted_identifier = controller
                .finalize_inception(icp_event.as_bytes(), &signature)
                .await?;
            IdentifierController::new(incepted_identifier, controller.clone())
        };
        identifier1.notify_witnesses().await?;
        Ok(identifier1)
    }

    #[async_std::test]
    async fn test_signing() -> Result<(), Error> {
        use controller::{CesrPrimitive, CryptoBox, KeyManager};
        // Setup signer
        // It will generate keypair and initiate identifier kel with inception event.
        let km1 = Arc::new(CryptoBox::new().unwrap());
        let signer = setup_controller(km1.clone()).await.unwrap();

        // Setup verifier
        // We use same database as signer, so signer kei is already inside.
        let verifier = signer.source.clone();
        // Process signer inception event to have current signing keys data
        // verifier.process_stream(&signer.get_kel().unwrap()).unwrap();

        // Make attestation. Signer is an issuer.
        let mut data = HashMap::new();
        data.insert("greetings".to_string(), "hello".to_string());

        let attributes = Attributes::Inline(data);
        let schema_id = SelfAddressing::Blake3_256.derive("schema id".as_bytes());
        let issuer_id = signer.id.clone();

        let attestation = Attestation::new(
            &issuer_id.to_str(),
            schema_id,
            SelfAddressing::Blake3_256,
            attributes,
        );

        let signature =
            SelfSigningPrefix::Ed25519Sha512(km1.sign("sign wrong data".as_bytes()).unwrap());
        // Sign attestation with wrong signatures
        let signed_stream = signer
            .sign_to_cesr(
                &String::from_utf8(attestation.encode().unwrap()).unwrap(),
                signature,
                0,
            )
            .unwrap();

        // Verify signed attestation
        let result = verifier.verify_from_cesr(&signed_stream);
        assert!(matches!(result, Err(ControllerError::VerificationError(_))));
        match result.err().unwrap() {
            ControllerError::VerificationError(errors) => {
                assert!(matches!(errors[0].0, ControllerError::FaultySignature))
            }
            _ => unreachable!(),
        }

        // Now with ok signature
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&attestation.encode()?).unwrap());
        let signed_stream = signer
            .sign_to_cesr(
                &String::from_utf8(attestation.encode().unwrap()).unwrap(),
                signature,
                0,
            )
            .unwrap();

        // Verify signed attestation
        assert!(verifier.verify_from_cesr(&signed_stream).is_ok());

        Ok(())
    }
}
