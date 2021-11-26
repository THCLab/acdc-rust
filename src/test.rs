#![cfg(test)]

use std::collections::HashMap;

use ed25519_dalek::{Keypair, Signer};
use rand::rngs::OsRng;

use crate::{Attestation, Hashed, Signed};

#[test]
fn attest_ser_deser() {
    let mut attest: Attestation = Attestation::new(
        "did:keri:EmkPreYpZfFk66jpf3uFv7vklXKhzBrAqjsKAn2EDIPM",
        "E46jrVPTzlSkUPqGGeIZ8a8FWS7a6s4reAXRZOkogZ2A",
    );
    attest.attrs.insert(
        "dt".to_string(),
        "2021-06-09T17:35:54.169967+00:00".to_string(),
    );
    let attest: Hashed<Attestation> = Hashed::new(attest);

    let sig: Vec<u8> = base64::decode(
        "+LsV0MWSqowHYQ+Hg5yvR6GIb6mPQ4orQ4tPRMNCcnEkYCtZELqicA216bucHOlP5m0dZorojkZY+tgLD3v6DA==",
    )
    .unwrap();

    let attest: Signed<Hashed<Attestation>> =
        Signed::new_with_ed25519(attest, sig.as_slice()).unwrap();

    let attest_str = attest.to_signed_json();

    assert_eq!(
        attest_str,
        concat!(
            r#"{"#,
            r#""v":"ACDC10JSON00011c_","#,
            r#""i":"did:keri:EmkPreYpZfFk66jpf3uFv7vklXKhzBrAqjsKAn2EDIPM","#,
            r#""s":"E46jrVPTzlSkUPqGGeIZ8a8FWS7a6s4reAXRZOkogZ2A","#,
            r#""a":{"dt":"2021-06-09T17:35:54.169967+00:00"},"#,
            r#""p":[],"#,
            r#""r":[],"#,
            r#""d":"E5NscgYCVjzrCpmBu8ztQND8S_1h3XLtqh0c0vi9gxwo""#,
            r#"}"#,
            r#"-0B+LsV0MWSqowHYQ+Hg5yvR6GIb6mPQ4orQ4tPRMNCcnEkYCtZELqicA216bucHOlP5m0dZorojkZY+tgLD3v6DA=="#,
        )
    );

    let attest2: Signed<Hashed<Attestation>> = Signed::from_signed_json(&attest_str).unwrap();

    assert_eq!(attest, attest2);
}

#[test]
fn attest_sign_verify() {
    let mut attest = Attestation::new(
        "did:keri:EQzFVaMasUf4cZZBKA0pUbRc9T8yUXRFLyM1JDASYqAA",
        "EBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5K0neuniccM",
    );
    attest.attrs.insert(
        "dt".to_string(),
        "2021-06-09T17:35:54.169967+00:00".to_string(),
    );
    let attest = Hashed::new(attest);

    let mut rng = OsRng {};
    let keypair = Keypair::generate(&mut rng);
    let sig = keypair.sign(&Signed::get_json_bytes(&attest));

    let attest = Signed::new_with_ed25519(attest, &sig.to_bytes()).unwrap();

    let mut oracle = HashMap::new();
    oracle.insert(
        "did:keri:EQzFVaMasUf4cZZBKA0pUbRc9T8yUXRFLyM1JDASYqAA".to_string(),
        keypair.public.to_bytes().to_vec(),
    );
    attest.verify(&oracle).unwrap();
}
