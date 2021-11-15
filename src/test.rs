#![cfg(test)]

use std::{collections::HashMap, convert::TryInto};

use serde_json::json;

use crate::{signed, Attestation};

#[test]
fn attest_ser_deser() {
    let attest = signed::Signed {
        data: Attestation {
            version: "ACDC10JSON00011c_".into(),
            digest: "EBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5K0neuniccM".into(),
            issuer: "did:keri:EmkPreYpZfFk66jpf3uFv7vklXKhzBrAqjsKAn2EDIPM".into(),
            schema: "E46jrVPTzlSkUPqGGeIZ8a8FWS7a6s4reAXRZOkogZ2A".into(),
            attrs: {
                let mut map = HashMap::new();
                map.insert("dt".into(), json!("2021-06-09T17:35:54.169967+00:00"));
                map
            },
            prov_chain: vec![],
            rules: vec![],
        },
        sig: signed::Signature::Ed25519(
            base64::decode("+LsV0MWSqowHYQ+Hg5yvR6GIb6mPQ4orQ4tPRMNCcnEkYCtZELqicA216bucHOlP5m0dZorojkZY+tgLD3v6DA==")
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap(),
        ),
    };

    let attest_str = attest.serialize();

    assert_eq!(
        attest_str,
        concat!(
            r#"{"#,
            r#""v":"ACDC10JSON00011c_","#,
            r#""d":"EBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5K0neuniccM","#,
            r#""i":"did:keri:EmkPreYpZfFk66jpf3uFv7vklXKhzBrAqjsKAn2EDIPM","#,
            r#""s":"E46jrVPTzlSkUPqGGeIZ8a8FWS7a6s4reAXRZOkogZ2A","#,
            r#""a":{"dt":"2021-06-09T17:35:54.169967+00:00"},"#,
            r#""p":[],"#,
            r#""r":[]"#,
            r#"}"#,
            r#"-0B+LsV0MWSqowHYQ+Hg5yvR6GIb6mPQ4orQ4tPRMNCcnEkYCtZELqicA216bucHOlP5m0dZorojkZY+tgLD3v6DA=="#,
        )
    );

    let attest2 = signed::Signed::<Attestation>::deserialize(&attest_str).unwrap();

    assert_eq!(attest, attest2);
}
