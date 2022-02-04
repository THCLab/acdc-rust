//! Type which contains its signature.

mod pub_key;
mod signature;

use std::collections::HashMap;

#[cfg(feature = "keriox")]
use keri::prefix::AttachedSignaturePrefix;
use serde::{Deserialize, Serialize};

pub use self::pub_key::PubKey;
use crate::Authored;

/// Wraps a serializable type and provides methods to verify and convert to/from signed JSON string.
///
/// # Examples
///
/// ## Serializing
///
/// ```
/// # use std::collections::HashMap;
/// use acdc::Signed;
/// use ed25519_dalek::{Keypair, Signer};
///
/// // create some data
/// let mut data: HashMap<String, String> = HashMap::new();
/// data.insert("msg".to_string(), "hello".to_string());
///
/// // compute the signature of the data
/// let mut rng = rand::rngs::OsRng {};
/// let keypair = Keypair::generate(&mut rng);
/// let sig = keypair.sign(&Signed::get_json_bytes(&data));
///
/// // create new signed instance with the data and the signature
/// let data: Signed<HashMap<String, String>> =
///     Signed::new_with_ed25519(data, &sig.to_bytes()).unwrap();
///
/// // serialize to signed json
/// dbg!(data.to_signed_json()); // {"msg":"hello"}-SIGNATURE
/// ```
///
/// ## Verifying
///
/// ```
/// # use std::collections::HashMap;
/// use acdc::{Authored, PubKey, Signed};
/// use ed25519_dalek::{Keypair, Signer};
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Debug, Clone, Serialize, Deserialize)]
/// struct Message {
///     author: String,
///     msg: String,
/// }
///
/// impl Authored for Message {
///     fn get_author_id(&self) -> &str {
///         &self.author
///     }
/// }
///
/// // create some data
/// let msg = Message {
///     author: "alice".to_string(),
///     msg: "hello".to_string(),
/// };
///
/// // compute the signature of the data
/// let mut rng = rand::rngs::OsRng {};
/// let keypair = Keypair::generate(&mut rng);
/// let sig = keypair.sign(&Signed::get_json_bytes(&msg));
///
/// // create new signed instance with the data and the signature
/// let msg: Signed<Message> =
///     Signed::new_with_ed25519(msg, &sig.to_bytes()).unwrap();
///
/// // initialize known public keys database
/// let mut pub_keys = HashMap::new();
/// pub_keys.insert(
///     "alice".to_string(),
///     PubKey::ED25519(keypair.public.to_bytes().to_vec()),
/// );
///
/// // verify
/// assert!(msg.verify(&pub_keys).is_ok());
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Signed<T> {
    /// The signed data.
    pub data: T,
    /// The signature of the data.
    sig: signature::Signature,
}

impl<'a, T> Signed<T>
where
    T: Serialize + Deserialize<'a>,
{
    /// Create a new [Signed] instance with a `ED25519_dalek` signature.
    ///
    /// # Errors
    /// Returns an error when the signature bytes are invalid.
    pub fn new_with_ed25519(data: T, sig: &[u8]) -> Result<Self, ed25519_dalek::ed25519::Error> {
        use std::convert::TryFrom;
        let sig = signature::Signature::ED25519(ed25519_dalek::Signature::try_from(sig)?);
        Ok(Self { data, sig })
    }

    /// Create a new [Signed] instance with a `keriox` signature.
    ///
    #[cfg(feature = "keriox")]
    pub fn new_with_keri_signatures(
        data: T,
        sig: &[AttachedSignaturePrefix],
    ) -> Result<Self, keri::error::Error> {
        let sig = signature::Signature::KeriSignatures(sig.to_vec());
        Ok(Self { data, sig })
    }

    /// Get JSON bytes for given data for signing.
    ///
    /// # Panics
    /// Panics if T's implementation of Serialize decides to fail.
    pub fn get_json_bytes(data: &T) -> Vec<u8> {
        serde_json::to_vec(data).unwrap()
    }

    /// Serialize to signed JSON.
    ///
    /// # Panics
    /// Panics if T's implementation of Serialize decides to fail.
    pub fn to_signed_json(&self) -> String {
        let json = serde_json::to_string(&self.data).unwrap();
        let sig = self.sig.to_string();
        format!("{}-{}", json, sig)
    }

    /// Deserialize from signed JSON.
    ///
    /// # Errors
    /// Returns error when the input is not a valid JSON + signature.
    pub fn from_signed_json(s: &'a str) -> Result<Self, DeserializeError> {
        let de = serde_json::Deserializer::from_str(s);
        let mut stream = de.into_iter::<T>();
        let (data, s) = match stream.next() {
            Some(Ok(data)) => (data, &s[stream.byte_offset()..]),
            Some(Err(err)) => return Err(DeserializeError::DataJSONInvalid(err)),
            None => return Err(DeserializeError::DataMissing),
        };
        let s = match (s.get(..1), s.get(1..)) {
            (Some("-"), Some(s)) => s,
            _ => return Err(DeserializeError::SignatureMissing),
        };
        let sig = s.parse().map_err(DeserializeError::SignatureInvalid)?;
        Ok(Self { data, sig })
    }
}

impl<'a, T> Signed<T>
where
    T: Serialize + Authored,
{
    /// Verify signature.
    ///
    /// # Panics
    /// Panics if T's implementation of Serialize decides to fail.
    ///
    /// # Errors
    /// Returns error when the verification fails.
    pub fn verify(&self, pub_keys: &HashMap<String, PubKey>) -> Result<(), VerifyError> {
        use ed25519_dalek::Verifier;
        let issuer = self.data.get_author_id();
        let key = match pub_keys.get(issuer) {
            Some(key) => key,
            None => return Err(VerifyError::PubKeyNotFound),
        };
        let json = serde_json::to_string(&self.data).unwrap();
        match key {
            PubKey::ED25519(key) => {
                let sig = match &self.sig {
                    signature::Signature::ED25519(sig) => sig,
                    #[allow(unreachable_patterns)] // TODO remove after adding more sig types
                    _ => return Err(VerifyError::PubKeyNotFound),
                };
                let key = ed25519_dalek::PublicKey::from_bytes(key)
                    .map_err(VerifyError::PubKeyInvalid)?;
                key.verify(json.as_bytes(), sig)
                    .map_err(|_| VerifyError::SignatureInvalid)
            }
            #[cfg(feature = "keriox")]
            PubKey::KeriKeys(key_config) => {
                if let signature::Signature::KeriSignatures(ks) = self.sig.clone() {
                    key_config
                        .verify(json.as_bytes(), &ks)
                        .map_err(|_e| VerifyError::SignatureInvalid)?
                        .then(|| ())
                        .ok_or(VerifyError::SignatureInvalid)
                } else {
                    Err(VerifyError::SignatureInvalid)
                }
            }
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

#[cfg(feature = "keriox")]
#[test]
fn test_parsing_keri_signatures() {
    use crate::Attestation;
    let signed = r#"{"v":"ACDC10JSON00011c_","i":"DeTaMr5iQxkiANa-prF_bqRdBrIudP293QJU5Td6Zalg","s":"E46jrVPTzlSkUPqGGeIZ8a8FWS7a6s4reAXRZOkogZ2A","a":{},"p":[],"r":[],"d":"EW8yY4SUSxMdVCT0ZyFT_WI8yA3nnewFgRGEI-xtiAJY"}-0K-AABAAaD8fuGiHip2QcPT3YJgz7l4KS7yMWTw67Y-IYpC2JYBts50EOL1Zu0zq3RmWbrg8FvEEioH078kt_2L59y62Aw"#;
    let s: Result<Signed<Attestation>, _> = Signed::from_signed_json(signed);
    assert!(s.is_ok())
}
