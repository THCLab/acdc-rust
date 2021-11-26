use std::{collections::HashMap, convert::TryInto};

use serde::{Deserialize, Serialize};

use crate::Authored;

/// Wraps a serializable type and provides methods to verify and convert to/from signed JSON string.
///
/// # Examples
///
/// Serializing:
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
/// Verifying:
///
/// ```
/// # use std::collections::HashMap;
/// use acdc::{Authored, Signed};
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
///     keypair.public.to_bytes().to_vec(),
/// );
///
/// // verify
/// assert!(msg.verify(&pub_keys).is_ok());
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Signed<T> {
    pub data: T,
    pub sig: ed25519_dalek::Signature,
}

impl<'a, T> Signed<T>
where
    T: Serialize + Deserialize<'a>,
{
    /// Create a new [Signed] instance with a `ED25519_dalek` signature.
    pub fn new_with_ed25519(data: T, sig: &[u8]) -> Result<Self, ed25519_dalek::ed25519::Error> {
        use std::convert::TryFrom;
        let sig = ed25519_dalek::Signature::try_from(sig)?;
        Ok(Self { data, sig })
    }

    /// Get JSON bytes for given data for signing.
    pub fn get_json_bytes(data: &T) -> Vec<u8> {
        serde_json::to_vec(data).unwrap()
    }

    /// Serialize to signed JSON.
    pub fn to_signed_json(&self) -> String {
        let json = serde_json::to_string(&self.data).unwrap();
        let sig = base64::encode(self.sig.to_bytes());
        format!("{}-0B{}", json, sig)
    }

    /// Deserialize from signed JSON.
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
        let sig = match s {
            s if s.starts_with("0B") => (base64::decode(&s[2..])?.as_slice().try_into()?),
            _ => return Err(DeserializeError::SignatureTypeUnknown),
        };
        Ok(Self { data, sig })
    }
}

impl<'a, T> Signed<T>
where
    T: Serialize + Authored,
{
    /// Verify signature.
    pub fn verify(&self, pub_keys: &HashMap<String, Vec<u8>>) -> Result<(), VerifyError> {
        let issuer = self.data.get_author_id();
        let key = match pub_keys.get(issuer) {
            Some(key) => {
                ed25519_dalek::PublicKey::from_bytes(key).map_err(VerifyError::PubKeyInvalid)?
            }
            None => return Err(VerifyError::PubKeyNotFound),
        };
        let json = serde_json::to_string(&self.data).unwrap();
        use ed25519_dalek::Verifier;
        key.verify(json.as_bytes(), &self.sig)
            .map_err(VerifyError::SignatureInvalid)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeserializeError {
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

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("pub key not found")]
    PubKeyNotFound,
    #[error("pub key is invalid")]
    PubKeyInvalid(ed25519_dalek::SignatureError),
    #[error("signature is invalid")]
    SignatureInvalid(ed25519_dalek::ed25519::Error),
}
