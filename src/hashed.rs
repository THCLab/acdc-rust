//! Type which contains its digest.

use said::prefix::SelfAddressingPrefix;
use serde::{Deserialize, Serialize};

use crate::Authored;

/// Wraps a serializable value and adds a `digest` field to it.
/// The digest is automatically calculated when calling [`Hashed::new`]
/// and checked upon deserializing.
/// The digest is a [`SelfAddressingPrefix`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hashed<T> {
    #[serde(flatten)]
    data: T,
    #[serde(rename = "d")]
    hash: SelfAddressingPrefix,
}

impl<T: Serialize> Hashed<T> {
    /// Creates new Hashed value.
    ///
    /// # Panics
    /// Panics when the wrapped value doesn't serialize to a JSON object.
    pub fn new(data: T) -> Self {
        let mut json = serde_json::to_value(&data).unwrap();
        json.as_object_mut()
            .expect("hashed data must serialize to JSON object")
            .insert("d".to_string(), "#".repeat(32).into());
        let json = serde_json::to_string(&json).unwrap();
        let hash = said::derivation::SelfAddressing::Blake3_256.derive(json.as_bytes());
        Self { data, hash }
    }

    /// Get the data as an immutable reference.
    pub fn get_data(&self) -> &T {
        &self.data
    }

    /// Get the hash as an immutable reference.
    pub fn get_hash(&self) -> &SelfAddressingPrefix {
        &self.hash
    }
}

impl<T> Authored for Hashed<T>
where
    T: Authored,
{
    fn get_author_id(&self) -> &str {
        self.data.get_author_id()
    }
}
