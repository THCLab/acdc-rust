use indexmap::IndexMap;
use said::SelfAddressingIdentifier;
use serde::{Serialize, Deserialize};

pub struct InlineAttributes(IndexMap<String, serde_json::Value>);

/// Attestation attributes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Attributes {
    /// Inlined attributes as a JSON object.
    Inline(IndexMap<String, serde_json::Value>),
    /// External attributes identified by their [`SelfAddressingIdentifier`].
    External(SelfAddressingIdentifier),
}

impl InlineAttributes {
    pub fn new() -> Self {
        InlineAttributes(IndexMap::new())
    }

    pub fn insert(&mut self, key: String, value: serde_json::Value) {
        self.0.insert(key, value);
    }
}

impl Default for InlineAttributes {
    fn default() -> Self {
        Self::new()
    }
}

impl Attributes {
    pub fn new_inline(attributes: InlineAttributes) -> Self {
        Attributes::Inline(attributes.0)
    }
}
