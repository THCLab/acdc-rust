use indexmap::IndexMap;
use said::{SelfAddressingIdentifier, sad::SAD, version::format::SerializationFormats};
use serde::{Serialize, Deserialize};

#[derive(Serialize, SAD, Default, Debug, Clone, PartialEq, Deserialize)]
pub struct AttributesBlock {
	#[said]
	#[serde(rename = "d")]
	said: Option<SelfAddressingIdentifier>,
	#[serde(rename = "i", skip_serializing_if = "Option::is_none")]
	target: Option<String>,
	#[serde(flatten)]
	data: InlineAttributes
}

#[derive(Serialize, Default, Debug, Clone, PartialEq, Deserialize)]
pub struct InlineAttributes(IndexMap<String, serde_json::Value>);
impl InlineAttributes {
	pub fn to_untargeted_public_block(self) -> Attributes {
		let mut attr = AttributesBlock { said: None, target: None, data: self };
		attr.compute_digest();
		Attributes::Inline(attr)
	}
	pub fn to_targeted_public_block(self, target: String) -> Attributes {
		let mut attr = AttributesBlock { said: None, target: Some(target), data: self };
		attr.compute_digest();
		Attributes::Inline(attr)
	}

	pub fn to_untargeted_private_block(self) -> Attributes {
		todo!()
	}
	pub fn to_targeted_private_block(self, target: String) -> Attributes {
		todo!()
	}
}

/// Attestation attributes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Attributes {
    /// Inlined attributes as a JSON object.
    Inline(AttributesBlock),
    /// External attributes identified by their [`SelfAddressingIdentifier`].
    External(SelfAddressingIdentifier),
}

impl InlineAttributes {
    pub fn insert(&mut self, key: String, value: serde_json::Value) {
        self.0.insert(key, value);
    }
}

impl Attributes {
    pub fn new_inline(attributes: AttributesBlock) -> Self {
        Attributes::Inline(attributes)
    }
}
