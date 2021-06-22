use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum Identifier {
    Basic(BasicIdentifier),
}

impl Identifier {
    pub fn get_id(&self) -> String {
        match self {
            Identifier::Basic(bi) => bi.id.to_owned(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct BasicIdentifier {
    pub id: String,
}

impl BasicIdentifier {
    pub fn new(id: &str) -> Self {
        BasicIdentifier { id: id.into() }
    }
}
