//! Datum - a piece of information, instance of specific data
use serde::{Deserialize, Serialize};
pub trait Datum {}

#[derive(Serialize, Deserialize, Clone)]
pub struct Message {
    pub message: String,
}

impl Datum for Message {}
