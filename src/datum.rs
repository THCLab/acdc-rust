//! Datum - a piece of information, instance of specific data
use std::fmt;

use serde::{Deserialize, Serialize};
pub trait Datum {}

#[derive(Serialize, Deserialize, Clone)]
pub struct Message {
    pub message: String,
}

impl Message {
    pub fn new(msg: &str) -> Self {
        Self {message: msg.to_string()}
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Datum for Message {}
