#![warn(clippy::all)]

pub mod attestation;
pub mod authored;
pub mod hashed;
pub mod signed;
mod test;

pub use attestation::{Attestation, Attributes, Version};
pub use authored::Authored;
pub use hashed::Hashed;
pub use signed::Signed;
