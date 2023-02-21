//! Authentic Chained Data Containers (ACDC)
//!
//! Spec: <https://github.com/trustoverip/TSS0033-technology-stack-acdc/blob/main/docs/index.md>
//!
//! For usage see: [`Attestation`]

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(missing_docs)]

pub mod attestation;
pub mod authored;
pub mod error;
pub mod hashed;
// pub mod signed;
// mod test;

pub use attestation::{Attestation, Attributes};
pub use authored::Authored;
pub use hashed::Hashed;
// pub use signed::{PubKey, Signed};
