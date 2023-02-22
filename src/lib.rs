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
#[cfg(feature = "cesrox")]
pub mod signed;

pub use attestation::{Attestation, Attributes};
pub use authored::Authored;

#[cfg(feature = "cesrox")]
pub use signed::Signed;
