//! Testator - a person who has made a will or given a legacy.

pub mod attestation;
pub mod datum;
pub mod error;
pub mod identifier;
pub mod signed_attestation;
pub mod source;

use crate::error::Error;
use crate::source::{ExternalSource, Source};
use crate::{
    attestation::AttestationDatum,
    attestation::{AttestationId, ObjectType},
    datum::Message,
    identifier::{BasicIdentifier, Identifier},
};
use std::str::FromStr;
