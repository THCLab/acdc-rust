use base64::DecodeError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Decode64Error(#[from] DecodeError),
    #[error("{0}")]
    Generic(String),
}
