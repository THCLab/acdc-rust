use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Version error")]
    VersionError(#[from] said::error::Error),

    #[error("Parse error")]
    ParseError,
}
