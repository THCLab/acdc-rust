use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Version error")]
    VersionError(#[from] version::error::Error),
}
