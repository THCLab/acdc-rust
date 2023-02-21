#[cfg(feature = "cesrox")]
use keri::event::sections::KeyConfig;

/// Types of supported public keys in [`Signed::verify`](super::Signed::verify) method.
pub enum PubKey {
    /// ED25519_dalek pub key.
    ED25519(Vec<u8>),
    #[cfg(feature = "cesrox")]
    KeriKeys(KeyConfig),
}
