//! Types which contain their author/issuer/testator ID.

/// Types which contain their author/issuer/testator ID.
/// When wrapped in [`crate::Signed`] they can be automatically verified via [`crate::Signed::verify`].
pub trait Authored {
    /// Get author ID.
    fn get_author_id(&self) -> &str;
}
