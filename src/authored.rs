/// Types that contain their author/issuer/testator ID.
/// When wrapped in [`crate::Signed`] they can be automatically verified via [`crate::Signed::verify`].
pub trait Authored {
    fn get_author_id(&self) -> &str;
}
