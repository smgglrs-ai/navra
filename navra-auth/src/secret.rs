//! Zeroizing secret wrapper.
//!
//! Unconditional (not gated behind the `desktop` feature) so that
//! non-desktop builds — e.g. the OAuth client-secret storage in
//! [`crate::auth::oauth`] — can keep secrets out of long-lived heap
//! copies. Zeroized on drop via the `zeroize` crate.

use zeroize::Zeroizing;

/// A resolved secret value. Zeroized on drop via the `zeroize` crate.
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    pub fn new(data: Vec<u8>) -> Self {
        Self(Zeroizing::new(data))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }
}
