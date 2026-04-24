//! Data labels for information flow control.
//!
//! These types annotate protocol messages with integrity and
//! confidentiality metadata. The label definitions live here
//! (in the protocol crate) because `CallToolResult` carries a
//! label field. Enforcement logic (taint tracking, write policies)
//! lives in the security crate.

use std::fmt;

/// Integrity level: can this data influence actions?
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Integrity {
    /// Data from system config, user input, or approved sources.
    Trusted = 0,
    /// Data from external sources (files, network, tool outputs).
    Untrusted = 1,
}

/// Confidentiality level: can this data leave the system?
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidentiality {
    /// Can appear in any tool output or external message.
    Public = 0,
    /// Can flow only to tools with matching clearance.
    Sensitive = 1,
    /// Cannot flow out at all (credentials, private keys).
    Secret = 2,
}

/// Data label combining integrity and confidentiality.
///
/// Assigned to tool results by the kernel. Propagated through
/// session taint accumulation. Checked by the IFC hook before
/// write operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DataLabel {
    pub integrity: Integrity,
    pub confidentiality: Confidentiality,
}

impl DataLabel {
    /// Fully trusted, public data (system-generated).
    pub const TRUSTED_PUBLIC: Self = Self {
        integrity: Integrity::Trusted,
        confidentiality: Confidentiality::Public,
    };

    /// Untrusted external data, public confidentiality.
    pub const UNTRUSTED_PUBLIC: Self = Self {
        integrity: Integrity::Untrusted,
        confidentiality: Confidentiality::Public,
    };

    /// Untrusted external data, sensitive confidentiality.
    pub const UNTRUSTED_SENSITIVE: Self = Self {
        integrity: Integrity::Untrusted,
        confidentiality: Confidentiality::Sensitive,
    };

    /// Trusted but secret data (credential values).
    pub const TRUSTED_SECRET: Self = Self {
        integrity: Integrity::Trusted,
        confidentiality: Confidentiality::Secret,
    };

    /// Join two labels: take the higher (more restrictive) value
    /// on each dimension. This is the lattice join operation.
    pub fn join(self, other: Self) -> Self {
        Self {
            integrity: if self.integrity > other.integrity {
                self.integrity
            } else {
                other.integrity
            },
            confidentiality: if self.confidentiality > other.confidentiality {
                self.confidentiality
            } else {
                other.confidentiality
            },
        }
    }

    /// Check if a write from this label to a target is allowed.
    ///
    /// Bell-LaPadula "no write-down": a session tainted with
    /// Sensitive data cannot write to a Public destination.
    pub fn can_write_to(self, target: Confidentiality) -> bool {
        self.confidentiality <= target
    }
}

impl Default for DataLabel {
    fn default() -> Self {
        Self::TRUSTED_PUBLIC
    }
}

impl fmt::Display for DataLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}+{:?}", self.integrity, self.confidentiality)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_join_takes_higher() {
        let a = DataLabel::TRUSTED_PUBLIC;
        let b = DataLabel::UNTRUSTED_SENSITIVE;
        let joined = a.join(b);
        assert_eq!(joined.integrity, Integrity::Untrusted);
        assert_eq!(joined.confidentiality, Confidentiality::Sensitive);
    }

    #[test]
    fn label_join_is_commutative() {
        let a = DataLabel::UNTRUSTED_PUBLIC;
        let b = DataLabel::TRUSTED_SECRET;
        assert_eq!(a.join(b), b.join(a));
    }

    #[test]
    fn label_join_is_idempotent() {
        let a = DataLabel::UNTRUSTED_SENSITIVE;
        assert_eq!(a.join(a), a);
    }

    #[test]
    fn no_write_down_secret_to_public() {
        let label = DataLabel::TRUSTED_SECRET;
        assert!(!label.can_write_to(Confidentiality::Public));
        assert!(!label.can_write_to(Confidentiality::Sensitive));
        assert!(label.can_write_to(Confidentiality::Secret));
    }

    #[test]
    fn public_can_write_anywhere() {
        let label = DataLabel::TRUSTED_PUBLIC;
        assert!(label.can_write_to(Confidentiality::Public));
        assert!(label.can_write_to(Confidentiality::Sensitive));
        assert!(label.can_write_to(Confidentiality::Secret));
    }

    #[test]
    fn display_format() {
        assert_eq!(
            format!("{}", DataLabel::UNTRUSTED_SENSITIVE),
            "Untrusted+Sensitive"
        );
    }
}
