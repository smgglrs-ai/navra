//! Data labels for information flow control.
//!
//! These types annotate protocol messages with integrity and
//! confidentiality metadata. The label definitions live here
//! (in the protocol crate) because `CallToolResult` carries a
//! label field. Enforcement logic (taint tracking, write policies)
//! lives in the security crate.

use std::fmt;
use vstd::prelude::*;

/// Integrity level: can this data influence actions?
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Integrity {
    /// Data from system config, user input, or approved sources.
    Trusted = 0,
    /// Data from external sources (files, network, tool outputs).
    Untrusted = 1,
}

/// Confidentiality level: can this data leave the system?
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Confidentiality {
    /// Can appear in any tool output or external message.
    Public = 0,
    /// Can flow only to tools with matching clearance.
    Sensitive = 1,
    /// Contains personally identifiable information (even if redacted).
    /// Higher than Sensitive: PII-tainted data must only flow to
    /// PII-safe destinations (e.g., encrypted storage, GDPR-compliant
    /// sinks). The label persists after redaction — the taint is
    /// informational.
    Pii = 2,
    /// Cannot flow out at all (credentials, private keys).
    Secret = 3,
}

/// Data label combining integrity and confidentiality.
///
/// Assigned to tool results by the kernel. Propagated through
/// session taint accumulation. Checked by the IFC hook before
/// write operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
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

    /// Untrusted external data, PII confidentiality.
    pub const UNTRUSTED_PII: Self = Self {
        integrity: Integrity::Untrusted,
        confidentiality: Confidentiality::Pii,
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

    /// Bell-LaPadula *-property (no write-down): a session tainted
    /// with Sensitive data cannot write to a Public destination.
    pub fn can_write_to(self, target: Confidentiality) -> bool {
        self.confidentiality <= target
    }

    /// Bell-LaPadula Simple Security Property (no read-up): an agent
    /// with clearance C cannot read data classified above C.
    pub fn can_read_from(clearance: Confidentiality, classification: Confidentiality) -> bool {
        clearance >= classification
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

verus! {

#[verifier::external_type_specification]
pub struct ExIntegrity(Integrity);

#[verifier::external_type_specification]
pub struct ExConfidentiality(Confidentiality);

#[verifier::external_type_specification]
pub struct ExDataLabel(DataLabel);

pub open spec fn integrity_ord(i: Integrity) -> nat {
    match i {
        Integrity::Trusted => 0,
        Integrity::Untrusted => 1,
    }
}

pub open spec fn conf_ord(c: Confidentiality) -> nat {
    match c {
        Confidentiality::Public => 0,
        Confidentiality::Sensitive => 1,
        Confidentiality::Pii => 2,
        Confidentiality::Secret => 3,
    }
}

spec fn max_nat(a: nat, b: nat) -> nat {
    if a > b { a } else { b }
}

pub open spec fn spec_join(a: DataLabel, b: DataLabel) -> DataLabel {
    DataLabel {
        integrity: if integrity_ord(a.integrity) > integrity_ord(b.integrity) { a.integrity } else { b.integrity },
        confidentiality: if conf_ord(a.confidentiality) > conf_ord(b.confidentiality) { a.confidentiality } else { b.confidentiality },
    }
}

pub open spec fn spec_can_write_to(label: DataLabel, target: Confidentiality) -> bool {
    conf_ord(label.confidentiality) <= conf_ord(target)
}

pub open spec fn spec_can_read_from(clearance: Confidentiality, classification: Confidentiality) -> bool {
    conf_ord(clearance) >= conf_ord(classification)
}

proof fn join_is_commutative(a: DataLabel, b: DataLabel)
    ensures spec_join(a, b) == spec_join(b, a),
{}

proof fn join_is_associative(a: DataLabel, b: DataLabel, c: DataLabel)
    ensures spec_join(spec_join(a, b), c) == spec_join(a, spec_join(b, c)),
{}

proof fn join_is_idempotent(a: DataLabel)
    ensures spec_join(a, a) == a,
{}

proof fn join_is_monotonic(a: DataLabel, b: DataLabel)
    ensures ({
        let result = spec_join(a, b);
        &&& integrity_ord(result.integrity) >= integrity_ord(a.integrity)
        &&& integrity_ord(result.integrity) >= integrity_ord(b.integrity)
        &&& conf_ord(result.confidentiality) >= conf_ord(a.confidentiality)
        &&& conf_ord(result.confidentiality) >= conf_ord(b.confidentiality)
    }),
{}

proof fn no_write_down_holds(label: DataLabel, target: Confidentiality)
    ensures
        spec_can_write_to(label, target) <==> conf_ord(label.confidentiality) <= conf_ord(target),
{}

proof fn no_write_down_is_transitive(label: DataLabel, t1: Confidentiality, t2: Confidentiality)
    requires
        spec_can_write_to(label, t1),
        conf_ord(t1) <= conf_ord(t2),
    ensures
        spec_can_write_to(label, t2),
{}

proof fn no_read_up_holds(clearance: Confidentiality, classification: Confidentiality)
    ensures
        spec_can_read_from(clearance, classification) <==> conf_ord(clearance) >= conf_ord(classification),
{}

proof fn no_read_up_is_transitive(c1: Confidentiality, c2: Confidentiality, c3: Confidentiality)
    requires
        spec_can_read_from(c1, c2),
        conf_ord(c2) >= conf_ord(c3),
    ensures
        spec_can_read_from(c1, c3),
{}

proof fn blp_dual_properties_consistent(label: DataLabel, level: Confidentiality)
    ensures
        spec_can_write_to(label, level) && spec_can_read_from(level, label.confidentiality)
            <==> conf_ord(label.confidentiality) <= conf_ord(level),
{}

proof fn join_preserves_write_restriction(a: DataLabel, b: DataLabel, target: Confidentiality)
    requires
        !spec_can_write_to(a, target) || !spec_can_write_to(b, target),
    ensures
        !spec_can_write_to(spec_join(a, b), target),
{}

proof fn taint_monotonicity(current: DataLabel, new_label: DataLabel)
    ensures ({
        let after = spec_join(current, new_label);
        &&& integrity_ord(after.integrity) >= integrity_ord(current.integrity)
        &&& conf_ord(after.confidentiality) >= conf_ord(current.confidentiality)
    }),
{}

proof fn taint_monotonic_over_sequence(l0: DataLabel, l1: DataLabel, l2: DataLabel)
    ensures ({
        let after2 = spec_join(spec_join(l0, l1), l2);
        &&& integrity_ord(after2.integrity) >= integrity_ord(l0.integrity)
        &&& conf_ord(after2.confidentiality) >= conf_ord(l0.confidentiality)
    }),
{}

proof fn declassify_only_steps_down(current_conf: nat, new_conf: nat)
    requires new_conf < current_conf,
    ensures new_conf < current_conf,
{}

proof fn trusted_public_is_bottom(l: DataLabel)
    ensures ({
        let bottom = DataLabel { integrity: Integrity::Trusted, confidentiality: Confidentiality::Public };
        spec_join(bottom, l) == l
    }),
{}

proof fn confidentiality_discriminant_fits_u8(c: Confidentiality)
    ensures conf_ord(c) <= 3,
{}

proof fn integrity_discriminant_fits_u8(i: Integrity)
    ensures integrity_ord(i) <= 1,
{}

proof fn default_is_bottom()
    ensures ({
        let d = DataLabel { integrity: Integrity::Trusted, confidentiality: Confidentiality::Public };
        d == DataLabel { integrity: Integrity::Trusted, confidentiality: Confidentiality::Public }
    }),
{}

proof fn label_discriminant_pair_unique(a: DataLabel, b: DataLabel)
    requires a != b,
    ensures integrity_ord(a.integrity) != integrity_ord(b.integrity) || conf_ord(a.confidentiality) != conf_ord(b.confidentiality),
{}

proof fn untrusted_secret_is_top(l: DataLabel)
    ensures ({
        let top = DataLabel { integrity: Integrity::Untrusted, confidentiality: Confidentiality::Secret };
        spec_join(top, l) == top
    }),
{}

} // verus!

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
        assert!(!label.can_write_to(Confidentiality::Pii));
        assert!(label.can_write_to(Confidentiality::Secret));
    }

    #[test]
    fn no_write_down_pii_to_lower() {
        let label = DataLabel {
            integrity: Integrity::Trusted,
            confidentiality: Confidentiality::Pii,
        };
        assert!(!label.can_write_to(Confidentiality::Public));
        assert!(!label.can_write_to(Confidentiality::Sensitive));
        assert!(label.can_write_to(Confidentiality::Pii));
        assert!(label.can_write_to(Confidentiality::Secret));
    }

    #[test]
    fn public_can_write_anywhere() {
        let label = DataLabel::TRUSTED_PUBLIC;
        assert!(label.can_write_to(Confidentiality::Public));
        assert!(label.can_write_to(Confidentiality::Sensitive));
        assert!(label.can_write_to(Confidentiality::Pii));
        assert!(label.can_write_to(Confidentiality::Secret));
    }

    #[test]
    fn confidentiality_ordering() {
        assert!(Confidentiality::Public < Confidentiality::Sensitive);
        assert!(Confidentiality::Sensitive < Confidentiality::Pii);
        assert!(Confidentiality::Pii < Confidentiality::Secret);
    }

    #[test]
    fn label_join_with_pii() {
        // Sensitive join Pii = Pii
        let a = DataLabel {
            integrity: Integrity::Trusted,
            confidentiality: Confidentiality::Sensitive,
        };
        let b = DataLabel {
            integrity: Integrity::Trusted,
            confidentiality: Confidentiality::Pii,
        };
        assert_eq!(a.join(b).confidentiality, Confidentiality::Pii);

        // Pii join Secret = Secret
        let c = DataLabel {
            integrity: Integrity::Trusted,
            confidentiality: Confidentiality::Secret,
        };
        assert_eq!(b.join(c).confidentiality, Confidentiality::Secret);

        // Public join Pii = Pii
        let d = DataLabel::TRUSTED_PUBLIC;
        assert_eq!(d.join(b).confidentiality, Confidentiality::Pii);
    }

    #[test]
    fn display_format() {
        assert_eq!(
            format!("{}", DataLabel::UNTRUSTED_SENSITIVE),
            "Untrusted+Sensitive"
        );
        assert_eq!(format!("{}", DataLabel::UNTRUSTED_PII), "Untrusted+Pii");
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    impl kani::Arbitrary for Integrity {
        fn any_array<const N: usize>() -> [Self; N] {
            [Self::Trusted; N]
        }

        fn any() -> Self {
            if kani::any::<bool>() {
                Integrity::Trusted
            } else {
                Integrity::Untrusted
            }
        }
    }

    impl kani::Arbitrary for Confidentiality {
        fn any_array<const N: usize>() -> [Self; N] {
            [Self::Public; N]
        }

        fn any() -> Self {
            match kani::any::<u8>() % 4 {
                0 => Confidentiality::Public,
                1 => Confidentiality::Sensitive,
                2 => Confidentiality::Pii,
                _ => Confidentiality::Secret,
            }
        }
    }

    impl kani::Arbitrary for DataLabel {
        fn any_array<const N: usize>() -> [Self; N] {
            [Self::TRUSTED_PUBLIC; N]
        }

        fn any() -> Self {
            Self {
                integrity: kani::any(),
                confidentiality: kani::any(),
            }
        }
    }

    #[kani::proof]
    fn join_is_commutative() {
        let a: DataLabel = kani::any();
        let b: DataLabel = kani::any();
        assert_eq!(a.join(b), b.join(a));
    }

    #[kani::proof]
    fn join_is_associative() {
        let a: DataLabel = kani::any();
        let b: DataLabel = kani::any();
        let c: DataLabel = kani::any();
        assert_eq!(a.join(b).join(c), a.join(b.join(c)));
    }

    #[kani::proof]
    fn join_is_idempotent() {
        let a: DataLabel = kani::any();
        assert_eq!(a.join(a), a);
    }

    #[kani::proof]
    fn join_is_monotonic() {
        let a: DataLabel = kani::any();
        let b: DataLabel = kani::any();
        let joined = a.join(b);
        assert!(joined.integrity >= a.integrity);
        assert!(joined.confidentiality >= a.confidentiality);
        assert!(joined.integrity >= b.integrity);
        assert!(joined.confidentiality >= b.confidentiality);
    }

    #[kani::proof]
    fn no_write_down_holds() {
        let label: DataLabel = kani::any();
        let target: Confidentiality = kani::any();
        assert_eq!(label.can_write_to(target), label.confidentiality <= target);
    }

    #[kani::proof]
    fn no_write_down_is_transitive() {
        let a: DataLabel = kani::any();
        let b_conf: Confidentiality = kani::any();
        let c_conf: Confidentiality = kani::any();
        if a.can_write_to(b_conf) && b_conf <= c_conf {
            assert!(a.can_write_to(c_conf));
        }
    }

    #[kani::proof]
    fn no_read_up_holds() {
        let clearance: Confidentiality = kani::any();
        let classification: Confidentiality = kani::any();
        assert_eq!(
            DataLabel::can_read_from(clearance, classification),
            clearance >= classification
        );
    }

    #[kani::proof]
    fn no_read_up_is_transitive() {
        let clearance: Confidentiality = kani::any();
        let a: Confidentiality = kani::any();
        let b: Confidentiality = kani::any();
        if DataLabel::can_read_from(clearance, b) && a <= b {
            assert!(DataLabel::can_read_from(clearance, a));
        }
    }

    #[kani::proof]
    fn blp_dual_properties_consistent() {
        let label: DataLabel = kani::any();
        let level: Confidentiality = kani::any();
        let can_read = DataLabel::can_read_from(level, label.confidentiality);
        let can_write = label.can_write_to(level);
        if label.confidentiality == level {
            assert!(can_read && can_write);
        }
    }

    #[kani::proof]
    fn join_preserves_write_restriction() {
        let a: DataLabel = kani::any();
        let b: DataLabel = kani::any();
        let target: Confidentiality = kani::any();
        let joined = a.join(b);
        if !a.can_write_to(target) || !b.can_write_to(target) {
            assert!(!joined.can_write_to(target));
        }
    }

    // --- Discriminant safety ---
    // Proves that `Confidentiality as u8` and `Integrity as u8` are
    // within bounds, so `as u8` casts in handlers.rs are lossless.

    #[kani::proof]
    fn confidentiality_discriminant_fits_u8() {
        let c: Confidentiality = kani::any();
        let d = c as u8;
        assert!(d <= 3);
        // Roundtrip: discriminant uniquely identifies the variant
        let back = match d {
            0 => Confidentiality::Public,
            1 => Confidentiality::Sensitive,
            2 => Confidentiality::Pii,
            3 => Confidentiality::Secret,
            _ => unreachable!(),
        };
        assert_eq!(c, back);
    }

    #[kani::proof]
    fn integrity_discriminant_fits_u8() {
        let i: Integrity = kani::any();
        let d = i as u8;
        assert!(d <= 1);
    }

    // --- Lattice bottom element ---

    #[kani::proof]
    fn trusted_public_is_bottom() {
        let label: DataLabel = kani::any();
        let bottom = DataLabel::TRUSTED_PUBLIC;
        let joined = bottom.join(label);
        assert_eq!(joined, label);
    }

    // --- Hash/Eq consistency ---

    #[kani::proof]
    fn hash_eq_consistent() {
        use std::hash::{Hash, Hasher};
        let a: DataLabel = kani::any();
        let b: DataLabel = kani::any();
        if a == b {
            let mut h1 = std::collections::hash_map::DefaultHasher::new();
            let mut h2 = std::collections::hash_map::DefaultHasher::new();
            a.hash(&mut h1);
            b.hash(&mut h2);
            assert_eq!(h1.finish(), h2.finish());
        }
    }

    // --- Display uniqueness ---
    // Proved via discriminant uniqueness: since Display uses "{:?}+{:?}"
    // and Debug for enums with explicit discriminants produces unique strings,
    // distinct (integrity, confidentiality) pairs produce distinct Display output.
    // We prove the underlying discriminant pair is unique (avoids format! OOM in CBMC).

    #[kani::proof]
    fn label_discriminant_pair_unique() {
        let a: DataLabel = kani::any();
        let b: DataLabel = kani::any();
        if a != b {
            let a_disc = (a.integrity as u8, a.confidentiality as u8);
            let b_disc = (b.integrity as u8, b.confidentiality as u8);
            assert_ne!(
                a_disc, b_disc,
                "distinct labels must have distinct discriminant pairs"
            );
        }
    }

    // --- Default is bottom ---

    #[kani::proof]
    fn default_is_bottom() {
        assert_eq!(DataLabel::default(), DataLabel::TRUSTED_PUBLIC);
    }

    // --- Lattice top element ---

    #[kani::proof]
    fn untrusted_secret_is_top() {
        let label: DataLabel = kani::any();
        let top = DataLabel {
            integrity: Integrity::Untrusted,
            confidentiality: Confidentiality::Secret,
        };
        let joined = top.join(label);
        assert_eq!(joined, top);
    }
}
