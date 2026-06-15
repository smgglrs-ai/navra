/// Data confidentiality level for IFC (Information Flow Control).
///
/// Ordered by sensitivity: `Public < Sensitive < Pii < Secret`.
/// Used by [`Declassification`](crate::Declassification) to recommend
/// label step-downs after PII filtering.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Confidentiality {
    /// Can appear in any tool output or external message.
    Public = 0,
    /// Can flow only to tools with matching clearance.
    Sensitive = 1,
    /// Contains personally identifiable information (even if redacted).
    Pii = 2,
    /// Cannot flow out at all (credentials, private keys).
    Secret = 3,
}
