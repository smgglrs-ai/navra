use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Category prefixes for pseudonym generation.
///
/// Maps finding categories to human-readable prefixes used in
/// pseudonyms: "person" → "Person_A", "location" → "Location_A", etc.
fn category_prefix(category: &str) -> &str {
    match category {
        "person" => "Person",
        "location" => "Location",
        "organization" => "Organization",
        "email" => "Email",
        "phone" | "phone-eu" => "Phone",
        "ssn" | "nir" => "ID",
        "credit-card" | "iban" => "Account",
        "ip-address" => "Address",
        "username" => "User",
        "demographic" => "Demographic",
        "misc-entity" => "Entity",
        _ => "Item",
    }
}

/// Convert a counter (0-based) to a letter suffix: 0→A, 1→B, ..., 25→Z, 26→AA, etc.
fn counter_to_suffix(n: usize) -> String {
    if n < 26 {
        return String::from((b'A' + n as u8) as char);
    }
    let mut result = String::new();
    let mut remaining = n;
    loop {
        result.insert(0, (b'A' + (remaining % 26) as u8) as char);
        if remaining < 26 {
            break;
        }
        remaining = remaining / 26 - 1;
    }
    result
}

/// Maintains a consistent mapping of real values to pseudonyms within a session.
///
/// Thread-safe: can be shared across concurrent filter invocations.
/// Each category maintains its own counter so pseudonyms are scoped:
/// "Jean Dupont" → "Person_A", "Paris" → "Location_A".
#[derive(Clone)]
pub struct PseudonymMap {
    /// real_value → pseudonym
    mapping: Arc<RwLock<HashMap<String, String>>>,
    /// category_prefix → next counter value
    counters: Arc<RwLock<HashMap<String, usize>>>,
}

impl PseudonymMap {
    pub fn new() -> Self {
        Self {
            mapping: Arc::new(RwLock::new(HashMap::new())),
            counters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Returns the existing pseudonym for `real_value`, or creates a new one.
    ///
    /// The pseudonym format is `{Prefix}_{Letter}` where the prefix is
    /// derived from the finding category and the letter increments per
    /// category (A, B, C, ..., Z, AA, AB, ...).
    pub fn get_or_create(&self, real_value: &str, category: &str) -> String {
        // Fast path: check read lock first
        {
            let map = self.mapping.read().unwrap();
            if let Some(pseudo) = map.get(real_value) {
                return pseudo.clone();
            }
        }

        // Slow path: acquire write lock and insert
        let mut map = self.mapping.write().unwrap();
        // Double-check after acquiring write lock
        if let Some(pseudo) = map.get(real_value) {
            return pseudo.clone();
        }

        let prefix = category_prefix(category);
        let mut counters = self.counters.write().unwrap();
        let counter = counters.entry(prefix.to_string()).or_insert(0);
        let suffix = counter_to_suffix(*counter);
        *counter += 1;

        let pseudonym = format!("{}_{}", prefix, suffix);
        map.insert(real_value.to_string(), pseudonym.clone());
        pseudonym
    }

    /// Extract a reverser for authorized de-pseudonymization.
    ///
    /// The reverser is a separate object that should only be passed to
    /// GDPR audit tools, not to the agent process. This separation
    /// ensures the forward-mapping process (agent) cannot de-pseudonymize
    /// without explicit authorization (GDPR Article 32).
    pub fn extract_reverser(&self) -> PseudonymReverser {
        let map = self.mapping.read().unwrap();
        let reverse = map.iter()
            .map(|(real, pseudo)| (pseudo.clone(), real.clone()))
            .collect();
        PseudonymReverser { reverse }
    }

}

/// Separate holder for the de-pseudonymization mapping.
///
/// Must be held in a different security context than PseudonymMap.
/// Only authorized consumers (GDPR data subject access tools) should
/// receive this object.
pub struct PseudonymReverser {
    reverse: HashMap<String, String>,
}

impl PseudonymReverser {
    /// Look up the real value for a pseudonym.
    pub fn resolve(&self, pseudonym: &str) -> Option<&str> {
        self.reverse.get(pseudonym).map(|s| s.as_str())
    }

    /// Returns the full reverse mapping.
    pub fn into_map(self) -> HashMap<String, String> {
        self.reverse
    }
}

impl Default for PseudonymMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_name_gets_same_pseudonym() {
        let map = PseudonymMap::new();
        let first = map.get_or_create("Jean Dupont", "person");
        let second = map.get_or_create("Jean Dupont", "person");
        assert_eq!(first, second);
        assert_eq!(first, "Person_A");
    }

    #[test]
    fn different_names_get_different_pseudonyms() {
        let map = PseudonymMap::new();
        let a = map.get_or_create("Jean Dupont", "person");
        let b = map.get_or_create("Marie Curie", "person");
        assert_ne!(a, b);
        assert_eq!(a, "Person_A");
        assert_eq!(b, "Person_B");
    }

    #[test]
    fn different_categories_get_different_prefixes() {
        let map = PseudonymMap::new();
        let person = map.get_or_create("Jean Dupont", "person");
        let location = map.get_or_create("Paris", "location");
        assert_eq!(person, "Person_A");
        assert_eq!(location, "Location_A");
    }

    #[test]
    fn reverser_resolves_pseudonyms() {
        let map = PseudonymMap::new();
        map.get_or_create("Jean Dupont", "person");
        map.get_or_create("Paris", "location");
        let reverser = map.extract_reverser();
        assert_eq!(reverser.resolve("Person_A"), Some("Jean Dupont"));
        assert_eq!(reverser.resolve("Location_A"), Some("Paris"));
        assert_eq!(reverser.resolve("Unknown_X"), None);
    }

    #[test]
    fn counter_suffix_letters() {
        assert_eq!(counter_to_suffix(0), "A");
        assert_eq!(counter_to_suffix(1), "B");
        assert_eq!(counter_to_suffix(25), "Z");
        assert_eq!(counter_to_suffix(26), "AA");
        assert_eq!(counter_to_suffix(27), "AB");
    }

    #[test]
    fn unknown_category_uses_item_prefix() {
        let map = PseudonymMap::new();
        let pseudo = map.get_or_create("secret-thing", "custom-category");
        assert_eq!(pseudo, "Item_A");
    }

    #[test]
    fn clone_shares_state() {
        let map = PseudonymMap::new();
        let cloned = map.clone();
        map.get_or_create("Jean Dupont", "person");
        let pseudo = cloned.get_or_create("Jean Dupont", "person");
        assert_eq!(pseudo, "Person_A");
    }
}
