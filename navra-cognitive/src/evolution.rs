//! Persona evolution via momentum-based trait adaptation.
//!
//! Personas accumulate interaction-derived traits over time rather than
//! staying static YAML. After each session, observed behavioral signals
//! update a trait vector with exponential moving average.

use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::path::Path;

use crate::error::CognitiveError;

/// Trait vector for a persona — behavioral scores that evolve over time.
///
/// Each trait is a named score in \[0.0, 1.0\] that influences prompt
/// assembly. Traits are updated via exponential moving average after
/// each session based on observed behavioral signals.
#[derive(Debug, Clone)]
pub struct TraitVector {
    /// Persona this vector belongs to.
    pub persona_name: String,
    /// Per-user evolution (different users may shape the same persona differently).
    pub user_id: String,
    /// Behavioral trait scores, e.g. "verbosity": 0.7, "formality": 0.3.
    pub traits: HashMap<String, f64>,
    /// Number of updates applied to this vector.
    pub update_count: u32,
    /// If true, no more updates are applied.
    pub frozen: bool,
}

impl TraitVector {
    /// Create a new trait vector with empty traits.
    pub fn new(persona_name: &str, user_id: &str) -> Self {
        Self {
            persona_name: persona_name.to_string(),
            user_id: user_id.to_string(),
            traits: HashMap::new(),
            update_count: 0,
            frozen: false,
        }
    }

    /// Momentum update: trait_new = alpha * observed + (1 - alpha) * trait_old.
    ///
    /// Alpha controls adaptation speed: small values (0.1) converge
    /// slowly, large values (1.0) jump immediately to observed values.
    /// Values are clamped to \[0.0, 1.0\].
    ///
    /// Does nothing if the vector is frozen.
    pub fn update(&mut self, observed: &HashMap<String, f64>, alpha: f64) {
        if self.frozen {
            return;
        }
        let alpha = alpha.clamp(0.0, 1.0);
        for (key, &obs) in observed {
            let obs = obs.clamp(0.0, 1.0);
            let old = self.traits.get(key).copied().unwrap_or(0.5);
            let new_val = alpha * obs + (1.0 - alpha) * old;
            self.traits.insert(key.clone(), new_val);
        }
        self.update_count += 1;
    }

    /// Reset to defaults (empty traits, zero update count).
    pub fn reset(&mut self) {
        self.traits.clear();
        self.update_count = 0;
        self.frozen = false;
    }

    /// Freeze — no more updates will be applied.
    pub fn freeze(&mut self) {
        self.frozen = true;
    }

    /// Generate a prompt modifier based on trait values.
    ///
    /// Maps trait scores to natural-language instructions. Only traits
    /// that deviate from the neutral midpoint (0.5) produce modifiers.
    pub fn prompt_modifier(&self) -> String {
        if self.traits.is_empty() {
            return String::new();
        }

        let mut modifiers = Vec::new();
        for (trait_name, &value) in &self.traits {
            let modifier = match trait_name.as_str() {
                "verbosity" if value > 0.7 => Some("Be detailed and thorough in explanations."),
                "verbosity" if value < 0.3 => Some("Be concise and brief."),
                "formality" if value > 0.7 => Some("Use formal, professional language."),
                "formality" if value < 0.3 => Some("Use casual, conversational tone."),
                "technical_depth" if value > 0.7 => {
                    Some("Include technical details and implementation specifics.")
                }
                "technical_depth" if value < 0.3 => {
                    Some("Keep explanations high-level and accessible.")
                }
                "caution" if value > 0.7 => Some("Emphasize risks, caveats, and edge cases."),
                "caution" if value < 0.3 => {
                    Some("Focus on the happy path and practical solutions.")
                }
                "creativity" if value > 0.7 => {
                    Some("Suggest creative and unconventional approaches.")
                }
                "creativity" if value < 0.3 => {
                    Some("Stick to established patterns and conventions.")
                }
                _ => None,
            };
            if let Some(m) = modifier {
                modifiers.push(m.to_string());
            }
        }

        modifiers.join(" ")
    }
}

/// Persistent store for trait vectors, backed by SQLite.
pub struct TraitStore {
    db: Connection,
}

impl TraitStore {
    /// Open a trait store at the given path, creating tables if needed.
    pub fn open(path: &Path) -> Result<Self, CognitiveError> {
        let db = Connection::open(path)
            .map_err(|e| CognitiveError::Io(std::io::Error::other(e.to_string())))?;
        let store = Self { db };
        store.init_schema()?;
        Ok(store)
    }

    /// Open an in-memory trait store (for testing).
    pub fn open_memory() -> Result<Self, CognitiveError> {
        let db = Connection::open_in_memory()
            .map_err(|e| CognitiveError::Io(std::io::Error::other(e.to_string())))?;
        let store = Self { db };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<(), CognitiveError> {
        self.db
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS trait_vectors (
                    persona_name TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    traits_json TEXT NOT NULL DEFAULT '{}',
                    update_count INTEGER NOT NULL DEFAULT 0,
                    frozen INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (persona_name, user_id)
                );",
            )
            .map_err(|e| CognitiveError::Io(std::io::Error::other(e.to_string())))?;
        Ok(())
    }

    /// Load a trait vector for a specific persona and user.
    pub fn load(&self, persona: &str, user: &str) -> Option<TraitVector> {
        let result = self.db.query_row(
            "SELECT traits_json, update_count, frozen
             FROM trait_vectors
             WHERE persona_name = ?1 AND user_id = ?2",
            params![persona, user],
            |row| {
                let traits_json: String = row.get(0)?;
                let update_count: u32 = row.get(1)?;
                let frozen: bool = row.get(2)?;
                Ok((traits_json, update_count, frozen))
            },
        );

        match result {
            Ok((traits_json, update_count, frozen)) => {
                let traits: HashMap<String, f64> =
                    serde_json::from_str(&traits_json).unwrap_or_default();
                Some(TraitVector {
                    persona_name: persona.to_string(),
                    user_id: user.to_string(),
                    traits,
                    update_count,
                    frozen,
                })
            }
            Err(_) => None,
        }
    }

    /// Save a trait vector, upserting by (persona_name, user_id).
    pub fn save(&self, vector: &TraitVector) -> Result<(), CognitiveError> {
        let traits_json =
            serde_json::to_string(&vector.traits).unwrap_or_else(|_| "{}".to_string());
        self.db
            .execute(
                "INSERT INTO trait_vectors (persona_name, user_id, traits_json, update_count, frozen)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(persona_name, user_id) DO UPDATE SET
                     traits_json = excluded.traits_json,
                     update_count = excluded.update_count,
                     frozen = excluded.frozen",
                params![
                    vector.persona_name,
                    vector.user_id,
                    traits_json,
                    vector.update_count,
                    vector.frozen,
                ],
            )
            .map_err(|e| {
                CognitiveError::Io(std::io::Error::other(e.to_string()))
            })?;
        Ok(())
    }

    /// List all trait vectors for a given persona (across all users).
    pub fn list(&self, persona: &str) -> Vec<TraitVector> {
        let mut stmt = match self.db.prepare(
            "SELECT user_id, traits_json, update_count, frozen
             FROM trait_vectors
             WHERE persona_name = ?1",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = stmt.query_map(params![persona], |row| {
            let user_id: String = row.get(0)?;
            let traits_json: String = row.get(1)?;
            let update_count: u32 = row.get(2)?;
            let frozen: bool = row.get(3)?;
            Ok((user_id, traits_json, update_count, frozen))
        });

        match rows {
            Ok(iter) => iter
                .filter_map(|r| r.ok())
                .map(|(user_id, traits_json, update_count, frozen)| {
                    let traits: HashMap<String, f64> =
                        serde_json::from_str(&traits_json).unwrap_or_default();
                    TraitVector {
                        persona_name: persona.to_string(),
                        user_id,
                        traits,
                        update_count,
                        frozen,
                    }
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_slow_convergence() {
        let mut tv = TraitVector::new("dev", "user1");
        let observed: HashMap<String, f64> = [("verbosity".to_string(), 1.0)].into_iter().collect();

        // With alpha=0.1, first update: 0.1 * 1.0 + 0.9 * 0.5 = 0.55
        tv.update(&observed, 0.1);
        let v = tv.traits["verbosity"];
        assert!((v - 0.55).abs() < 1e-9, "expected 0.55, got {v}");

        // Second update: 0.1 * 1.0 + 0.9 * 0.55 = 0.595
        tv.update(&observed, 0.1);
        let v = tv.traits["verbosity"];
        assert!((v - 0.595).abs() < 1e-9, "expected 0.595, got {v}");

        assert_eq!(tv.update_count, 2);
    }

    #[test]
    fn update_immediate_jump() {
        let mut tv = TraitVector::new("dev", "user1");
        let observed: HashMap<String, f64> = [("formality".to_string(), 0.8)].into_iter().collect();

        // With alpha=1.0, jumps immediately: 1.0 * 0.8 + 0.0 * 0.5 = 0.8
        tv.update(&observed, 1.0);
        let v = tv.traits["formality"];
        assert!((v - 0.8).abs() < 1e-9, "expected 0.8, got {v}");

        assert_eq!(tv.update_count, 1);
    }

    #[test]
    fn freeze_prevents_updates() {
        let mut tv = TraitVector::new("dev", "user1");
        let observed: HashMap<String, f64> = [("verbosity".to_string(), 1.0)].into_iter().collect();

        tv.update(&observed, 0.5);
        assert_eq!(tv.update_count, 1);

        tv.freeze();
        tv.update(&observed, 0.5);
        // Update count should not change
        assert_eq!(tv.update_count, 1);
        // Value should not change (was 0.5 * 1.0 + 0.5 * 0.5 = 0.75)
        let v = tv.traits["verbosity"];
        assert!((v - 0.75).abs() < 1e-9);
    }

    #[test]
    fn reset_clears_traits() {
        let mut tv = TraitVector::new("dev", "user1");
        let observed: HashMap<String, f64> = [("verbosity".to_string(), 0.9)].into_iter().collect();

        tv.update(&observed, 0.5);
        tv.freeze();
        assert!(!tv.traits.is_empty());
        assert!(tv.frozen);

        tv.reset();
        assert!(tv.traits.is_empty());
        assert_eq!(tv.update_count, 0);
        assert!(!tv.frozen);
    }

    #[test]
    fn prompt_modifier_non_empty_for_extreme_traits() {
        let mut tv = TraitVector::new("dev", "user1");
        tv.traits.insert("verbosity".to_string(), 0.9);
        tv.traits.insert("formality".to_string(), 0.1);

        let modifier = tv.prompt_modifier();
        assert!(!modifier.is_empty());
        assert!(modifier.contains("detailed"));
        assert!(modifier.contains("casual"));
    }

    #[test]
    fn prompt_modifier_empty_for_neutral_traits() {
        let mut tv = TraitVector::new("dev", "user1");
        tv.traits.insert("verbosity".to_string(), 0.5);
        tv.traits.insert("formality".to_string(), 0.5);

        let modifier = tv.prompt_modifier();
        assert!(modifier.is_empty());
    }

    #[test]
    fn prompt_modifier_empty_for_no_traits() {
        let tv = TraitVector::new("dev", "user1");
        let modifier = tv.prompt_modifier();
        assert!(modifier.is_empty());
    }

    #[test]
    fn trait_store_save_load_roundtrip() {
        let store = TraitStore::open_memory().unwrap();
        let mut tv = TraitVector::new("analyst", "alice");
        tv.traits.insert("verbosity".to_string(), 0.7);
        tv.traits.insert("formality".to_string(), 0.3);
        tv.update_count = 5;

        store.save(&tv).unwrap();

        let loaded = store.load("analyst", "alice").unwrap();
        assert_eq!(loaded.persona_name, "analyst");
        assert_eq!(loaded.user_id, "alice");
        assert!((loaded.traits["verbosity"] - 0.7).abs() < 1e-9);
        assert!((loaded.traits["formality"] - 0.3).abs() < 1e-9);
        assert_eq!(loaded.update_count, 5);
        assert!(!loaded.frozen);
    }

    #[test]
    fn trait_store_save_frozen() {
        let store = TraitStore::open_memory().unwrap();
        let mut tv = TraitVector::new("dev", "bob");
        tv.freeze();

        store.save(&tv).unwrap();
        let loaded = store.load("dev", "bob").unwrap();
        assert!(loaded.frozen);
    }

    #[test]
    fn trait_store_upsert() {
        let store = TraitStore::open_memory().unwrap();
        let mut tv = TraitVector::new("dev", "alice");
        tv.traits.insert("verbosity".to_string(), 0.5);
        store.save(&tv).unwrap();

        tv.traits.insert("verbosity".to_string(), 0.9);
        tv.update_count = 10;
        store.save(&tv).unwrap();

        let loaded = store.load("dev", "alice").unwrap();
        assert!((loaded.traits["verbosity"] - 0.9).abs() < 1e-9);
        assert_eq!(loaded.update_count, 10);
    }

    #[test]
    fn trait_store_list() {
        let store = TraitStore::open_memory().unwrap();

        store.save(&TraitVector::new("analyst", "alice")).unwrap();
        store.save(&TraitVector::new("analyst", "bob")).unwrap();
        store.save(&TraitVector::new("developer", "alice")).unwrap();

        let analysts = store.list("analyst");
        assert_eq!(analysts.len(), 2);

        let developers = store.list("developer");
        assert_eq!(developers.len(), 1);

        let none = store.list("nonexistent");
        assert!(none.is_empty());
    }

    #[test]
    fn trait_store_load_nonexistent() {
        let store = TraitStore::open_memory().unwrap();
        assert!(store.load("nope", "nobody").is_none());
    }
}
