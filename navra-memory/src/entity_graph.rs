//! Lightweight entity-relationship graph backed by SQLite.
//!
//! Stores (entity1, relation, entity2) triples with optional temporal
//! validity (valid_from, valid_until). Supports 1-2 hop traversal
//! queries without requiring a full graph database.

use crate::error::MemoryError;
use rusqlite::{params, Connection};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Relationship {
    pub id: i64,
    pub entity1: String,
    pub relation: String,
    pub entity2: String,
    pub valid_from: Option<i64>,
    pub valid_until: Option<i64>,
    pub confidence: f64,
    pub source: Option<String>,
}

pub struct EntityGraph {
    db: Connection,
}

impl EntityGraph {
    pub fn open(path: &Path) -> Result<Self, MemoryError> {
        let db = Connection::open(path)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
        let graph = Self { db };
        graph.init_schema()?;
        Ok(graph)
    }

    pub fn open_memory() -> Result<Self, MemoryError> {
        let db = Connection::open_in_memory()?;
        let graph = Self { db };
        graph.init_schema()?;
        Ok(graph)
    }

    fn init_schema(&self) -> Result<(), MemoryError> {
        self.db.execute_batch(
            "CREATE TABLE IF NOT EXISTS entity_relations (
                id          INTEGER PRIMARY KEY,
                entity1     TEXT NOT NULL,
                relation    TEXT NOT NULL,
                entity2     TEXT NOT NULL,
                valid_from  INTEGER,
                valid_until INTEGER,
                confidence  REAL NOT NULL DEFAULT 1.0,
                source      TEXT,
                created_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            );
            CREATE INDEX IF NOT EXISTS idx_er_e1 ON entity_relations(entity1);
            CREATE INDEX IF NOT EXISTS idx_er_e2 ON entity_relations(entity2);
            CREATE INDEX IF NOT EXISTS idx_er_rel ON entity_relations(relation);
            CREATE INDEX IF NOT EXISTS idx_er_e1_rel ON entity_relations(entity1, relation);",
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add(
        &self,
        entity1: &str,
        relation: &str,
        entity2: &str,
        valid_from: Option<i64>,
        valid_until: Option<i64>,
        confidence: f64,
        source: Option<&str>,
    ) -> Result<i64, MemoryError> {
        self.db.execute(
            "INSERT INTO entity_relations (entity1, relation, entity2, valid_from, valid_until, confidence, source)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![entity1, relation, entity2, valid_from, valid_until, confidence, source],
        )?;
        Ok(self.db.last_insert_rowid())
    }

    pub fn remove(&self, id: i64) -> Result<bool, MemoryError> {
        let changed = self
            .db
            .execute("DELETE FROM entity_relations WHERE id = ?1", params![id])?;
        Ok(changed > 0)
    }

    pub fn expire(&self, id: i64, until: i64) -> Result<bool, MemoryError> {
        let changed = self.db.execute(
            "UPDATE entity_relations SET valid_until = ?1 WHERE id = ?2",
            params![until, id],
        )?;
        Ok(changed > 0)
    }

    pub fn relations_of(&self, entity: &str) -> Result<Vec<Relationship>, MemoryError> {
        let mut stmt = self.db.prepare(
            "SELECT id, entity1, relation, entity2, valid_from, valid_until, confidence, source
             FROM entity_relations
             WHERE entity1 = ?1 OR entity2 = ?1
             ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(params![entity], |row| {
            Ok(Relationship {
                id: row.get(0)?,
                entity1: row.get(1)?,
                relation: row.get(2)?,
                entity2: row.get(3)?,
                valid_from: row.get(4)?,
                valid_until: row.get(5)?,
                confidence: row.get(6)?,
                source: row.get(7)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(MemoryError::from)
    }

    pub fn relations_of_active(
        &self,
        entity: &str,
        at_time: i64,
    ) -> Result<Vec<Relationship>, MemoryError> {
        let mut stmt = self.db.prepare(
            "SELECT id, entity1, relation, entity2, valid_from, valid_until, confidence, source
             FROM entity_relations
             WHERE (entity1 = ?1 OR entity2 = ?1)
               AND (valid_from IS NULL OR valid_from <= ?2)
               AND (valid_until IS NULL OR valid_until > ?2)
             ORDER BY confidence DESC",
        )?;
        let rows = stmt.query_map(params![entity, at_time], |row| {
            Ok(Relationship {
                id: row.get(0)?,
                entity1: row.get(1)?,
                relation: row.get(2)?,
                entity2: row.get(3)?,
                valid_from: row.get(4)?,
                valid_until: row.get(5)?,
                confidence: row.get(6)?,
                source: row.get(7)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(MemoryError::from)
    }

    pub fn find(
        &self,
        entity1: Option<&str>,
        relation: Option<&str>,
        entity2: Option<&str>,
    ) -> Result<Vec<Relationship>, MemoryError> {
        let mut conditions = Vec::new();
        let mut values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut idx = 1;

        if let Some(e1) = entity1 {
            conditions.push(format!("entity1 = ?{idx}"));
            values.push(Box::new(e1.to_string()));
            idx += 1;
        }
        if let Some(r) = relation {
            conditions.push(format!("relation = ?{idx}"));
            values.push(Box::new(r.to_string()));
            idx += 1;
        }
        if let Some(e2) = entity2 {
            conditions.push(format!("entity2 = ?{idx}"));
            values.push(Box::new(e2.to_string()));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let sql = format!(
            "SELECT id, entity1, relation, entity2, valid_from, valid_until, confidence, source
             FROM entity_relations
             {where_clause}
             ORDER BY created_at DESC
             LIMIT 100"
        );

        let mut stmt = self.db.prepare(&sql)?;
        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            values.iter().map(|v| v.as_ref()).collect();
        let rows = stmt.query_map(params_ref.as_slice(), |row| {
            Ok(Relationship {
                id: row.get(0)?,
                entity1: row.get(1)?,
                relation: row.get(2)?,
                entity2: row.get(3)?,
                valid_from: row.get(4)?,
                valid_until: row.get(5)?,
                confidence: row.get(6)?,
                source: row.get(7)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(MemoryError::from)
    }

    /// 2-hop traversal: find entities reachable from `start` within 2 hops.
    ///
    /// Returns pairs of (hop1_relation, intermediate_entity, hop2_relation, target_entity).
    pub fn traverse_2hop(
        &self,
        start: &str,
    ) -> Result<Vec<(String, String, String, String)>, MemoryError> {
        let mut stmt = self.db.prepare(
            "SELECT r1.relation, r1.entity2, r2.relation, r2.entity2
             FROM entity_relations r1
             JOIN entity_relations r2 ON r1.entity2 = r2.entity1
             WHERE r1.entity1 = ?1
               AND r2.entity2 != ?1
               AND (r1.valid_until IS NULL OR r1.valid_until > strftime('%s', 'now'))
               AND (r2.valid_until IS NULL OR r2.valid_until > strftime('%s', 'now'))
             LIMIT 200",
        )?;
        let rows = stmt.query_map(params![start], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(MemoryError::from)
    }

    pub fn count(&self) -> Result<usize, MemoryError> {
        let count: i64 = self
            .db
            .query_row("SELECT COUNT(*) FROM entity_relations", [], |row| {
                row.get(0)
            })?;
        Ok(count as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_graph() -> EntityGraph {
        EntityGraph::open_memory().unwrap()
    }

    #[test]
    fn add_and_query() {
        let g = test_graph();
        g.add("Alice", "works_at", "Acme", None, None, 1.0, None)
            .unwrap();

        let rels = g.relations_of("Alice").unwrap();
        assert_eq!(rels.len(), 1);
        assert_eq!(rels[0].entity1, "Alice");
        assert_eq!(rels[0].relation, "works_at");
        assert_eq!(rels[0].entity2, "Acme");
    }

    #[test]
    fn bidirectional_lookup() {
        let g = test_graph();
        g.add("Alice", "works_at", "Acme", None, None, 1.0, None)
            .unwrap();

        let from_acme = g.relations_of("Acme").unwrap();
        assert_eq!(from_acme.len(), 1);
        assert_eq!(from_acme[0].entity1, "Alice");
    }

    #[test]
    fn temporal_validity() {
        let g = test_graph();
        g.add("Alice", "works_at", "Acme", Some(100), Some(200), 1.0, None)
            .unwrap();
        g.add("Alice", "works_at", "Beta", Some(200), None, 1.0, None)
            .unwrap();

        let at_150 = g.relations_of_active("Alice", 150).unwrap();
        assert_eq!(at_150.len(), 1);
        assert_eq!(at_150[0].entity2, "Acme");

        let at_250 = g.relations_of_active("Alice", 250).unwrap();
        assert_eq!(at_250.len(), 1);
        assert_eq!(at_250[0].entity2, "Beta");
    }

    #[test]
    fn find_by_relation() {
        let g = test_graph();
        g.add("Alice", "knows", "Bob", None, None, 1.0, None)
            .unwrap();
        g.add("Alice", "works_at", "Acme", None, None, 1.0, None)
            .unwrap();
        g.add("Bob", "knows", "Carol", None, None, 1.0, None)
            .unwrap();

        let knows = g.find(None, Some("knows"), None).unwrap();
        assert_eq!(knows.len(), 2);
    }

    #[test]
    fn find_specific_triple() {
        let g = test_graph();
        g.add("Alice", "knows", "Bob", None, None, 0.9, None)
            .unwrap();
        g.add("Alice", "knows", "Carol", None, None, 0.8, None)
            .unwrap();

        let result = g.find(Some("Alice"), Some("knows"), Some("Bob")).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].entity2, "Bob");
    }

    #[test]
    fn two_hop_traversal() {
        let g = test_graph();
        g.add("Alice", "works_at", "Acme", None, None, 1.0, None)
            .unwrap();
        g.add("Acme", "located_in", "Paris", None, None, 1.0, None)
            .unwrap();
        g.add("Acme", "industry", "Tech", None, None, 1.0, None)
            .unwrap();

        let hops = g.traverse_2hop("Alice").unwrap();
        assert_eq!(hops.len(), 2);

        let targets: Vec<&str> = hops.iter().map(|(_, _, _, t)| t.as_str()).collect();
        assert!(targets.contains(&"Paris"));
        assert!(targets.contains(&"Tech"));
    }

    #[test]
    fn remove_relationship() {
        let g = test_graph();
        let id = g
            .add("Alice", "knows", "Bob", None, None, 1.0, None)
            .unwrap();

        assert!(g.remove(id).unwrap());
        assert_eq!(g.relations_of("Alice").unwrap().len(), 0);
    }

    #[test]
    fn expire_relationship() {
        let g = test_graph();
        let id = g
            .add("Alice", "works_at", "Acme", Some(100), None, 1.0, None)
            .unwrap();

        g.expire(id, 200).unwrap();

        let at_250 = g.relations_of_active("Alice", 250).unwrap();
        assert_eq!(at_250.len(), 0);

        let at_150 = g.relations_of_active("Alice", 150).unwrap();
        assert_eq!(at_150.len(), 1);
    }

    #[test]
    fn count() {
        let g = test_graph();
        assert_eq!(g.count().unwrap(), 0);

        g.add("A", "r", "B", None, None, 1.0, None).unwrap();
        g.add("B", "r", "C", None, None, 1.0, None).unwrap();
        assert_eq!(g.count().unwrap(), 2);
    }

    #[test]
    fn confidence_ordering() {
        let g = test_graph();
        g.add("Alice", "knows", "Bob", None, None, 0.5, None)
            .unwrap();
        g.add("Alice", "knows", "Carol", None, None, 0.9, None)
            .unwrap();

        let active = g.relations_of_active("Alice", 0).unwrap();
        assert_eq!(active[0].entity2, "Carol");
        assert_eq!(active[1].entity2, "Bob");
    }

    #[test]
    fn source_tracking() {
        let g = test_graph();
        g.add(
            "Alice",
            "works_at",
            "Acme",
            None,
            None,
            1.0,
            Some("session-123"),
        )
        .unwrap();

        let rels = g.relations_of("Alice").unwrap();
        assert_eq!(rels[0].source.as_deref(), Some("session-123"));
    }
}
