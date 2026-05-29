//! Hierarchical temporal tree index on SQLite (MemForest architecture).
//!
//! Three tree types — session, entity, scene — share a single table
//! with a `tree_type` discriminator. Each tree has a root (depth=0)
//! and leaf facts (depth=1). Internal nodes mark themselves dirty
//! when children change; an external summarizer calls `update_summary`
//! to regenerate roll-ups.

use crate::error::MemoryError;
use rusqlite::{params, Connection};
use std::fmt;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeType {
    Session,
    Entity,
    Scene,
}

impl fmt::Display for TreeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Session => "session",
            Self::Entity => "entity",
            Self::Scene => "scene",
        })
    }
}

impl FromStr for TreeType {
    type Err = MemoryError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "session" => Ok(Self::Session),
            "entity" => Ok(Self::Entity),
            "scene" => Ok(Self::Scene),
            _ => Err(MemoryError::InvalidType(s.into())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TreeNode {
    pub id: i64,
    pub tree_type: TreeType,
    pub tree_name: String,
    pub parent_id: Option<i64>,
    pub depth: i32,
    pub time_start: i64,
    pub time_end: i64,
    pub content: String,
    pub dirty: bool,
}

pub struct TemporalTree {
    db: Connection,
}

impl TemporalTree {
    pub fn open(path: &Path) -> Result<Self, MemoryError> {
        let db = Connection::open(path)?;
        Self::initialize_schema(&db)?;
        Ok(Self { db })
    }

    pub fn open_memory() -> Result<Self, MemoryError> {
        let db = Connection::open_in_memory()?;
        Self::initialize_schema(&db)?;
        Ok(Self { db })
    }

    fn initialize_schema(db: &Connection) -> Result<(), MemoryError> {
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS memory_tree (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tree_type TEXT NOT NULL,
                tree_name TEXT NOT NULL,
                parent_id INTEGER REFERENCES memory_tree(id),
                depth INTEGER NOT NULL,
                time_start INTEGER NOT NULL,
                time_end INTEGER NOT NULL,
                content TEXT NOT NULL,
                dirty INTEGER NOT NULL DEFAULT 0,
                UNIQUE(tree_type, tree_name, time_start, time_end, depth)
            );
            CREATE INDEX IF NOT EXISTS idx_memory_tree_lookup
                ON memory_tree(tree_type, tree_name, depth);
            CREATE INDEX IF NOT EXISTS idx_memory_tree_dirty
                ON memory_tree(tree_type, tree_name, dirty) WHERE dirty = 1;",
        )?;
        Ok(())
    }

    /// Insert a leaf fact into a tree. Creates the root if the tree
    /// doesn't exist yet. Marks the root as dirty.
    pub fn insert_fact(
        &self,
        tree_type: TreeType,
        tree_name: &str,
        content: &str,
        timestamp: i64,
    ) -> Result<i64, MemoryError> {
        let tt = tree_type.to_string();

        // Find or create the root node (depth=0).
        let root_id: i64 = match self.db.query_row(
            "SELECT id FROM memory_tree WHERE tree_type = ?1 AND tree_name = ?2 AND depth = 0",
            params![tt, tree_name],
            |row| row.get(0),
        ) {
            Ok(id) => id,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                self.db.execute(
                    "INSERT INTO memory_tree (tree_type, tree_name, parent_id, depth, time_start, time_end, content, dirty)
                     VALUES (?1, ?2, NULL, 0, ?3, ?4, '', 0)",
                    params![tt, tree_name, timestamp, timestamp],
                )?;
                self.db.last_insert_rowid()
            }
            Err(e) => return Err(e.into()),
        };

        // Insert the leaf (depth=1).
        self.db.execute(
            "INSERT INTO memory_tree (tree_type, tree_name, parent_id, depth, time_start, time_end, content, dirty)
             VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, 0)",
            params![tt, tree_name, root_id, timestamp, timestamp, content],
        )?;
        let leaf_id = self.db.last_insert_rowid();

        // Expand root's time range to cover this timestamp and mark dirty.
        self.db.execute(
            "UPDATE memory_tree SET
                time_start = MIN(time_start, ?1),
                time_end = MAX(time_end, ?2),
                dirty = 1
             WHERE id = ?3",
            params![timestamp, timestamp, root_id],
        )?;

        Ok(leaf_id)
    }

    /// Get all dirty nodes that need summary regeneration.
    pub fn dirty_nodes(
        &self,
        tree_type: TreeType,
        tree_name: &str,
    ) -> Result<Vec<TreeNode>, MemoryError> {
        let tt = tree_type.to_string();
        let mut stmt = self.db.prepare(
            "SELECT id, tree_type, tree_name, parent_id, depth, time_start, time_end, content, dirty
             FROM memory_tree
             WHERE tree_type = ?1 AND tree_name = ?2 AND dirty = 1
             ORDER BY depth ASC",
        )?;
        let nodes = stmt
            .query_map(params![tt, tree_name], row_to_node)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(nodes)
    }

    /// Update a node's summary and clear its dirty flag.
    pub fn update_summary(&self, node_id: i64, summary: &str) -> Result<(), MemoryError> {
        self.db.execute(
            "UPDATE memory_tree SET content = ?1, dirty = 0 WHERE id = ?2",
            params![summary, node_id],
        )?;
        Ok(())
    }

    /// Phase 1: Forest Recall — search root summaries using LIKE.
    pub fn search_roots(
        &self,
        tree_type: TreeType,
        query: &str,
        limit: usize,
    ) -> Result<Vec<TreeNode>, MemoryError> {
        let tt = tree_type.to_string();
        let pattern = format!("%{query}%");
        let mut stmt = self.db.prepare(
            "SELECT id, tree_type, tree_name, parent_id, depth, time_start, time_end, content, dirty
             FROM memory_tree
             WHERE tree_type = ?1 AND depth = 0 AND content LIKE ?2
             ORDER BY time_end DESC
             LIMIT ?3",
        )?;
        let nodes = stmt
            .query_map(params![tt, pattern, limit as i64], row_to_node)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(nodes)
    }

    /// Phase 2: Tree Browse — return all nodes in a tree, ordered by
    /// depth then time_start.
    pub fn browse_tree(
        &self,
        tree_type: TreeType,
        tree_name: &str,
    ) -> Result<Vec<TreeNode>, MemoryError> {
        let tt = tree_type.to_string();
        let mut stmt = self.db.prepare(
            "SELECT id, tree_type, tree_name, parent_id, depth, time_start, time_end, content, dirty
             FROM memory_tree
             WHERE tree_type = ?1 AND tree_name = ?2
             ORDER BY depth ASC, time_start ASC",
        )?;
        let nodes = stmt
            .query_map(params![tt, tree_name], row_to_node)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(nodes)
    }

    /// Get all leaf nodes in a time range.
    pub fn leaves_in_range(
        &self,
        tree_type: TreeType,
        tree_name: &str,
        start: i64,
        end: i64,
    ) -> Result<Vec<TreeNode>, MemoryError> {
        let tt = tree_type.to_string();
        let mut stmt = self.db.prepare(
            "SELECT id, tree_type, tree_name, parent_id, depth, time_start, time_end, content, dirty
             FROM memory_tree
             WHERE tree_type = ?1 AND tree_name = ?2 AND depth = 1
                   AND time_start >= ?3 AND time_end <= ?4
             ORDER BY time_start ASC",
        )?;
        let nodes = stmt
            .query_map(params![tt, tree_name, start, end], row_to_node)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(nodes)
    }

    /// List all tree names of a given type.
    pub fn list_trees(&self, tree_type: TreeType) -> Result<Vec<String>, MemoryError> {
        let tt = tree_type.to_string();
        let mut stmt = self.db.prepare(
            "SELECT DISTINCT tree_name FROM memory_tree
             WHERE tree_type = ?1 AND depth = 0
             ORDER BY tree_name ASC",
        )?;
        let names = stmt
            .query_map(params![tt], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        Ok(names)
    }

    /// Count total nodes across all trees.
    pub fn count(&self) -> Result<usize, MemoryError> {
        let count: i64 = self
            .db
            .query_row("SELECT COUNT(*) FROM memory_tree", [], |row| row.get(0))?;
        Ok(count as usize)
    }
}

fn row_to_node(row: &rusqlite::Row<'_>) -> rusqlite::Result<TreeNode> {
    let tt_str: String = row.get(1)?;
    let tree_type = TreeType::from_str(&tt_str).unwrap_or(TreeType::Session);
    let dirty_int: i32 = row.get(8)?;
    Ok(TreeNode {
        id: row.get(0)?,
        tree_type,
        tree_name: row.get(2)?,
        parent_id: row.get(3)?,
        depth: row.get(4)?,
        time_start: row.get(5)?,
        time_end: row.get(6)?,
        content: row.get(7)?,
        dirty: dirty_int != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_fact_creates_tree() {
        let tree = TemporalTree::open_memory().unwrap();
        let leaf_id = tree
            .insert_fact(TreeType::Session, "sess-1", "user said hello", 1000)
            .unwrap();
        assert!(leaf_id > 0);

        let nodes = tree.browse_tree(TreeType::Session, "sess-1").unwrap();
        assert_eq!(nodes.len(), 2); // root + leaf
        assert_eq!(nodes[0].depth, 0); // root
        assert_eq!(nodes[1].depth, 1); // leaf
        assert_eq!(nodes[1].content, "user said hello");
    }

    #[test]
    fn insert_fact_marks_root_dirty() {
        let tree = TemporalTree::open_memory().unwrap();
        tree.insert_fact(TreeType::Session, "sess-1", "fact one", 1000)
            .unwrap();

        let nodes = tree.browse_tree(TreeType::Session, "sess-1").unwrap();
        let root = &nodes[0];
        assert_eq!(root.depth, 0);
        assert!(root.dirty);
    }

    #[test]
    fn update_summary_clears_dirty() {
        let tree = TemporalTree::open_memory().unwrap();
        tree.insert_fact(TreeType::Session, "sess-1", "fact", 1000)
            .unwrap();

        let dirty = tree.dirty_nodes(TreeType::Session, "sess-1").unwrap();
        assert_eq!(dirty.len(), 1);
        let root_id = dirty[0].id;

        tree.update_summary(root_id, "summary of facts").unwrap();

        let dirty = tree.dirty_nodes(TreeType::Session, "sess-1").unwrap();
        assert!(dirty.is_empty());

        let nodes = tree.browse_tree(TreeType::Session, "sess-1").unwrap();
        assert_eq!(nodes[0].content, "summary of facts");
        assert!(!nodes[0].dirty);
    }

    #[test]
    fn multiple_facts_same_tree() {
        let tree = TemporalTree::open_memory().unwrap();
        tree.insert_fact(TreeType::Session, "sess-1", "fact one", 1000)
            .unwrap();
        tree.insert_fact(TreeType::Session, "sess-1", "fact two", 2000)
            .unwrap();
        tree.insert_fact(TreeType::Session, "sess-1", "fact three", 3000)
            .unwrap();

        let nodes = tree.browse_tree(TreeType::Session, "sess-1").unwrap();
        assert_eq!(nodes.len(), 4); // 1 root + 3 leaves

        let root = &nodes[0];
        assert_eq!(root.time_start, 1000);
        assert_eq!(root.time_end, 3000);
    }

    #[test]
    fn separate_trees_by_name() {
        let tree = TemporalTree::open_memory().unwrap();
        tree.insert_fact(TreeType::Session, "sess-1", "in session one", 1000)
            .unwrap();
        tree.insert_fact(TreeType::Session, "sess-2", "in session two", 2000)
            .unwrap();

        let nodes1 = tree.browse_tree(TreeType::Session, "sess-1").unwrap();
        let nodes2 = tree.browse_tree(TreeType::Session, "sess-2").unwrap();
        assert_eq!(nodes1.len(), 2);
        assert_eq!(nodes2.len(), 2);
        assert_eq!(nodes1[1].content, "in session one");
        assert_eq!(nodes2[1].content, "in session two");
    }

    #[test]
    fn separate_trees_by_type() {
        let tree = TemporalTree::open_memory().unwrap();
        tree.insert_fact(TreeType::Session, "alpha", "session fact", 1000)
            .unwrap();
        tree.insert_fact(TreeType::Entity, "alpha", "entity fact", 2000)
            .unwrap();

        let session_nodes = tree.browse_tree(TreeType::Session, "alpha").unwrap();
        let entity_nodes = tree.browse_tree(TreeType::Entity, "alpha").unwrap();
        assert_eq!(session_nodes.len(), 2);
        assert_eq!(entity_nodes.len(), 2);
        assert_eq!(session_nodes[1].content, "session fact");
        assert_eq!(entity_nodes[1].content, "entity fact");
    }

    #[test]
    fn search_roots_finds_matching() {
        let tree = TemporalTree::open_memory().unwrap();
        tree.insert_fact(TreeType::Entity, "rust-lang", "ownership rules", 1000)
            .unwrap();
        tree.insert_fact(TreeType::Entity, "python", "dynamic typing", 2000)
            .unwrap();

        // Update root summaries
        let dirty = tree.dirty_nodes(TreeType::Entity, "rust-lang").unwrap();
        tree.update_summary(dirty[0].id, "Rust programming language concepts")
            .unwrap();
        let dirty = tree.dirty_nodes(TreeType::Entity, "python").unwrap();
        tree.update_summary(dirty[0].id, "Python programming basics")
            .unwrap();

        let results = tree.search_roots(TreeType::Entity, "Rust", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].tree_name, "rust-lang");
    }

    #[test]
    fn search_roots_no_match() {
        let tree = TemporalTree::open_memory().unwrap();
        tree.insert_fact(TreeType::Entity, "rust-lang", "ownership", 1000)
            .unwrap();
        let dirty = tree.dirty_nodes(TreeType::Entity, "rust-lang").unwrap();
        tree.update_summary(dirty[0].id, "Rust language").unwrap();

        let results = tree
            .search_roots(TreeType::Entity, "JavaScript", 10)
            .unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn browse_tree_returns_hierarchy() {
        let tree = TemporalTree::open_memory().unwrap();
        tree.insert_fact(TreeType::Scene, "meeting-1", "alice joined", 1000)
            .unwrap();
        tree.insert_fact(TreeType::Scene, "meeting-1", "bob joined", 2000)
            .unwrap();

        let nodes = tree.browse_tree(TreeType::Scene, "meeting-1").unwrap();
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].depth, 0);
        assert_eq!(nodes[1].depth, 1);
        assert_eq!(nodes[2].depth, 1);
        assert!(nodes[1].time_start <= nodes[2].time_start);
    }

    #[test]
    fn leaves_in_range_filters() {
        let tree = TemporalTree::open_memory().unwrap();
        tree.insert_fact(TreeType::Session, "s1", "early", 100)
            .unwrap();
        tree.insert_fact(TreeType::Session, "s1", "middle", 500)
            .unwrap();
        tree.insert_fact(TreeType::Session, "s1", "late", 900)
            .unwrap();

        let range = tree
            .leaves_in_range(TreeType::Session, "s1", 200, 600)
            .unwrap();
        assert_eq!(range.len(), 1);
        assert_eq!(range[0].content, "middle");
    }

    #[test]
    fn list_trees_returns_names() {
        let tree = TemporalTree::open_memory().unwrap();
        tree.insert_fact(TreeType::Session, "alpha", "a", 100)
            .unwrap();
        tree.insert_fact(TreeType::Session, "beta", "b", 200)
            .unwrap();
        tree.insert_fact(TreeType::Session, "gamma", "c", 300)
            .unwrap();

        let names = tree.list_trees(TreeType::Session).unwrap();
        assert_eq!(names, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn count_tracks_total() {
        let tree = TemporalTree::open_memory().unwrap();
        assert_eq!(tree.count().unwrap(), 0);

        tree.insert_fact(TreeType::Session, "s1", "fact1", 100)
            .unwrap();
        assert_eq!(tree.count().unwrap(), 2); // root + leaf

        tree.insert_fact(TreeType::Entity, "e1", "fact2", 200)
            .unwrap();
        assert_eq!(tree.count().unwrap(), 4); // 2 roots + 2 leaves

        tree.insert_fact(TreeType::Session, "s1", "fact3", 300)
            .unwrap();
        assert_eq!(tree.count().unwrap(), 5); // 2 roots + 3 leaves
    }
}
