//! Hierarchical temporal tree index on SQLite (MemForest architecture).
//!
//! Three tree types — session, entity, scene — share a single table
//! with a `tree_type` discriminator. The tree has configurable depth:
//! root (depth=0) → intermediate nodes → leaves (max depth). Internal
//! nodes mark themselves dirty when children change; an external
//! summarizer calls `update_summary` to regenerate roll-ups.
//!
//! When an intermediate node accumulates more than `max_children`
//! leaves, new inserts create a deeper level — the tree grows
//! downward automatically.

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
    max_children: usize,
}

impl TemporalTree {
    pub fn open(path: &Path) -> Result<Self, MemoryError> {
        let db = Connection::open(path)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
        Self::initialize_schema(&db)?;
        Ok(Self {
            db,
            max_children: 64,
        })
    }

    pub fn open_memory() -> Result<Self, MemoryError> {
        let db = Connection::open_in_memory()?;
        Self::initialize_schema(&db)?;
        Ok(Self {
            db,
            max_children: 64,
        })
    }

    pub fn with_max_children(mut self, n: usize) -> Self {
        self.max_children = n.max(2);
        self
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
                is_leaf INTEGER NOT NULL DEFAULT 1,
                child_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_memory_tree_lookup
                ON memory_tree(tree_type, tree_name, depth);
            CREATE INDEX IF NOT EXISTS idx_memory_tree_dirty
                ON memory_tree(tree_type, tree_name, dirty) WHERE dirty = 1;
            CREATE INDEX IF NOT EXISTS idx_memory_tree_leaves
                ON memory_tree(tree_type, tree_name, is_leaf, time_start) WHERE is_leaf = 1;",
        )?;
        Ok(())
    }

    /// Insert a leaf fact into a tree. Creates intermediate levels
    /// when a parent exceeds `max_children`. Marks the ancestor path
    /// dirty up to the root.
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
                    "INSERT INTO memory_tree (tree_type, tree_name, parent_id, depth, time_start, time_end, content, dirty, is_leaf)
                     VALUES (?1, ?2, NULL, 0, ?3, ?4, '', 0, 0)",
                    params![tt, tree_name, timestamp, timestamp],
                )?;
                self.db.last_insert_rowid()
            }
            Err(e) => return Err(e.into()),
        };

        // Walk down from root to find the best parent for this leaf.
        let parent_id = self.find_insert_parent(&tt, tree_name, root_id, timestamp)?;

        // Get parent's current depth to compute leaf depth.
        let parent_depth: i32 = self.db.query_row(
            "SELECT depth FROM memory_tree WHERE id = ?1",
            params![parent_id],
            |row| row.get(0),
        )?;

        // Insert the leaf.
        self.db.execute(
            "INSERT INTO memory_tree (tree_type, tree_name, parent_id, depth, time_start, time_end, content, dirty, is_leaf)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 1)",
            params![tt, tree_name, parent_id, parent_depth + 1, timestamp, timestamp, content],
        )?;
        let leaf_id = self.db.last_insert_rowid();

        // Update parent: mark non-leaf, increment child count.
        self.db.execute(
            "UPDATE memory_tree SET is_leaf = 0, child_count = child_count + 1 WHERE id = ?1",
            params![parent_id],
        )?;

        // Mark ancestor path dirty and expand time ranges.
        self.mark_ancestors_dirty(parent_id, timestamp)?;

        Ok(leaf_id)
    }

    /// Batch-insert multiple facts in a single transaction. Defers
    /// ancestor dirty-marking to the end — one pass instead of N walks.
    pub fn insert_facts(
        &self,
        tree_type: TreeType,
        tree_name: &str,
        facts: &[(&str, i64)], // (content, timestamp)
    ) -> Result<Vec<i64>, MemoryError> {
        if facts.is_empty() {
            return Ok(vec![]);
        }

        let tx = self.db.unchecked_transaction()?;
        let tt = tree_type.to_string();

        // Find or create root.
        let root_id: i64 = match tx.query_row(
            "SELECT id FROM memory_tree WHERE tree_type = ?1 AND tree_name = ?2 AND depth = 0",
            params![tt, tree_name],
            |row| row.get(0),
        ) {
            Ok(id) => id,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                let min_ts = facts.iter().map(|(_, t)| *t).min().unwrap();
                let max_ts = facts.iter().map(|(_, t)| *t).max().unwrap();
                tx.execute(
                    "INSERT INTO memory_tree (tree_type, tree_name, parent_id, depth, time_start, time_end, content, dirty, is_leaf, child_count)
                     VALUES (?1, ?2, NULL, 0, ?3, ?4, '', 0, 0, 0)",
                    params![tt, tree_name, min_ts, max_ts],
                )?;
                tx.last_insert_rowid()
            }
            Err(e) => return Err(e.into()),
        };

        let mut leaf_ids = Vec::with_capacity(facts.len());
        let mut time_min = i64::MAX;
        let mut time_max = i64::MIN;

        // Cache parent lookup: for sequential timestamps hitting the
        // same parent, reuse it instead of re-querying.
        let mut cached_parent: Option<(i64, i32, i64)> = None; // (id, depth, child_count)

        for &(content, timestamp) in facts {
            time_min = time_min.min(timestamp);
            time_max = time_max.max(timestamp);

            // Try cached parent first.
            let parent_id = if let Some((pid, _pdepth, ref mut count)) = cached_parent {
                if (*count as usize) < self.max_children {
                    *count += 1;
                    pid
                } else {
                    cached_parent = None;
                    self.find_insert_parent_tx(&tx, &tt, tree_name, root_id, timestamp)?
                }
            } else {
                self.find_insert_parent_tx(&tx, &tt, tree_name, root_id, timestamp)?
            };

            let parent_depth: i32 = if let Some((pid, pdepth, _)) = cached_parent {
                if pid == parent_id {
                    pdepth
                } else {
                    tx.query_row(
                        "SELECT depth FROM memory_tree WHERE id = ?1",
                        params![parent_id],
                        |row| row.get(0),
                    )?
                }
            } else {
                tx.query_row(
                    "SELECT depth FROM memory_tree WHERE id = ?1",
                    params![parent_id],
                    |row| row.get(0),
                )?
            };

            tx.execute(
                "INSERT INTO memory_tree (tree_type, tree_name, parent_id, depth, time_start, time_end, content, dirty, is_leaf, child_count)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 1, 0)",
                params![tt, tree_name, parent_id, parent_depth + 1, timestamp, timestamp, content],
            )?;
            leaf_ids.push(tx.last_insert_rowid());

            tx.execute(
                "UPDATE memory_tree SET is_leaf = 0, child_count = child_count + 1 WHERE id = ?1",
                params![parent_id],
            )?;

            // Update cache.
            if cached_parent.as_ref().map(|(pid, _, _)| *pid) != Some(parent_id) {
                let cc: i64 = tx.query_row(
                    "SELECT child_count FROM memory_tree WHERE id = ?1",
                    params![parent_id],
                    |row| row.get(0),
                )?;
                cached_parent = Some((parent_id, parent_depth, cc));
            }
        }

        // Batch-mark all ancestors dirty + expand root time range.
        tx.execute(
            "UPDATE memory_tree SET dirty = 1,
                time_start = MIN(time_start, ?1),
                time_end = MAX(time_end, ?2)
             WHERE tree_type = ?3 AND tree_name = ?4 AND is_leaf = 0",
            params![time_min, time_max, tt, tree_name],
        )?;

        tx.commit()?;
        Ok(leaf_ids)
    }

    /// Like find_insert_parent but takes a transaction reference.
    fn find_insert_parent_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        tt: &str,
        tree_name: &str,
        root_id: i64,
        timestamp: i64,
    ) -> Result<i64, MemoryError> {
        let mut current_id = root_id;
        loop {
            let child_count: i64 = tx.query_row(
                "SELECT child_count FROM memory_tree WHERE id = ?1",
                params![current_id],
                |row| row.get(0),
            )?;

            if (child_count as usize) < self.max_children {
                return Ok(current_id);
            }

            let existing_child: Option<i64> = tx
                .query_row(
                    "SELECT id FROM memory_tree
                     WHERE parent_id = ?1 AND time_start <= ?2 AND time_end >= ?3
                           AND is_leaf = 0
                     ORDER BY time_start ASC LIMIT 1",
                    params![current_id, timestamp, timestamp],
                    |row| row.get(0),
                )
                .ok();

            if let Some(child_id) = existing_child {
                current_id = child_id;
                continue;
            }

            let current_depth: i32 = tx.query_row(
                "SELECT depth FROM memory_tree WHERE id = ?1",
                params![current_id],
                |row| row.get(0),
            )?;

            tx.execute(
                "INSERT INTO memory_tree (tree_type, tree_name, parent_id, depth, time_start, time_end, content, dirty, is_leaf, child_count)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, '', 1, 0, 0)",
                params![tt, tree_name, current_id, current_depth + 1, timestamp, timestamp],
            )?;
            tx.execute(
                "UPDATE memory_tree SET child_count = child_count + 1 WHERE id = ?1",
                params![current_id],
            )?;
            return Ok(tx.last_insert_rowid());
        }
    }

    /// Find the best parent node for a new leaf at the given timestamp.
    /// If the deepest eligible parent has too many children, create an
    /// intermediate node to split the load.
    fn find_insert_parent(
        &self,
        tt: &str,
        tree_name: &str,
        root_id: i64,
        timestamp: i64,
    ) -> Result<i64, MemoryError> {
        let mut current_id = root_id;

        loop {
            // Read cached child count.
            let child_count: i64 = self.db.query_row(
                "SELECT child_count FROM memory_tree WHERE id = ?1",
                params![current_id],
                |row| row.get(0),
            )?;

            if (child_count as usize) < self.max_children {
                return Ok(current_id);
            }

            // Too many children — find an existing intermediate child
            // whose time range covers this timestamp.
            let existing_child: Option<i64> = self
                .db
                .query_row(
                    "SELECT id FROM memory_tree
                     WHERE parent_id = ?1 AND time_start <= ?2 AND time_end >= ?3
                           AND id NOT IN (
                               SELECT id FROM memory_tree
                               WHERE parent_id = ?1 AND depth = (
                                   SELECT MAX(depth) FROM memory_tree WHERE tree_type = ?4 AND tree_name = ?5
                               )
                           )
                     ORDER BY time_start ASC LIMIT 1",
                    params![current_id, timestamp, timestamp, tt, tree_name],
                    |row| row.get(0),
                )
                .ok();

            if let Some(child_id) = existing_child {
                current_id = child_id;
                continue;
            }

            // No suitable intermediate child — create one.
            let current_depth: i32 = self.db.query_row(
                "SELECT depth FROM memory_tree WHERE id = ?1",
                params![current_id],
                |row| row.get(0),
            )?;

            self.db.execute(
                "INSERT INTO memory_tree (tree_type, tree_name, parent_id, depth, time_start, time_end, content, dirty, is_leaf, child_count)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, '', 1, 0, 0)",
                params![tt, tree_name, current_id, current_depth + 1, timestamp, timestamp],
            )?;
            // Increment parent's child count for the new intermediate.
            self.db.execute(
                "UPDATE memory_tree SET child_count = child_count + 1 WHERE id = ?1",
                params![current_id],
            )?;
            return Ok(self.db.last_insert_rowid());
        }
    }

    /// Walk up from a node to the root, marking each ancestor dirty
    /// and expanding its time range.
    fn mark_ancestors_dirty(&self, mut node_id: i64, timestamp: i64) -> Result<(), MemoryError> {
        loop {
            self.db.execute(
                "UPDATE memory_tree SET
                    time_start = MIN(time_start, ?1),
                    time_end = MAX(time_end, ?2),
                    dirty = 1
                 WHERE id = ?3",
                params![timestamp, timestamp, node_id],
            )?;

            let parent: Option<i64> = self
                .db
                .query_row(
                    "SELECT parent_id FROM memory_tree WHERE id = ?1",
                    params![node_id],
                    |row| row.get(0),
                )
                .ok()
                .flatten();

            match parent {
                Some(pid) => node_id = pid,
                None => break,
            }
        }
        Ok(())
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

    /// Get all leaf nodes in a time range. Leaves are nodes with no
    /// children (works at any depth).
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
             WHERE tree_type = ?1 AND tree_name = ?2
                   AND time_start >= ?3 AND time_end <= ?4
                   AND is_leaf = 1
             ORDER BY time_start ASC",
        )?;
        let nodes = stmt
            .query_map(params![tt, tree_name, start, end], row_to_node)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(nodes)
    }

    /// Get the maximum depth in a tree (0 = root only).
    pub fn max_depth(&self, tree_type: TreeType, tree_name: &str) -> Result<i32, MemoryError> {
        let tt = tree_type.to_string();
        let depth: i32 = self.db.query_row(
            "SELECT COALESCE(MAX(depth), 0) FROM memory_tree WHERE tree_type = ?1 AND tree_name = ?2",
            params![tt, tree_name],
            |row| row.get(0),
        )?;
        Ok(depth)
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
    fn intermediate_levels_created_when_full() {
        let tree = TemporalTree::open_memory().unwrap().with_max_children(4);
        for i in 0..10 {
            tree.insert_fact(
                TreeType::Session,
                "s1",
                &format!("fact {i}"),
                1000 + i * 100,
            )
            .unwrap();
        }
        let depth = tree.max_depth(TreeType::Session, "s1").unwrap();
        assert!(
            depth >= 2,
            "expected depth >= 2 with 10 facts and max_children=4, got {depth}"
        );

        let nodes = tree.browse_tree(TreeType::Session, "s1").unwrap();
        let intermediates: Vec<_> = nodes
            .iter()
            .filter(|n| n.depth > 0 && n.depth < depth)
            .collect();
        assert!(!intermediates.is_empty(), "expected intermediate nodes");
    }

    #[test]
    fn dirty_path_marks_all_ancestors() {
        let tree = TemporalTree::open_memory().unwrap().with_max_children(3);
        for i in 0..9 {
            tree.insert_fact(
                TreeType::Session,
                "s1",
                &format!("fact {i}"),
                1000 + i * 100,
            )
            .unwrap();
        }
        let dirty = tree.dirty_nodes(TreeType::Session, "s1").unwrap();
        let dirty_depths: Vec<i32> = dirty.iter().map(|n| n.depth).collect();
        assert!(dirty_depths.contains(&0), "root should be dirty");
    }

    #[test]
    fn leaves_in_range_works_with_deep_tree() {
        let tree = TemporalTree::open_memory().unwrap().with_max_children(3);
        for i in 0..12 {
            tree.insert_fact(
                TreeType::Session,
                "s1",
                &format!("fact {i}"),
                1000 + i * 100,
            )
            .unwrap();
        }
        let leaves = tree
            .leaves_in_range(TreeType::Session, "s1", 1500, 1800)
            .unwrap();
        assert!(!leaves.is_empty());
        for leaf in &leaves {
            assert!(leaf.time_start >= 1500 && leaf.time_end <= 1800);
        }
    }

    #[test]
    fn max_depth_increases_with_facts() {
        let tree = TemporalTree::open_memory().unwrap().with_max_children(4);
        assert_eq!(tree.max_depth(TreeType::Session, "s1").unwrap(), 0);

        tree.insert_fact(TreeType::Session, "s1", "first", 1000)
            .unwrap();
        assert_eq!(tree.max_depth(TreeType::Session, "s1").unwrap(), 1);

        for i in 1..20 {
            tree.insert_fact(
                TreeType::Session,
                "s1",
                &format!("fact {i}"),
                1000 + i * 100,
            )
            .unwrap();
        }
        assert!(tree.max_depth(TreeType::Session, "s1").unwrap() >= 2);
    }

    #[test]
    fn insert_facts_batch_matches_individual() {
        let tree1 = TemporalTree::open_memory().unwrap().with_max_children(4);
        let tree2 = TemporalTree::open_memory().unwrap().with_max_children(4);

        let fact_strings: Vec<String> = (0..20).map(|i| format!("fact {i}")).collect();
        let facts: Vec<(&str, i64)> = fact_strings
            .iter()
            .enumerate()
            .map(|(i, s)| (s.as_str(), 1000 + i as i64 * 100))
            .collect();

        // Individual inserts
        for &(content, ts) in &facts {
            tree1
                .insert_fact(TreeType::Session, "s1", content, ts)
                .unwrap();
        }

        // Batch insert
        let ids = tree2.insert_facts(TreeType::Session, "s1", &facts).unwrap();
        assert_eq!(ids.len(), 20);

        // Both should have the same leaf count
        let leaves1 = tree1
            .leaves_in_range(TreeType::Session, "s1", 0, i64::MAX)
            .unwrap();
        let leaves2 = tree2
            .leaves_in_range(TreeType::Session, "s1", 0, i64::MAX)
            .unwrap();
        assert_eq!(leaves1.len(), leaves2.len());
    }

    #[test]
    fn insert_facts_empty_is_noop() {
        let tree = TemporalTree::open_memory().unwrap();
        let ids = tree.insert_facts(TreeType::Session, "s1", &[]).unwrap();
        assert!(ids.is_empty());
        assert_eq!(tree.count().unwrap(), 0);
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
