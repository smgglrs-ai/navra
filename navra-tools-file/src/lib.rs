//! File system tools for navra.
//!
//! Provides `file_read`, `file_write`, `file_list`, `file_tree`, and
//! `file_search` tools backed by SQLite FTS5 and sqlite-vec. Includes
//! a file watcher for automatic reindexing.

mod store;
mod tools;
pub mod watcher;

pub use store::IndexStore;
pub use tools::FileModule;
pub use watcher::{start_watcher, start_watcher_with_embeddings, WatcherHandle};
