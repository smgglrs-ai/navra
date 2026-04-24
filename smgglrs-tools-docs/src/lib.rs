mod store;
mod tools;
pub mod watcher;

pub use store::IndexStore;
pub use tools::DocsModule;
pub use watcher::{start_watcher, start_watcher_with_embeddings, WatcherHandle};
