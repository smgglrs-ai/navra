use crate::store::IndexStore;
use smgglrs_core::models::ModelBackend;
use smgglrs_core::notify::Notifier;
use smgglrs_core::permissions::{ApprovalStore, PermissionEngine};
use std::sync::Arc;

pub(crate) struct DocsState {
    pub perm_engine: Arc<PermissionEngine>,
    pub index: Arc<IndexStore>,
    pub approvals: Arc<ApprovalStore>,
    pub notifier: Arc<dyn Notifier>,
    pub embedding_model: Option<Arc<dyn ModelBackend>>,
    pub default_root: Option<String>,
}
