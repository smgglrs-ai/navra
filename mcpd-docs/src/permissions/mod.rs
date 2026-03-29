mod acl;
mod approval;

pub use acl::{Operation, PathAcl, PermissionEngine, PermissionResult};
pub use approval::{ApprovalRequest, ApprovalStatus, ApprovalStore};

use crate::config::Config;

impl PermissionEngine {
    pub fn from_config(config: &Config) -> Self {
        let mut engine = PermissionEngine::new();
        for (name, pset) in &config.permissions {
            let acl = PathAcl {
                allow: pset.allow.clone(),
                deny: pset.deny.clone(),
                operations: pset
                    .operations
                    .iter()
                    .filter_map(|s| Operation::from_str(s))
                    .collect(),
                requires_approval: pset
                    .approve
                    .iter()
                    .filter_map(|s| Operation::from_str(s))
                    .collect(),
            };
            engine.add_permission_set(name.clone(), acl);
        }
        engine
    }
}
