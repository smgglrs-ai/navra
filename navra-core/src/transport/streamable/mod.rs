mod handlers;
pub(crate) mod router;

pub use router::{build_router, build_router_with_broadcaster, build_router_with_discovery};

#[cfg(test)]
mod tests;
