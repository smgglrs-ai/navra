//! Integration tests for `subscriptions/listen` (MCP 2026-07-28).
//!
//! Serves a NavraHandler over duplex against a discover-lifecycle
//! rmcp client (the only peer kind that can send the 2026-07-28
//! method), and asserts notifications flow from navra's internal
//! broadcast bus through the SubscriptionSink.

use navra_core::{Module, NavraHandler};
use navra_protocol::CallToolResult;
use std::sync::Arc;

fn test_module() -> navra_mcp::protocol::ResourceDefinition {
    navra_mcp::protocol::RawResource::new("test://status", "status")
        .with_description("Server status")
        .with_mime_type("text/plain")
}

struct TestModule;

impl Module for TestModule {
    fn name(&self) -> &str {
        "test"
    }

    fn tools(&self) -> Vec<(navra_mcp::protocol::ToolDefinition, navra_mcp::ToolHandler)> {
        vec![(
            navra_mcp::protocol::ToolDefinition::new(
                "ping",
                "Returns pong",
                navra_protocol::compat::empty_input_schema(),
            ),
            Arc::new(|_args, _ctx| {
                Box::pin(async move {
                    use navra_protocol::compat::CallToolResultExt;
                    navra_protocol::CallToolResponse::Complete(CallToolResult::text("pong"))
                })
            }),
        )]
    }

    fn resources(
        &self,
    ) -> Vec<(
        navra_mcp::protocol::ResourceDefinition,
        navra_mcp::ResourceHandler,
    )> {
        vec![(
            test_module(),
            Arc::new(|uri, _ctx| {
                Box::pin(async move {
                    navra_mcp::protocol::ReadResourceResult::new(vec![
                        navra_mcp::protocol::ResourceContent::TextResourceContents {
                            uri,
                            mime_type: Some("text/plain".to_string()),
                            text: "ok".to_string(),
                            meta: None,
                        },
                    ])
                })
            }),
        )]
    }
}

/// Serve a NavraHandler over duplex and connect a discover-lifecycle
/// client (2026-07-28), returning the server and the client peer.
async fn serve_and_connect() -> (Arc<navra_core::McpServer>, rmcp::Peer<rmcp::RoleClient>) {
    let broadcaster = navra_core::transport::sse::SseBroadcaster::new();
    let server = Arc::new(
        navra_core::McpServer::builder()
            .allow_anonymous()
            .broadcaster(broadcaster)
            .module(TestModule)
            .build(),
    );
    let handler = NavraHandler::new(Arc::clone(&server));
    let (server_io, client_io) = tokio::io::duplex(65536);
    tokio::spawn(async move {
        if let Ok(service) =
            rmcp::service::ServiceExt::<rmcp::RoleServer>::serve(handler, server_io).await
        {
            let _ = service.waiting().await;
        }
    });
    let client = rmcp::service::ClientServiceExt::serve_with_lifecycle(
        (),
        client_io,
        rmcp::service::ClientLifecycleMode::Discover {
            preferred_versions: vec![rmcp::model::ProtocolVersion::V_2026_07_28],
        },
    )
    .await
    .expect("discover init");
    let peer = client.peer().clone();
    tokio::spawn(async move {
        let _ = client.waiting().await;
    });
    (server, peer)
}

async fn next_notification(
    subscription: &mut rmcp::service::Subscription,
) -> rmcp::model::ServerNotification {
    tokio::time::timeout(std::time::Duration::from_secs(5), subscription.next())
        .await
        .expect("notification within 5s")
        .expect("subscription alive")
        .expect("a notification")
}

#[tokio::test]
async fn subscription_delivers_tools_list_changed() {
    let (server, peer) = serve_and_connect().await;

    let filter = rmcp::model::SubscriptionFilter::builder()
        .tools_list_changed()
        .build();
    let mut subscription = peer.listen(filter).await.expect("listen");
    assert_eq!(
        subscription.acknowledged().tools_list_changed,
        Some(true),
        "tools_list_changed must be acknowledged"
    );

    // A registry swap (or any notify) broadcasts tools/list_changed.
    server.notify("notifications/tools/list_changed", None);

    match next_notification(&mut subscription).await {
        rmcp::model::ServerNotification::ToolListChangedNotification(_) => {}
        other => panic!("expected tools/list_changed, got {other:?}"),
    }
    let _ = subscription.cancel().await;
}

#[tokio::test]
async fn subscription_delivers_resource_updates_for_accepted_uris() {
    let (server, peer) = serve_and_connect().await;

    let filter = rmcp::model::SubscriptionFilter::builder()
        .resource_subscription("test://status")
        .build();
    let mut subscription = peer.listen(filter).await.expect("listen");
    let accepted_uris = subscription
        .acknowledged()
        .resource_subscriptions
        .clone()
        .expect("resource subscriptions accepted");
    assert!(
        accepted_uris.contains(&"test://status".to_string()),
        "known URI must be accepted, got {accepted_uris:?}"
    );

    server.notify_resource_updated("test://status");

    match next_notification(&mut subscription).await {
        rmcp::model::ServerNotification::ResourceUpdatedNotification(n) => {
            assert_eq!(n.params.uri, "test://status");
        }
        other => panic!("expected resources/updated, got {other:?}"),
    }
    let _ = subscription.cancel().await;
}

#[tokio::test]
async fn subscription_filter_strips_unknown_uris_and_unsupported_categories() {
    let (_server, peer) = serve_and_connect().await;

    // Unknown URI + prompts list_changed (navra never emits it).
    let mut filter = rmcp::model::SubscriptionFilter::new();
    filter.prompts_list_changed = Some(true);
    filter.resource_subscriptions = Some(vec![
        "test://status".to_string(),
        "test://nonexistent".to_string(),
    ]);
    let mut subscription = peer.listen(filter).await.expect("listen");
    let acknowledged = subscription.acknowledged();
    assert_eq!(
        acknowledged.prompts_list_changed, None,
        "navra does not emit prompts list_changed"
    );
    let uris = acknowledged
        .resource_subscriptions
        .as_ref()
        .expect("resource subscriptions");
    assert_eq!(
        uris,
        &vec!["test://status".to_string()],
        "only registered URIs are accepted"
    );
    let _ = subscription.cancel().await;
}
