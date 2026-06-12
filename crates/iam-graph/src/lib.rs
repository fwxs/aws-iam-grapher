//! Neo4j ingestion for IAM data.
//!
//! # Usage
//! ```no_run
//! use iam_graph::{GraphClient, GraphIngester, IngestConfig};
//!
//! async fn example() {
//!     let client = GraphClient::connect("bolt://localhost:7687", "neo4j", "password")
//!         .await.unwrap();
//!     client.initialize_schema().await.unwrap();
//!     let config = IngestConfig {
//!         snapshot_id: "snap-001".to_string(),
//!         account_id: "123456789012".to_string(),
//!         ..Default::default()
//!     };
//!     let ingester = GraphIngester::new(client, config);
//! }
//! ```

mod client;
mod errors;
mod ingester;
pub mod nodes;
pub mod queries;
mod schema;

pub use client::GraphClient;
pub use errors::GraphError;
pub use ingester::{GraphIngester, IngestConfig, IngestStats};
pub use queries::{
    delete_snapshot, diff_permissions, entity_permissions, instance_profiles_with_action,
    list_snapshots, privilege_escalation_paths, risky_instance_profiles, who_can, EntityRef,
    EscalationPath, PermissionDiff, PermissionRecord, PermissionRow, QueryContext,
    RiskyInstanceProfile, SnapshotRecord,
};
