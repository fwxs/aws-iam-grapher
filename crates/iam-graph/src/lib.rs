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
    latest_org_run_id, list_account_ids, list_accounts, list_snapshots, org_escalation_paths,
    privilege_escalation_paths, risky_instance_profiles, snapshot_account_id, stitch_cross_account,
    who_can, AccountRecord, EntityRef, EscalationPath, Hop, OrgEscalationPath, OrgHop,
    OrgQueryContext, PermissionDiff, PermissionRecord, PermissionRow, QueryContext,
    RiskyInstanceProfile, SnapshotRecord, DEFAULT_MAX_HOPS, MAX_HOPS_CAP,
};
