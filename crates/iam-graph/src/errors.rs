/// Errors produced by the graph ingestion layer.
#[derive(Debug, thiserror::Error)]
pub enum GraphError {
    /// Neo4j driver / connection error.
    #[error("neo4j error: {0}")]
    Neo4j(#[from] neo4rs::Error),

    /// Schema initialization failed.
    #[error("schema initialization failed: {0}")]
    SchemaInit(String),

    /// Ingestion error in a specific phase.
    #[error("ingestion failed in phase {phase}: {cause}")]
    Ingestion { phase: u8, cause: String },

    /// Query returned unexpected shape.
    #[error("unexpected query result: {0}")]
    UnexpectedResult(String),

    /// Requested snapshot does not exist in the graph.
    #[error("snapshot {0} not found")]
    SnapshotNotFound(String),

    /// Account has no snapshots in the graph.
    #[error(
        "no snapshots found for account {0}.\n\
         Run first: aws-iam-grapher collect --account-alias my-account"
    )]
    NoSnapshotsForAccount(String),

    /// Graph has no snapshots at all.
    #[error(
        "no snapshots found in the graph.\n\
         Run first: aws-iam-grapher collect --account-alias my-account"
    )]
    NoSnapshots,

    /// No org collection runs exist in the graph.
    #[error(
        "no org collection runs found.\n\
         Run first: aws-iam-grapher collect org ..."
    )]
    NoOrgRuns,

    /// Explicit snapshot belongs to a different account than expected.
    #[error("snapshot {snapshot_id} belongs to account {actual} but expected account {expected}")]
    AccountMismatch {
        snapshot_id: String,
        expected: String,
        actual: String,
    },
}
