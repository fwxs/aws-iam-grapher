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
}
