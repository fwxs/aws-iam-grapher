use crate::errors::GraphError;
use crate::schema;

/// Wrapper around a neo4rs connection.
pub struct GraphClient {
    graph: neo4rs::Graph,
}

/// Strips `user:pass@` userinfo from a URI before it is logged or placed in an
/// error, preserving scheme, host, and port. Returns a fixed placeholder on
/// parse failure so a malformed URI can never leak through the fallback path.
pub fn redact_uri(uri: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(uri) else {
        return "<unparsable-uri>".to_string();
    };
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.to_string()
}

impl GraphClient {
    /// Connect to Neo4j using the bolt protocol.
    pub async fn connect(uri: &str, user: &str, password: &str) -> Result<Self, GraphError> {
        let config = neo4rs::ConfigBuilder::new()
            .uri(uri)
            .user(user)
            .password(password)
            .build()
            .map_err(GraphError::Neo4j)?;
        let graph = neo4rs::Graph::connect(config).await?;
        Ok(Self { graph })
    }

    /// Create all constraints and indexes. Idempotent — safe to call multiple times.
    pub async fn initialize_schema(&self) -> Result<(), GraphError> {
        schema::initialize(&self.graph).await
    }

    /// Access the underlying neo4rs graph handle for query functions.
    pub fn inner(&self) -> &neo4rs::Graph {
        &self.graph
    }

    /// Execute a read query and collect all rows.
    pub async fn fetch_all(&self, query: neo4rs::Query) -> Result<Vec<neo4rs::Row>, GraphError> {
        let mut stream = self.graph.execute(query).await?;
        let mut rows = Vec::new();
        while let Some(row) = stream.next().await? {
            rows.push(row);
        }
        Ok(rows)
    }

    /// Run a write query with no return value.
    pub async fn run(&self, query: neo4rs::Query) -> Result<(), GraphError> {
        Ok(self.graph.run(query).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_uri_strips_userinfo_preserves_scheme_host_port() {
        // Arrange
        let uri = "bolt://neo4j:secret@host:7687";

        // Act
        let redacted = redact_uri(uri);

        // Assert
        assert!(redacted.starts_with("bolt://"));
        assert!(redacted.contains("host:7687"));
        assert!(!redacted.contains("secret"));
        assert!(!redacted.contains("neo4j:"));
    }

    #[test]
    fn redact_uri_passthrough_when_no_userinfo() {
        // Arrange
        let uri = "bolt://host:7687";

        // Act
        let redacted = redact_uri(uri);

        // Assert
        assert_eq!(redacted, "bolt://host:7687");
    }
}
