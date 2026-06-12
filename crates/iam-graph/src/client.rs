use crate::errors::GraphError;
use crate::schema;

/// Wrapper around a neo4rs connection.
pub struct GraphClient {
    graph: neo4rs::Graph,
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
