/// Errors produced by the graph ingestion layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GraphError {
    /// Neo4j driver / connection error.
    #[error("neo4j error: {0}")]
    Neo4j(#[from] neo4rs::Error),

    /// Schema initialization failed.
    #[error("schema initialization failed: {statement}: {source}")]
    SchemaInit {
        statement: String,
        #[source]
        source: neo4rs::Error,
    },

    /// Ingestion error in a specific phase.
    #[error("ingestion failed in phase {phase}: {source}")]
    Ingestion {
        phase: u8,
        #[source]
        source: neo4rs::Error,
    },

    /// Query returned unexpected shape.
    #[error("unexpected query result: {0}")]
    UnexpectedResult(String),

    /// A row column could not be decoded to the requested type.
    #[error("failed to decode column `{column}`")]
    RowDecode {
        column: &'static str,
        #[source]
        source: neo4rs::DeError,
    },

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

impl GraphError {
    /// True for transport/connection-level failures (retryable; maps to HTTP 503
    /// in the GUI). `Neo4j(_)`, `Ingestion`, and `SchemaInit` are checked via
    /// their inner `neo4rs::Error`; only its unambiguous `IOError`/`ConnectionError`
    /// variants qualify. Other `neo4rs::Error` variants (including `Transient`)
    /// and decode errors (`RowDecode`, whose source is a `DeError` — a column
    /// mismatch, never a transport failure) are protocol/application level, not
    /// connection failures, so they are excluded even though some `Transient`
    /// cases are retryable.
    pub fn is_connection_error(&self) -> bool {
        let source = match self {
            Self::Neo4j(e) => e,
            Self::Ingestion { source, .. } | Self::SchemaInit { source, .. } => source,
            _ => return false,
        };
        matches!(
            source,
            neo4rs::Error::IOError { .. } | neo4rs::Error::ConnectionError
        )
    }

    /// True for authentication/authorization failures against Neo4j itself (wrong
    /// password, expired token) — distinct from [`is_connection_error`](Self::is_connection_error),
    /// which is transport-level (the driver never reached a server at all). Both map to
    /// the CLI's "credential" exit class, but a caller that wants to tell "can't reach
    /// the server" from "reached it, credentials rejected" apart uses these separately.
    pub fn is_credential_error(&self) -> bool {
        let source = match self {
            Self::Neo4j(e) => e,
            Self::Ingestion { source, .. } | Self::SchemaInit { source, .. } => source,
            _ => return false,
        };
        match source {
            neo4rs::Error::AuthenticationError(_) => true,
            neo4rs::Error::Neo4j(e) => matches!(
                e.kind(),
                neo4rs::Neo4jErrorKind::Client(neo4rs::Neo4jClientErrorKind::Security(_))
            ),
            _ => false,
        }
    }

    /// Construct a [`GraphError::SnapshotNotFound`] error.
    pub fn snapshot_not_found(snapshot_id: impl Into<String>) -> Self {
        Self::SnapshotNotFound(snapshot_id.into())
    }

    /// Construct a [`GraphError::NoSnapshotsForAccount`] error.
    pub fn no_snapshots_for_account(account_id: impl Into<String>) -> Self {
        Self::NoSnapshotsForAccount(account_id.into())
    }

    /// Construct a [`GraphError::NoSnapshots`] error.
    pub fn no_snapshots() -> Self {
        Self::NoSnapshots
    }

    /// Construct a [`GraphError::NoOrgRuns`] error.
    pub fn no_org_runs() -> Self {
        Self::NoOrgRuns
    }

    /// Construct a [`GraphError::AccountMismatch`] error.
    pub fn account_mismatch(
        snapshot_id: impl Into<String>,
        expected: impl Into<String>,
        actual: impl Into<String>,
    ) -> Self {
        Self::AccountMismatch {
            snapshot_id: snapshot_id.into(),
            expected: expected.into(),
            actual: actual.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn query_against_unreachable_port_is_connection_error() {
        // Arrange: nothing listens on this port; the pool connects lazily, so the
        // failure surfaces on first use, not on `connect()` itself.
        let uri = "bolt://127.0.0.1:1";
        let client = crate::client::GraphClient::connect(uri, "neo4j", "password")
            .await
            .expect("connect() only builds the lazy pool, it doesn't dial yet");

        // Act
        let result = client.run(neo4rs::query("RETURN 1")).await;
        let Err(err) = result else {
            panic!("querying an unreachable port must fail");
        };

        // Assert
        assert!(
            err.is_connection_error(),
            "expected a connection error, got: {err:?}"
        );
        assert!(
            std::error::Error::source(&err).is_some(),
            "connection error must preserve its neo4rs source"
        );
    }

    #[test]
    fn row_decode_error_is_not_connection_error() {
        // Arrange
        let err = GraphError::RowDecode {
            column: "is_partial",
            source: neo4rs::DeError::MissingField {
                field: "is_partial",
            },
        };

        // Act & Assert
        assert!(!err.is_connection_error());
        assert!(std::error::Error::source(&err).is_some());
    }

    #[tokio::test]
    async fn connect_failure_error_string_excludes_password() {
        // Arrange: credentials embedded in the URI itself (worst case for leakage)
        // plus passed again as separate connect() args, against an unreachable port.
        let uri = "bolt://neo4j:supersecretpw@127.0.0.1:1";
        let client = crate::client::GraphClient::connect(uri, "neo4j", "supersecretpw")
            .await
            .expect("connect() only builds the lazy pool, it doesn't dial yet");

        // Act
        let result = client.run(neo4rs::query("RETURN 1")).await;
        let Err(err) = result else {
            panic!("querying an unreachable port must fail");
        };

        // Assert: neither Display nor Debug output may contain the password.
        let display = err.to_string();
        let debug = format!("{err:?}");
        assert!(
            !display.contains("supersecretpw"),
            "error Display leaked the password: {display}"
        );
        assert!(
            !debug.contains("supersecretpw"),
            "error Debug leaked the password: {debug}"
        );
        assert!(
            !display.contains("neo4j:supersecretpw"),
            "error Display leaked the userinfo form: {display}"
        );
    }

    #[test]
    fn ingestion_error_preserves_source_chain() {
        // Arrange: the CLI boundary wraps GraphError in anyhow::Error via `?`,
        // which walks `std::error::Error::source()` to build its chain — so a
        // populated `source()` is what makes anyhow's chain non-trivial.
        let err = GraphError::Ingestion {
            phase: 3,
            source: neo4rs::Error::ConnectionError,
        };

        // Act
        let source = std::error::Error::source(&err);

        // Assert: the underlying neo4rs error must be reachable, not just the
        // top-level "ingestion failed in phase 3" message.
        let source = source.expect("Ingestion error must expose its neo4rs source");
        assert_eq!(source.to_string(), "connection error");
    }
}
