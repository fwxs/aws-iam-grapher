//! Maps CLI failures to a process exit code and, under `--output json`, a stderr JSON
//! envelope. This is the one place in the binary that owns the exit-code taxonomy —
//! `iam-graph` and `iam-collector` stay process-agnostic and only define typed errors.

use std::process::ExitCode;

/// Usage/validation failures that don't originate from `iam-graph` or `iam-collector` —
/// contradictory flags, missing required arguments. Kept typed (rather than
/// `anyhow::bail!` strings) so [`CliError::exit_class`] can classify them without
/// string-matching.
#[derive(Debug, thiserror::Error)]
pub enum CliValidationError {
    #[error(
        "offline mode requires --input-file.\n\n\
         Generate the file with:\n\n    \
         aws iam get-account-authorization-details --output json > account-auth-details.json"
    )]
    OfflineMissingInputFile,

    #[error(
        "--snapshot-id cannot be combined with multi-account mode \
         (no --account-id, {accounts} accounts found); pass --account-id to \
         target a single account"
    )]
    SnapshotIdMultiAccountConflict { accounts: usize },

    #[error(
        "could not determine AWS account ID: no entities were collected and \
         --account-id was not provided.\n\n\
         Pass the account ID explicitly:\n\n    \
         aws-iam-grapher collect --account-id 123456789012 ..."
    )]
    AccountIdNotResolved,

    #[error(
        "--output graphviz is not supported for this query; supported queries: \
         who-can, privilege-escalation, org-escalation"
    )]
    GraphvizUnsupported,
}

/// The union of typed error sources the CLI classifies into an exit code. Constructed at
/// the point of failure (not by downcasting a generic `anyhow::Error`), then converted to
/// `anyhow::Error` via `?` like any other error — [`handle_error`] recovers the concrete
/// type from `anyhow::Error::chain()`.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error(transparent)]
    Graph(#[from] iam_graph::GraphError),

    #[error(transparent)]
    Collector(#[from] iam_collector::CollectorError),

    #[error(transparent)]
    Usage(#[from] CliValidationError),

    #[error(
        "Neo4j password required: pass --neo4j-pass-file <path> or set the \
         NEO4J_PASSWORD environment variable ({detail})"
    )]
    MissingNeo4jPassword { detail: &'static str },
}

/// The exit-code class a [`CliError`] (or an unclassified `anyhow::Error`) maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitClass {
    Usage,
    Credential,
    ScopeNotFound,
    Unexpected,
}

impl ExitClass {
    pub fn code(self) -> u8 {
        match self {
            Self::Usage => 2,
            Self::Credential => 3,
            Self::ScopeNotFound => 4,
            Self::Unexpected => 1,
        }
    }

    /// The `error.code` string in the JSON envelope.
    pub fn json_code(self) -> &'static str {
        match self {
            Self::Usage => "usage",
            Self::Credential => "credential",
            Self::ScopeNotFound => "scope-not-found",
            Self::Unexpected => "unexpected",
        }
    }
}

impl CliError {
    pub fn exit_class(&self) -> ExitClass {
        match self {
            Self::Graph(e) => graph_exit_class(e),
            Self::Collector(e) => collector_exit_class(e),
            Self::Usage(_) => ExitClass::Usage,
            Self::MissingNeo4jPassword { .. } => ExitClass::Credential,
        }
    }
}

fn graph_exit_class(err: &iam_graph::GraphError) -> ExitClass {
    use iam_graph::GraphError;
    match err {
        GraphError::SnapshotNotFound(_)
        | GraphError::NoSnapshotsForAccount(_)
        | GraphError::NoSnapshots
        | GraphError::NoOrgRuns
        | GraphError::AccountMismatch { .. } => ExitClass::ScopeNotFound,
        _ if err.is_connection_error() || err.is_credential_error() => ExitClass::Credential,
        _ => ExitClass::Unexpected,
    }
}

fn collector_exit_class(err: &iam_collector::CollectorError) -> ExitClass {
    use iam_collector::CollectorError;
    match err {
        CollectorError::CredentialsUnavailable(_) | CollectorError::InsufficientPermissions(_) => {
            ExitClass::Credential
        }
        CollectorError::ManualInterventionRequired { .. }
        | CollectorError::InvalidOuProfileOverride(_)
        | CollectorError::InvalidOuRoleOverride(_)
        | CollectorError::InvalidProfile(_) => ExitClass::Usage,
        _ => ExitClass::Unexpected,
    }
}

/// Recover a typed error from an `anyhow::Error`'s source chain and classify it.
/// `anyhow`'s `?` conversion (and `.context(...)`) preserve the original typed error as the
/// chain's innermost link even after wrapping — see
/// `iam_graph::errors::tests::ingestion_error_preserves_source_chain`. Every source type
/// `CliError` can wrap is tried both as a bare `CliError` and unwrapped, because
/// `SomeError.into()` at a call site resolves to whichever `From` impl type inference
/// picks — often anyhow's blanket `From<E: std::error::Error>` straight to `anyhow::Error`,
/// bypassing `CliError` entirely, rather than `CliError`'s own `#[from]` impl.
fn classify(err: &anyhow::Error) -> ExitClass {
    for cause in err.chain() {
        if let Some(e) = cause.downcast_ref::<CliError>() {
            return e.exit_class();
        }
        if cause.downcast_ref::<CliValidationError>().is_some() {
            return ExitClass::Usage;
        }
        if let Some(e) = cause.downcast_ref::<iam_graph::GraphError>() {
            return graph_exit_class(e);
        }
        if let Some(e) = cause.downcast_ref::<iam_collector::CollectorError>() {
            return collector_exit_class(e);
        }
    }
    ExitClass::Unexpected
}

/// Handle the final `Err` from `cli::run()`: classify it, print exactly one line to
/// stderr (a JSON envelope when `json` is true, otherwise today's plain `Error: ...`
/// line), and return the matching [`ExitCode`]. Never writes to stdout. The JSON
/// envelope's `message` is the outermost `Display` only — never the full causal chain —
/// so internal paths/connection details aren't leaked to a machine consumer (see
/// `docs/limitations.md`'s security notes); the full chain remains available via
/// `RUST_LOG`.
pub fn handle_error(err: anyhow::Error, json: bool) -> ExitCode {
    let class = classify(&err);
    if json {
        crate::output::json::eprint_json_error(class.json_code(), &err.to_string());
    } else {
        eprintln!("Error: {err}");
    }
    ExitCode::from(class.code())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_scope_variants_classify_as_scope_not_found() {
        assert_eq!(
            graph_exit_class(&iam_graph::GraphError::snapshot_not_found("abc")),
            ExitClass::ScopeNotFound
        );
        assert_eq!(
            graph_exit_class(&iam_graph::GraphError::no_snapshots()),
            ExitClass::ScopeNotFound
        );
        assert_eq!(
            graph_exit_class(&iam_graph::GraphError::no_snapshots_for_account(
                "111111111111"
            )),
            ExitClass::ScopeNotFound
        );
        assert_eq!(
            graph_exit_class(&iam_graph::GraphError::no_org_runs()),
            ExitClass::ScopeNotFound
        );
        assert_eq!(
            graph_exit_class(&iam_graph::GraphError::account_mismatch("s", "a", "b")),
            ExitClass::ScopeNotFound
        );
    }

    #[test]
    fn graph_connection_error_classifies_as_credential() {
        let err = iam_graph::GraphError::from(neo4rs::Error::ConnectionError);
        assert_eq!(graph_exit_class(&err), ExitClass::Credential);
    }

    #[test]
    fn graph_authentication_error_classifies_as_credential() {
        let err = iam_graph::GraphError::from(neo4rs::Error::AuthenticationError(
            "wrong password".into(),
        ));
        assert_eq!(graph_exit_class(&err), ExitClass::Credential);
    }

    #[test]
    fn graph_row_decode_classifies_as_unexpected() {
        let err = iam_graph::GraphError::RowDecode {
            column: "x",
            source: neo4rs::DeError::MissingField { field: "x" },
        };
        assert_eq!(graph_exit_class(&err), ExitClass::Unexpected);
    }

    #[test]
    fn collector_credentials_unavailable_classifies_as_credential() {
        let err = iam_collector::CollectorError::CredentialsUnavailable("no chain".into());
        assert_eq!(collector_exit_class(&err), ExitClass::Credential);
    }

    #[test]
    fn collector_manual_intervention_classifies_as_usage() {
        let err = iam_collector::CollectorError::ManualInterventionRequired {
            reason: "r".into(),
            instructions: "i".into(),
        };
        assert_eq!(collector_exit_class(&err), ExitClass::Usage);
    }

    #[test]
    fn collector_insufficient_permissions_classifies_as_credential() {
        let err = iam_collector::CollectorError::InsufficientPermissions("iam:GetRole".into());
        assert_eq!(collector_exit_class(&err), ExitClass::Credential);
    }

    #[test]
    fn collector_bad_cli_argument_variants_classify_as_usage() {
        assert_eq!(
            collector_exit_class(&iam_collector::CollectorError::InvalidOuProfileOverride(
                "bad".into()
            )),
            ExitClass::Usage
        );
        assert_eq!(
            collector_exit_class(&iam_collector::CollectorError::InvalidOuRoleOverride(
                "bad".into()
            )),
            ExitClass::Usage
        );
        assert_eq!(
            collector_exit_class(&iam_collector::CollectorError::InvalidProfile("bad".into())),
            ExitClass::Usage
        );
    }

    #[test]
    fn collector_other_variants_classify_as_unexpected() {
        let err = iam_collector::CollectorError::AwsSdk("boom".into());
        assert_eq!(collector_exit_class(&err), ExitClass::Unexpected);
    }

    #[test]
    fn validation_error_classifies_as_usage() {
        let err = CliError::Usage(CliValidationError::OfflineMissingInputFile);
        assert_eq!(err.exit_class(), ExitClass::Usage);
    }

    #[test]
    fn missing_neo4j_password_classifies_as_credential() {
        let err = CliError::MissingNeo4jPassword { detail: "not set" };
        assert_eq!(err.exit_class(), ExitClass::Credential);
    }

    #[test]
    fn classify_recovers_cli_error_through_anyhow_context_wrapping() {
        let cli_err: CliError = CliValidationError::AccountIdNotResolved.into();
        let wrapped: anyhow::Error = anyhow::Error::from(cli_err).context("collection failed");

        assert_eq!(classify(&wrapped), ExitClass::Usage);
    }

    #[test]
    fn classify_unclassified_anyhow_error_is_unexpected() {
        let err = anyhow::anyhow!("something went wrong");
        assert_eq!(classify(&err), ExitClass::Unexpected);
    }

    #[test]
    fn classify_recovers_bare_graph_error_propagated_via_question_mark() {
        // Most call sites (e.g. query.rs's `Diff` arm) propagate `GraphError` directly via
        // `?`, never wrapped in `CliError` — this is the real-world path, not just the
        // `CliError`-wrapped one.
        let graph_err: anyhow::Error = iam_graph::GraphError::snapshot_not_found("abc").into();
        let wrapped = graph_err.context("diff query failed");

        assert_eq!(classify(&wrapped), ExitClass::ScopeNotFound);
    }

    #[test]
    fn classify_recovers_bare_collector_error_propagated_via_context() {
        let collector_err = iam_collector::CollectorError::CredentialsUnavailable("x".into());
        let wrapped: anyhow::Error = anyhow::Error::new(collector_err).context("collection failed");

        assert_eq!(classify(&wrapped), ExitClass::Credential);
    }

    #[test]
    fn exit_class_codes_match_the_issue_taxonomy() {
        assert_eq!(ExitClass::Usage.code(), 2);
        assert_eq!(ExitClass::Credential.code(), 3);
        assert_eq!(ExitClass::ScopeNotFound.code(), 4);
        assert_eq!(ExitClass::Unexpected.code(), 1);
    }
}
