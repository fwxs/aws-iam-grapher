/// Fatal errors from data collection.
#[derive(Debug, thiserror::Error)]
pub enum CollectorError {
    #[error("insufficient permissions calling {0}")]
    InsufficientPermissions(String),

    #[error("manual intervention required: {reason}\n\n{instructions}")]
    ManualInterventionRequired {
        reason: String,
        instructions: String,
    },

    #[error("AWS SDK error: {0}")]
    AwsSdk(String),

    #[error("invalid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("expander error: {0}")]
    Expander(#[from] iam_expander::ExpanderError),
}

/// Non-fatal warnings produced during collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectorWarning {
    InstanceProfilesMissing,
    InlinePoliciesNotResolved,
    WildcardsNotExpanded,
    PartialData(String),
}
