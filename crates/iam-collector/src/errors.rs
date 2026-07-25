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

    #[error("invalid --ou-profile-override: {0}")]
    InvalidOuProfileOverride(String),

    #[error("invalid --ou-role-override: {0}")]
    InvalidOuRoleOverride(String),

    #[error("invalid --profile: {0}")]
    InvalidProfile(String),
}

/// Non-fatal warnings produced during collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectorWarning {
    InstanceProfilesMissing,
    InlinePoliciesNotResolved,
    WildcardsNotExpanded,
    PartialData(String),
    /// One or more users' MFA devices could not be listed (`ListMFADevices` failed).
    MfaDevicesMissing,
    /// One or more users' console login profile could not be determined
    /// (`GetLoginProfile` failed with something other than `NoSuchEntity`).
    LoginProfileMissing,
    /// One or more users' access key activity could not be determined
    /// (`ListAccessKeys` or `GetAccessKeyLastUsed` failed).
    AccessKeyActivityMissing,
    /// User security attributes (MFA, console login, last activity) were not collected
    /// at all — offline collection has no data source for them.
    UserSecurityAttributesNotCollected,
}
