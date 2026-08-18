use crate::errors::CollectorWarning;
use chrono::{DateTime, Utc};
use iam_models::{IamGroup, IamInstanceProfile, IamPolicy, IamRole, IamUser};

/// How data was collected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectorMode {
    Live,
    Offline,
    Hybrid,
}

/// All IAM entities collected from a single AWS account.
#[derive(Debug, Clone)]
pub struct CollectedData {
    pub source: CollectorMode,
    pub account_id: Option<String>,
    /// Immediate parent OU id from an org-wide collection (`collect org`), or `None` for
    /// standalone (live/offline/hybrid) collection or an account directly under the org root.
    pub ou_id: Option<String>,
    /// Immediate parent OU display name from an org-wide collection, or `None`.
    pub ou_name: Option<String>,
    pub policies: Vec<IamPolicy>,
    pub roles: Vec<IamRole>,
    pub users: Vec<IamUser>,
    pub groups: Vec<IamGroup>,
    pub instance_profiles: Vec<IamInstanceProfile>,
    pub collection_timestamp: DateTime<Utc>,
    pub warnings: Vec<CollectorWarning>,
}

impl Default for CollectedData {
    fn default() -> Self {
        Self {
            source: CollectorMode::Offline,
            account_id: None,
            ou_id: None,
            ou_name: None,
            policies: Vec::new(),
            roles: Vec::new(),
            users: Vec::new(),
            groups: Vec::new(),
            instance_profiles: Vec::new(),
            collection_timestamp: Utc::now(),
            warnings: Vec::new(),
        }
    }
}

/// Trait for IAM data sources.
#[async_trait::async_trait]
pub trait IamDataSource: Send + Sync {
    async fn collect(&self) -> Result<CollectedData, crate::errors::CollectorError>;
}
