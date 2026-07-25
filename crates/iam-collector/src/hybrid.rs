use crate::errors::CollectorError;
use crate::live::LiveCollector;
use crate::traits::{CollectedData, CollectorMode, IamDataSource};

const OFFLINE_INSTRUCTIONS: &str = "\
To continue, generate the file with your current credentials:

    aws iam get-account-authorization-details \\
        --output json > account-auth-details.json

Then run:

    aws-iam-grapher collect \\
        --mode offline \\
        --input-file account-auth-details.json";

/// Tries live collection; on 403 returns a `ManualInterventionRequired` error
/// with actionable instructions. Never falls back silently.
pub struct HybridCollector {
    live: LiveCollector,
}

impl HybridCollector {
    pub fn new(client: aws_sdk_iam::Client) -> Self {
        Self {
            live: LiveCollector::new(client),
        }
    }

    pub async fn from_env(
        regions: &[String],
        profile: Option<&str>,
    ) -> Result<Self, CollectorError> {
        let live = LiveCollector::from_env(regions, profile).await?;
        Ok(Self { live })
    }
}

#[async_trait::async_trait]
impl IamDataSource for HybridCollector {
    fn mode(&self) -> CollectorMode {
        CollectorMode::Hybrid
    }

    async fn collect(&self) -> Result<CollectedData, CollectorError> {
        match self.live.collect().await {
            Ok(mut data) => {
                data.source = CollectorMode::Hybrid;
                Ok(data)
            }
            Err(CollectorError::InsufficientPermissions(op)) => {
                Err(CollectorError::ManualInterventionRequired {
                    reason: format!("insufficient permissions: {op}"),
                    instructions: OFFLINE_INSTRUCTIONS.to_string(),
                })
            }
            Err(other) => Err(other),
        }
    }
}
