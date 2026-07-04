use crate::errors::{CollectorError, CollectorWarning};
use crate::expand::expand_collected_data;
use crate::raw::auth_details::AccountAuthorizationDetails;
use crate::raw::instance_profiles::ListInstanceProfilesResponse;
use crate::traits::{CollectedData, CollectorMode, IamDataSource};
use crate::util::account_id_from_arns;
use chrono::Utc;
use iam_models::{IamGroup, IamInstanceProfile, IamPolicy, IamRole, IamUser};
use tracing::{debug, info};

/// Collects IAM data from CLI JSON files (no network calls to AWS).
pub struct OfflineCollector {
    auth_details_json: String,
    instance_profiles_json: Option<String>,
}

impl OfflineCollector {
    /// Validates the auth_details JSON (schema, not just syntax) and builds the collector.
    ///
    /// `instance_profiles_json` is JSON from `aws iam list-instance-profiles`; omit it
    /// when instance profiles were not collected.
    pub fn new(
        auth_details_json: &str,
        instance_profiles_json: Option<&str>,
    ) -> Result<Self, CollectorError> {
        // Parse to the typed struct so missing required fields are caught here,
        // not deferred to the first collect() call.
        let _: AccountAuthorizationDetails = serde_json::from_str(auth_details_json)?;
        Ok(Self {
            auth_details_json: auth_details_json.to_string(),
            instance_profiles_json: instance_profiles_json.map(String::from),
        })
    }
}

#[async_trait::async_trait]
impl IamDataSource for OfflineCollector {
    fn mode(&self) -> CollectorMode {
        CollectorMode::Offline
    }

    async fn collect(&self) -> Result<CollectedData, CollectorError> {
        info!("starting offline IAM collection");
        let mut warnings = Vec::new();

        let details: AccountAuthorizationDetails = serde_json::from_str(&self.auth_details_json)?;

        let users: Vec<IamUser> = details
            .user_detail_list
            .into_iter()
            .map(IamUser::from)
            .collect();

        let groups: Vec<IamGroup> = details
            .group_detail_list
            .into_iter()
            .map(IamGroup::from)
            .collect();

        let roles: Vec<IamRole> = details
            .role_detail_list
            .into_iter()
            .map(IamRole::from)
            .collect();

        let policies: Vec<IamPolicy> = details.policies.into_iter().map(IamPolicy::from).collect();

        debug!(
            users = users.len(),
            roles = roles.len(),
            groups = groups.len(),
            policies = policies.len(),
            "deserialized offline entities"
        );

        // Parse instance profiles
        let instance_profiles: Vec<IamInstanceProfile> =
            if let Some(ip_json) = &self.instance_profiles_json {
                let resp: ListInstanceProfilesResponse = serde_json::from_str(ip_json)?;
                resp.instance_profiles
                    .into_iter()
                    .map(IamInstanceProfile::from)
                    .collect()
            } else {
                warnings.push(CollectorWarning::InstanceProfilesMissing);
                Vec::new()
            };

        info!(
            instance_profiles = instance_profiles.len(),
            "offline collection complete"
        );

        // Prefer customer entity ARNs (users, roles, groups) over managed-policy ARNs,
        // which use the literal "aws" as their account segment.
        let account_id = account_id_from_arns(
            users
                .iter()
                .map(|u| u.arn.as_str())
                .chain(roles.iter().map(|r| r.arn.as_str()))
                .chain(groups.iter().map(|g| g.arn.as_str()))
                .chain(instance_profiles.iter().map(|ip| ip.arn.as_str()))
                .chain(policies.iter().map(|p| p.arn.as_str())),
        );

        let mut data = CollectedData {
            source: CollectorMode::Offline,
            account_id,
            policies,
            roles,
            users,
            groups,
            instance_profiles,
            collection_timestamp: Utc::now(),
            warnings,
        };

        expand_collected_data(&mut data).await;

        Ok(data)
    }
}
