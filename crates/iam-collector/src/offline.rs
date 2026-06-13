use crate::errors::{CollectorError, CollectorWarning};
use crate::raw::auth_details::AccountAuthorizationDetails;
use crate::raw::instance_profiles::ListInstanceProfilesResponse;
use crate::traits::{CollectedData, CollectorMode, IamDataSource};
use crate::util::account_id_from_arns;
use chrono::Utc;
use iam_models::{
    IamGroup, IamInlinePolicy, IamInstanceProfile, IamPolicy, IamRole, IamUser, PolicyDocument,
};
use tracing::{debug, info, warn};

/// Collects IAM data from CLI JSON files (no network calls to AWS).
pub struct OfflineCollector {
    auth_details_json: String,
    instance_profiles_json: Option<String>,
}

/// Builder for `OfflineCollector`.
pub struct OfflineCollectorBuilder {
    auth_details_json: String,
    instance_profiles_json: Option<String>,
}

impl OfflineCollectorBuilder {
    pub fn new() -> Self {
        Self {
            auth_details_json: String::new(),
            instance_profiles_json: None,
        }
    }

    /// Set JSON from `aws iam get-account-authorization-details`.
    pub fn auth_details_json(mut self, json: &str) -> Self {
        self.auth_details_json = json.to_string();
        self
    }

    /// Optionally set JSON from `aws iam list-instance-profiles`.
    pub fn instance_profiles_json(mut self, json: &str) -> Self {
        self.instance_profiles_json = Some(json.to_string());
        self
    }

    /// Validate the auth_details JSON (schema, not just syntax) and build the collector.
    pub fn build(self) -> Result<OfflineCollector, CollectorError> {
        // Parse to the typed struct so missing required fields are caught here,
        // not deferred to the first collect() call.
        let _: AccountAuthorizationDetails = serde_json::from_str(&self.auth_details_json)?;
        Ok(OfflineCollector {
            auth_details_json: self.auth_details_json,
            instance_profiles_json: self.instance_profiles_json,
        })
    }
}

impl Default for OfflineCollectorBuilder {
    fn default() -> Self {
        Self::new()
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

        let mut users: Vec<IamUser> = details
            .user_detail_list
            .into_iter()
            .map(IamUser::from)
            .collect();

        let mut groups: Vec<IamGroup> = details
            .group_detail_list
            .into_iter()
            .map(IamGroup::from)
            .collect();

        let mut roles: Vec<IamRole> = details
            .role_detail_list
            .into_iter()
            .map(IamRole::from)
            .collect();

        let mut policies: Vec<IamPolicy> =
            details.policies.into_iter().map(IamPolicy::from).collect();

        debug!(
            users = users.len(),
            roles = roles.len(),
            groups = groups.len(),
            policies = policies.len(),
            "deserialized offline entities"
        );

        // Expand wildcards in managed policy documents
        for policy in &mut policies {
            if let Some(doc) = policy.document.take() {
                policy.document = Some(try_expand(doc).await);
            }
        }

        // Expand wildcards in inline policies across all entity types
        for role in &mut roles {
            expand_inline_policies(&mut role.inline_policies).await;
        }
        for user in &mut users {
            expand_inline_policies(&mut user.inline_policies).await;
        }
        for group in &mut groups {
            expand_inline_policies(&mut group.inline_policies).await;
        }

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

        Ok(CollectedData {
            source: CollectorMode::Offline,
            account_id,
            policies,
            roles,
            users,
            groups,
            instance_profiles,
            collection_timestamp: Utc::now(),
            warnings,
        })
    }
}

/// Expand wildcards in each inline policy document in-place.
async fn expand_inline_policies(inlines: &mut Vec<IamInlinePolicy>) {
    let placeholder = PolicyDocument {
        version: None,
        statement: Vec::new(),
    };
    for inline in inlines {
        let doc = std::mem::replace(&mut inline.policy_document, placeholder.clone());
        inline.policy_document = try_expand(doc).await;
    }
}

/// Serialize a PolicyDocument to JSON, expand wildcards via iam-expander, then deserialize.
/// Falls back to the original document on any error.
async fn try_expand(doc: PolicyDocument) -> PolicyDocument {
    let json = match serde_json::to_string(&doc) {
        Ok(j) => j,
        Err(_) => return doc,
    };
    match iam_expander::expand_policy_document(&json).await {
        Ok(expanded_json) => serde_json::from_str(&expanded_json).unwrap_or(doc),
        Err(e) => {
            warn!(err = %e, "wildcard expansion failed, keeping original");
            doc
        }
    }
}
