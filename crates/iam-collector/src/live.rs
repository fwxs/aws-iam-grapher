use crate::errors::{CollectorError, CollectorWarning};
use crate::expand::expand_collected_data;
use crate::traits::{CollectedData, CollectorMode, IamDataSource};
use crate::util::{account_id_from_arns, map_sdk_error};
use aws_sdk_iam::error::SdkError;
use aws_sdk_iam::operation::get_login_profile::GetLoginProfileError;
use chrono::{DateTime, Utc};
use futures::stream::{self, StreamExt};
use iam_models::{
    AccessKeyMeta, AccessKeyStatus, IamGroup, IamInlinePolicy, IamInstanceProfile, IamPolicy,
    IamRole, IamUser, MfaDeviceType, PermissionsBoundary, PolicyDocument, PolicyRef, RoleLastUsed,
};
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};

/// Bounded concurrency for per-user enrichment calls (MFA/login/access-key lookups).
/// IAM rate-limits aggressively; this keeps a large account from tripping throttling.
const USER_ENRICHMENT_CONCURRENCY: usize = 8;

/// Collects IAM data from the live AWS API.
pub struct LiveCollector {
    iam_client: aws_sdk_iam::Client,
}

impl LiveCollector {
    /// Create a collector from an already-constructed IAM client (for testing).
    pub fn new(client: aws_sdk_iam::Client) -> Self {
        Self { iam_client: client }
    }

    /// Create a collector loading credentials from the environment.
    ///
    /// `regions` is the CLI `--region` flag: when non-empty, its first entry overrides
    /// whatever region the profile/environment resolves; otherwise falls back to that
    /// resolved region, then to `us-east-1`. See [`crate::resolve_region`].
    ///
    /// `profile` is the CLI `--profile` flag. See [`crate::credentials::resolve_config`] for
    /// the full credential-source precedence.
    pub async fn from_env(
        regions: &[String],
        profile: Option<&str>,
    ) -> Result<Self, CollectorError> {
        let config = crate::credentials::resolve_config(profile).await?;
        let region = crate::resolve_region(regions, config.region());
        info!(%region, "resolved AWS region for live collection");
        let config = config.into_builder().region(region).build();
        Ok(Self::new(aws_sdk_iam::Client::new(&config)))
    }
}

#[async_trait::async_trait]
impl IamDataSource for LiveCollector {
    async fn collect(&self) -> Result<CollectedData, CollectorError> {
        info!("starting live IAM collection");
        let mut warnings = Vec::new();

        let mut users: Vec<IamUser> = Vec::new();
        let mut roles: Vec<IamRole> = Vec::new();
        let mut groups: Vec<IamGroup> = Vec::new();
        let mut policies: Vec<IamPolicy> = Vec::new();

        info!("fetching GetAccountAuthorizationDetails");
        let mut paginator = self
            .iam_client
            .get_account_authorization_details()
            .into_paginator()
            .send();

        let mut page_count = 0u32;
        while let Some(page) = paginator.next().await {
            let page = page.map_err(map_sdk_error)?;
            page_count += 1;
            debug!(
                page = page_count,
                "processing GetAccountAuthorizationDetails page"
            );

            for u in page.user_detail_list() {
                users.push(sdk_user_to_model(u));
            }
            for r in page.role_detail_list() {
                roles.push(sdk_role_to_model(r));
            }
            for g in page.group_detail_list() {
                groups.push(sdk_group_to_model(g));
            }
            for p in page.policies() {
                policies.push(sdk_managed_policy_to_model(p));
            }
        }

        debug!(
            users = users.len(),
            roles = roles.len(),
            groups = groups.len(),
            policies = policies.len(),
            "collected entities"
        );

        info!(
            users = users.len(),
            "enriching users with MFA/login/activity data"
        );
        let user_names: Vec<(usize, String)> = users
            .iter()
            .enumerate()
            .map(|(i, u)| (i, u.user_name.clone()))
            .collect();
        let client = &self.iam_client;
        let enrichment_results: Vec<(usize, UserEnrichment, Vec<EnrichmentWarning>)> =
            stream::iter(user_names)
                .map(|(i, user_name)| async move {
                    let (enrichment, warns) = enrich_user(client, &user_name).await;
                    (i, enrichment, warns)
                })
                .buffer_unordered(USER_ENRICHMENT_CONCURRENCY)
                .collect()
                .await;

        let mut enrichment_warnings: HashSet<EnrichmentWarning> = HashSet::new();
        for (i, enrichment, warns) in enrichment_results {
            users[i].has_mfa = enrichment.has_mfa;
            users[i].mfa_method = enrichment.mfa_method;
            users[i].console_login_enabled = enrichment.console_login_enabled;
            users[i].password_last_used = enrichment.password_last_used;
            users[i].last_activity_date = enrichment.last_activity_date;
            users[i].access_keys = enrichment.access_keys;
            enrichment_warnings.extend(warns);
        }
        if enrichment_warnings.contains(&EnrichmentWarning::Mfa) {
            warn!("insufficient permissions for ListMFADevices on one or more users");
            warnings.push(CollectorWarning::MfaDevicesMissing);
        }
        if enrichment_warnings.contains(&EnrichmentWarning::LoginProfile) {
            warn!("insufficient permissions for GetLoginProfile on one or more users");
            warnings.push(CollectorWarning::LoginProfileMissing);
        }
        if enrichment_warnings.contains(&EnrichmentWarning::AccessKeyActivity) {
            warn!("insufficient permissions for access key activity lookups on one or more users");
            warnings.push(CollectorWarning::AccessKeyActivityMissing);
        }

        // Paginate ListInstanceProfiles (non-fatal on 403)
        info!("fetching ListInstanceProfiles");
        let mut instance_profiles: Vec<IamInstanceProfile> = Vec::new();
        let mut ip_paginator = self
            .iam_client
            .list_instance_profiles()
            .into_paginator()
            .send();

        loop {
            match ip_paginator.next().await {
                None => break,
                Some(Err(e)) => {
                    let mapped = map_sdk_error(e);
                    if matches!(mapped, CollectorError::InsufficientPermissions(_)) {
                        warn!("insufficient permissions for ListInstanceProfiles — skipping");
                        warnings.push(CollectorWarning::InstanceProfilesMissing);
                        break;
                    }
                    return Err(mapped);
                }
                Some(Ok(page)) => {
                    for ip in page.instance_profiles() {
                        instance_profiles.push(sdk_instance_profile_to_model(ip));
                    }
                }
            }
        }

        info!(
            instance_profiles = instance_profiles.len(),
            "live collection complete"
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
            source: CollectorMode::Live,
            account_id,
            ou_id: None,
            ou_name: None,
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

// ---------------------------------------------------------------------------
// SDK type → iam-models type conversions
// ---------------------------------------------------------------------------

/// Convert an AWS smithy DateTime to chrono UTC. Calling `.secs()` and
/// `.subsec_nanos()` works without naming `aws_smithy_types::DateTime`
/// directly in our Cargo.toml because the type comes from the SDK.
macro_rules! sdk_dt {
    ($opt:expr) => {
        $opt.and_then(|d| DateTime::from_timestamp(d.secs(), d.subsec_nanos()))
            .unwrap_or_else(Utc::now)
    };
}

fn parse_policy_doc(s: Option<&str>) -> Option<PolicyDocument> {
    let s = s?;
    serde_json::from_str(s)
        .or_else(|_| serde_json::from_str(&percent_decode(s)))
        .ok()
}

fn percent_decode(s: &str) -> String {
    let mut result = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Some(byte) = std::str::from_utf8(&bytes[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                result.push(byte);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            result.push(b' ');
            i += 1;
            continue;
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).into_owned()
}

fn sdk_policy_ref(p: &aws_sdk_iam::types::AttachedPolicy) -> PolicyRef {
    PolicyRef {
        policy_arn: p.policy_arn().unwrap_or_default().to_string(),
        policy_name: p.policy_name().unwrap_or_default().to_string(),
    }
}

fn sdk_boundary(
    b: Option<&aws_sdk_iam::types::AttachedPermissionsBoundary>,
) -> Option<PermissionsBoundary> {
    b.map(|b| PermissionsBoundary {
        permissions_boundary_type: b
            .permissions_boundary_type()
            .map(|t| t.as_str().to_string())
            .unwrap_or_default(),
        permissions_boundary_arn: b.permissions_boundary_arn().unwrap_or_default().to_string(),
    })
}

fn sdk_inline(p: &aws_sdk_iam::types::PolicyDetail) -> Option<IamInlinePolicy> {
    let name = p.policy_name()?.to_string();
    let doc = parse_policy_doc(p.policy_document())?;
    Some(IamInlinePolicy {
        policy_name: name,
        policy_document: doc,
    })
}

fn sdk_tags(tags: &[aws_sdk_iam::types::Tag]) -> HashMap<String, String> {
    tags.iter()
        .map(|t| (t.key().to_string(), t.value().to_string()))
        .collect()
}

fn sdk_user_to_model(u: &aws_sdk_iam::types::UserDetail) -> IamUser {
    IamUser {
        arn: u.arn().unwrap_or_default().to_string(),
        user_id: u.user_id().unwrap_or_default().to_string(),
        user_name: u.user_name().unwrap_or_default().to_string(),
        path: u.path().unwrap_or("/").to_string(),
        create_date: sdk_dt!(u.create_date()),
        attached_managed_policies: u
            .attached_managed_policies()
            .iter()
            .map(sdk_policy_ref)
            .collect(),
        inline_policies: u.user_policy_list().iter().filter_map(sdk_inline).collect(),
        group_list: u.group_list().to_vec(),
        permissions_boundary: sdk_boundary(u.permissions_boundary()),
        // GetAccountAuthorizationDetails' UserDetail carries no password_last_used field
        // (unlike ListUsers/GetUser's User type); populated by enrich_user() below.
        password_last_used: None,
        access_keys: Vec::new(),
        is_aws_managed: false,
        tags: sdk_tags(u.tags()),
        has_mfa: false,
        mfa_method: None,
        console_login_enabled: false,
        last_activity_date: None,
    }
}

fn sdk_group_to_model(g: &aws_sdk_iam::types::GroupDetail) -> IamGroup {
    IamGroup {
        arn: g.arn().unwrap_or_default().to_string(),
        group_id: g.group_id().unwrap_or_default().to_string(),
        group_name: g.group_name().unwrap_or_default().to_string(),
        path: g.path().unwrap_or("/").to_string(),
        create_date: sdk_dt!(g.create_date()),
        attached_managed_policies: g
            .attached_managed_policies()
            .iter()
            .map(sdk_policy_ref)
            .collect(),
        inline_policies: g
            .group_policy_list()
            .iter()
            .filter_map(sdk_inline)
            .collect(),
    }
}

fn sdk_role_to_model(r: &aws_sdk_iam::types::RoleDetail) -> IamRole {
    let is_aws_managed = r.path().unwrap_or("/").starts_with("/aws-service-role/");
    let role_last_used = r.role_last_used().map(|rlu| RoleLastUsed {
        last_used_date: rlu
            .last_used_date()
            .and_then(|d| DateTime::from_timestamp(d.secs(), d.subsec_nanos())),
        region: rlu.region().map(|s| s.to_string()),
    });
    IamRole {
        arn: r.arn().unwrap_or_default().to_string(),
        role_id: r.role_id().unwrap_or_default().to_string(),
        role_name: r.role_name().unwrap_or_default().to_string(),
        path: r.path().unwrap_or("/").to_string(),
        create_date: sdk_dt!(r.create_date()),
        assume_role_policy_document: parse_policy_doc(r.assume_role_policy_document()),
        attached_managed_policies: r
            .attached_managed_policies()
            .iter()
            .map(sdk_policy_ref)
            .collect(),
        inline_policies: r.role_policy_list().iter().filter_map(sdk_inline).collect(),
        permissions_boundary: sdk_boundary(r.permissions_boundary()),
        role_last_used,
        description: None,
        max_session_duration: None,
        is_aws_managed,
        tags: sdk_tags(r.tags()),
    }
}

fn sdk_managed_policy_to_model(p: &aws_sdk_iam::types::ManagedPolicyDetail) -> IamPolicy {
    let arn = p.arn().unwrap_or_default().to_string();
    let is_aws_managed = arn.contains(":aws:policy/");
    let document = p
        .policy_version_list()
        .iter()
        .find(|v| v.is_default_version())
        .and_then(|v| parse_policy_doc(v.document()));
    IamPolicy {
        arn,
        policy_id: p.policy_id().unwrap_or_default().to_string(),
        policy_name: p.policy_name().unwrap_or_default().to_string(),
        path: p.path().unwrap_or("/").to_string(),
        create_date: sdk_dt!(p.create_date()),
        update_date: sdk_dt!(p.update_date()),
        attachment_count: p.attachment_count().unwrap_or(0),
        is_attachable: p.is_attachable(),
        default_version_id: p.default_version_id().unwrap_or("v1").to_string(),
        description: p.description().map(|s| s.to_string()),
        is_aws_managed,
        document,
        tags: HashMap::new(),
    }
}

fn sdk_role_from_role_type(r: &aws_sdk_iam::types::Role) -> IamRole {
    let is_aws_managed = r.path().starts_with("/aws-service-role/");
    let role_last_used = r.role_last_used().map(|rlu| RoleLastUsed {
        last_used_date: rlu
            .last_used_date()
            .and_then(|d| DateTime::from_timestamp(d.secs(), d.subsec_nanos())),
        region: rlu.region().map(|s| s.to_string()),
    });
    IamRole {
        arn: r.arn().to_string(),
        role_id: r.role_id().to_string(),
        role_name: r.role_name().to_string(),
        path: r.path().to_string(),
        create_date: DateTime::from_timestamp(
            r.create_date().secs(),
            r.create_date().subsec_nanos(),
        )
        .unwrap_or_else(Utc::now),
        assume_role_policy_document: parse_policy_doc(r.assume_role_policy_document()),
        attached_managed_policies: Vec::new(),
        inline_policies: Vec::new(),
        permissions_boundary: None,
        role_last_used,
        description: r.description().map(|s| s.to_string()),
        max_session_duration: r.max_session_duration(),
        is_aws_managed,
        tags: sdk_tags(r.tags()),
    }
}

fn sdk_instance_profile_to_model(ip: &aws_sdk_iam::types::InstanceProfile) -> IamInstanceProfile {
    let is_aws_managed = ip.path().starts_with("/aws-service-role/");
    let roles = ip.roles().iter().map(sdk_role_from_role_type).collect();
    IamInstanceProfile {
        arn: ip.arn().to_string(),
        instance_profile_id: ip.instance_profile_id().to_string(),
        instance_profile_name: ip.instance_profile_name().to_string(),
        path: ip.path().to_string(),
        create_date: DateTime::from_timestamp(
            ip.create_date().secs(),
            ip.create_date().subsec_nanos(),
        )
        .unwrap_or_else(Utc::now),
        roles,
        is_aws_managed,
    }
}

// ---------------------------------------------------------------------------
// Per-user enrichment (MFA, console login, activity)
// ---------------------------------------------------------------------------

struct UserEnrichment {
    has_mfa: bool,
    mfa_method: Option<MfaDeviceType>,
    console_login_enabled: bool,
    password_last_used: Option<DateTime<Utc>>,
    last_activity_date: Option<DateTime<Utc>>,
    access_keys: Vec<AccessKeyMeta>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum EnrichmentWarning {
    Mfa,
    LoginProfile,
    AccessKeyActivity,
}

fn sdk_dt_opt(d: Option<&aws_smithy_types::DateTime>) -> Option<DateTime<Utc>> {
    d.and_then(|d| DateTime::from_timestamp(d.secs(), d.subsec_nanos()))
}

fn max_option(a: Option<DateTime<Utc>>, b: Option<DateTime<Utc>>) -> Option<DateTime<Utc>> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(d), None) | (None, Some(d)) => Some(d),
        (None, None) => None,
    }
}

/// Fetch MFA, console login, and activity data for a single user. Every call is
/// non-fatal: a failure is recorded as a warning (except `GetLoginProfile`'s
/// `NoSuchEntity`, which means "no console login" and is not an error) and the
/// corresponding field is left at its default.
async fn enrich_user(
    client: &aws_sdk_iam::Client,
    user_name: &str,
) -> (UserEnrichment, Vec<EnrichmentWarning>) {
    let mut warnings = Vec::new();

    let (has_mfa, mfa_method) = match client.list_mfa_devices().user_name(user_name).send().await {
        Ok(out) => {
            let device = out.mfa_devices().first();
            let method = device.and_then(|d| MfaDeviceType::from_serial(d.serial_number()));
            (device.is_some(), method)
        }
        Err(e) => {
            debug!(%user_name, error = ?e, "ListMFADevices failed");
            warnings.push(EnrichmentWarning::Mfa);
            (false, None)
        }
    };

    let console_login_enabled = match client.get_login_profile().user_name(user_name).send().await {
        Ok(_) => true,
        Err(SdkError::ServiceError(ref se))
            if matches!(se.err(), GetLoginProfileError::NoSuchEntityException(_)) =>
        {
            false
        }
        Err(e) => {
            debug!(%user_name, error = ?e, "GetLoginProfile failed");
            warnings.push(EnrichmentWarning::LoginProfile);
            false
        }
    };

    // GetUser is the only source for password_last_used: GetAccountAuthorizationDetails'
    // UserDetail does not carry this field. A failure here is folded into the access-key
    // warning bucket rather than a fourth warning kind, since it feeds the same
    // last_activity_date computation.
    let mut access_key_ok = true;
    let password_last_used = match client.get_user().user_name(user_name).send().await {
        Ok(out) => out.user().and_then(|u| sdk_dt_opt(u.password_last_used())),
        Err(e) => {
            debug!(%user_name, error = ?e, "GetUser failed");
            access_key_ok = false;
            None
        }
    };

    let mut last_activity_date = password_last_used;
    let mut access_keys: Vec<AccessKeyMeta> = Vec::new();
    match client.list_access_keys().user_name(user_name).send().await {
        Ok(out) => {
            for key in out.access_key_metadata() {
                let Some(key_id) = key.access_key_id() else {
                    continue;
                };
                let status = match key.status() {
                    Some(aws_sdk_iam::types::StatusType::Active) => AccessKeyStatus::Active,
                    _ => AccessKeyStatus::Inactive,
                };
                let create_date = match sdk_dt_opt(key.create_date()) {
                    Some(d) => d,
                    None => {
                        debug!(%user_name, %key_id, "access key CreateDate missing or unparseable");
                        access_key_ok = false;
                        Utc::now()
                    }
                };

                // A key we know exists but can't date is still signal — keep it in the
                // result with `last_used_date: None` rather than dropping it, and fold
                // the failure into the existing AccessKeyActivity warning.
                let (last_used_date, last_used_service, last_used_region) = match client
                    .get_access_key_last_used()
                    .access_key_id(key_id)
                    .send()
                    .await
                {
                    Ok(lu) => {
                        let used = lu
                            .access_key_last_used()
                            .and_then(|a| sdk_dt_opt(a.last_used_date()));
                        last_activity_date = max_option(last_activity_date, used);
                        let service = lu
                            .access_key_last_used()
                            .map(|a| a.service_name())
                            .filter(|s| *s != "N/A")
                            .map(String::from);
                        let region = lu
                            .access_key_last_used()
                            .map(|a| a.region())
                            .filter(|r| *r != "N/A")
                            .map(String::from);
                        (used, service, region)
                    }
                    Err(e) => {
                        debug!(%user_name, %key_id, error = ?e, "GetAccessKeyLastUsed failed");
                        access_key_ok = false;
                        (None, None, None)
                    }
                };

                access_keys.push(AccessKeyMeta {
                    access_key_id: key_id.to_string(),
                    status,
                    create_date,
                    last_used_date,
                    last_used_service,
                    last_used_region,
                });
            }
        }
        Err(e) => {
            debug!(%user_name, error = ?e, "ListAccessKeys failed");
            access_key_ok = false;
        }
    }
    if !access_key_ok {
        warnings.push(EnrichmentWarning::AccessKeyActivity);
    }

    (
        UserEnrichment {
            has_mfa,
            mfa_method,
            console_login_enabled,
            password_last_used,
            last_activity_date,
            access_keys,
        },
        warnings,
    )
}

#[cfg(test)]
mod enrichment_tests {
    use super::*;
    use aws_smithy_mocks::{mock, mock_client, RuleMode};

    fn mfa_device(user_name: &str, serial: &str) -> aws_sdk_iam::types::MfaDevice {
        aws_sdk_iam::types::MfaDevice::builder()
            .user_name(user_name)
            .serial_number(serial)
            .enable_date(aws_smithy_types::DateTime::from_secs(1_700_000_000))
            .build()
            .expect("valid MfaDevice")
    }

    fn login_profile_output(
        user_name: &str,
    ) -> aws_sdk_iam::operation::get_login_profile::GetLoginProfileOutput {
        aws_sdk_iam::operation::get_login_profile::GetLoginProfileOutput::builder()
            .login_profile(
                aws_sdk_iam::types::LoginProfile::builder()
                    .user_name(user_name)
                    .create_date(aws_smithy_types::DateTime::from_secs(1_700_000_000))
                    .build()
                    .expect("valid LoginProfile"),
            )
            .build()
    }

    fn no_such_entity_error() -> aws_sdk_iam::operation::get_login_profile::GetLoginProfileError {
        aws_sdk_iam::operation::get_login_profile::GetLoginProfileError::NoSuchEntityException(
            aws_sdk_iam::types::error::NoSuchEntityException::builder()
                .message("no login profile")
                .build(),
        )
    }

    fn access_denied_login_profile_error(
    ) -> aws_sdk_iam::operation::get_login_profile::GetLoginProfileError {
        aws_sdk_iam::operation::get_login_profile::GetLoginProfileError::generic(
            aws_smithy_types::error::ErrorMetadata::builder()
                .code("AccessDenied")
                .build(),
        )
    }

    fn get_user_output(
        user_name: &str,
        password_last_used_secs: Option<i64>,
    ) -> aws_sdk_iam::operation::get_user::GetUserOutput {
        let mut builder = aws_sdk_iam::types::User::builder()
            .path("/")
            .user_name(user_name)
            .user_id("AIDAEXAMPLE")
            .arn(format!("arn:aws:iam::123456789012:user/{user_name}"))
            .create_date(aws_smithy_types::DateTime::from_secs(1_600_000_000));
        if let Some(secs) = password_last_used_secs {
            builder = builder.password_last_used(aws_smithy_types::DateTime::from_secs(secs));
        }
        aws_sdk_iam::operation::get_user::GetUserOutput::builder()
            .user(builder.build().expect("valid User"))
            .build()
    }

    fn empty_access_keys_output() -> aws_sdk_iam::operation::list_access_keys::ListAccessKeysOutput
    {
        aws_sdk_iam::operation::list_access_keys::ListAccessKeysOutput::builder()
            .set_access_key_metadata(Some(Vec::new()))
            .is_truncated(false)
            .build()
            .expect("valid ListAccessKeysOutput")
    }

    fn access_keys_output(
        user_name: &str,
        key_id: &str,
    ) -> aws_sdk_iam::operation::list_access_keys::ListAccessKeysOutput {
        aws_sdk_iam::operation::list_access_keys::ListAccessKeysOutput::builder()
            .access_key_metadata(
                aws_sdk_iam::types::AccessKeyMetadata::builder()
                    .user_name(user_name)
                    .access_key_id(key_id)
                    .status(aws_sdk_iam::types::StatusType::Active)
                    .create_date(aws_smithy_types::DateTime::from_secs(1_600_000_000))
                    .build(),
            )
            .is_truncated(false)
            .build()
            .expect("valid ListAccessKeysOutput")
    }

    fn access_key_last_used_output(
        last_used_secs: Option<i64>,
    ) -> aws_sdk_iam::operation::get_access_key_last_used::GetAccessKeyLastUsedOutput {
        let mut builder = aws_sdk_iam::types::AccessKeyLastUsed::builder()
            .service_name("s3")
            .region("us-east-1");
        if let Some(secs) = last_used_secs {
            builder = builder.last_used_date(aws_smithy_types::DateTime::from_secs(secs));
        }
        aws_sdk_iam::operation::get_access_key_last_used::GetAccessKeyLastUsedOutput::builder()
            .access_key_last_used(builder.build().expect("valid AccessKeyLastUsed"))
            .build()
    }

    /// Client whose calls all succeed with empty/default responses: no MFA devices, no
    /// console login (`NoSuchEntity`), no password use, no access keys.
    fn baseline_client() -> aws_sdk_iam::Client {
        let mfa_rule = mock!(aws_sdk_iam::Client::list_mfa_devices).then_output(|| {
            aws_sdk_iam::operation::list_mfa_devices::ListMfaDevicesOutput::builder()
                .set_mfa_devices(Some(Vec::new()))
                .is_truncated(false)
                .build()
                .expect("valid ListMfaDevicesOutput")
        });
        let login_rule =
            mock!(aws_sdk_iam::Client::get_login_profile).then_error(no_such_entity_error);
        let get_user_rule =
            mock!(aws_sdk_iam::Client::get_user).then_output(|| get_user_output("alice", None));
        let keys_rule =
            mock!(aws_sdk_iam::Client::list_access_keys).then_output(empty_access_keys_output);
        mock_client!(
            aws_sdk_iam,
            RuleMode::MatchAny,
            &[&mfa_rule, &login_rule, &get_user_rule, &keys_rule]
        )
    }

    #[tokio::test]
    async fn enrich_user_baseline_has_no_mfa_no_login_no_activity() {
        let client = baseline_client();
        let (enrichment, warnings) = enrich_user(&client, "alice").await;

        assert!(!enrichment.has_mfa);
        assert!(enrichment.mfa_method.is_none());
        assert!(!enrichment.console_login_enabled);
        assert!(enrichment.last_activity_date.is_none());
        assert!(warnings.is_empty(), "no warnings expected: {warnings:?}");
    }

    #[tokio::test]
    async fn enrich_user_detects_virtual_mfa_device() {
        let mfa_rule = mock!(aws_sdk_iam::Client::list_mfa_devices).then_output(|| {
            aws_sdk_iam::operation::list_mfa_devices::ListMfaDevicesOutput::builder()
                .mfa_devices(mfa_device("alice", "arn:aws:iam::123456789012:mfa/alice"))
                .is_truncated(false)
                .build()
                .expect("valid ListMfaDevicesOutput")
        });
        let login_rule =
            mock!(aws_sdk_iam::Client::get_login_profile).then_error(no_such_entity_error);
        let get_user_rule =
            mock!(aws_sdk_iam::Client::get_user).then_output(|| get_user_output("alice", None));
        let keys_rule =
            mock!(aws_sdk_iam::Client::list_access_keys).then_output(empty_access_keys_output);
        let client = mock_client!(
            aws_sdk_iam,
            RuleMode::MatchAny,
            &[&mfa_rule, &login_rule, &get_user_rule, &keys_rule]
        );

        let (enrichment, warnings) = enrich_user(&client, "alice").await;

        assert!(enrichment.has_mfa);
        assert_eq!(enrichment.mfa_method, Some(MfaDeviceType::Virtual));
        assert!(warnings.is_empty(), "no warnings expected: {warnings:?}");
    }

    #[tokio::test]
    async fn enrich_user_list_mfa_devices_denied_pushes_warning() {
        let mfa_rule = mock!(aws_sdk_iam::Client::list_mfa_devices).then_error(|| {
            aws_sdk_iam::operation::list_mfa_devices::ListMFADevicesError::generic(
                aws_smithy_types::error::ErrorMetadata::builder()
                    .code("AccessDenied")
                    .build(),
            )
        });
        let login_rule =
            mock!(aws_sdk_iam::Client::get_login_profile).then_error(no_such_entity_error);
        let get_user_rule =
            mock!(aws_sdk_iam::Client::get_user).then_output(|| get_user_output("alice", None));
        let keys_rule =
            mock!(aws_sdk_iam::Client::list_access_keys).then_output(empty_access_keys_output);
        let client = mock_client!(
            aws_sdk_iam,
            RuleMode::MatchAny,
            &[&mfa_rule, &login_rule, &get_user_rule, &keys_rule]
        );

        let (enrichment, warnings) = enrich_user(&client, "alice").await;

        assert!(!enrichment.has_mfa);
        assert_eq!(warnings, vec![EnrichmentWarning::Mfa]);
    }

    #[tokio::test]
    async fn enrich_user_console_login_true_when_profile_present() {
        let mfa_rule = mock!(aws_sdk_iam::Client::list_mfa_devices).then_output(|| {
            aws_sdk_iam::operation::list_mfa_devices::ListMfaDevicesOutput::builder()
                .set_mfa_devices(Some(Vec::new()))
                .is_truncated(false)
                .build()
                .expect("valid ListMfaDevicesOutput")
        });
        let login_rule = mock!(aws_sdk_iam::Client::get_login_profile)
            .then_output(|| login_profile_output("alice"));
        let get_user_rule =
            mock!(aws_sdk_iam::Client::get_user).then_output(|| get_user_output("alice", None));
        let keys_rule =
            mock!(aws_sdk_iam::Client::list_access_keys).then_output(empty_access_keys_output);
        let client = mock_client!(
            aws_sdk_iam,
            RuleMode::MatchAny,
            &[&mfa_rule, &login_rule, &get_user_rule, &keys_rule]
        );

        let (enrichment, warnings) = enrich_user(&client, "alice").await;

        assert!(enrichment.console_login_enabled);
        assert!(warnings.is_empty(), "no warnings expected: {warnings:?}");
    }

    #[tokio::test]
    async fn enrich_user_console_login_no_such_entity_is_false_without_warning() {
        // NoSuchEntity means "no login profile" — this is a valid, non-error result.
        let client = baseline_client();
        let (enrichment, warnings) = enrich_user(&client, "alice").await;

        assert!(!enrichment.console_login_enabled);
        assert!(
            !warnings.contains(&EnrichmentWarning::LoginProfile),
            "NoSuchEntity must not produce a warning: {warnings:?}"
        );
    }

    #[tokio::test]
    async fn enrich_user_login_profile_other_error_pushes_warning() {
        let mfa_rule = mock!(aws_sdk_iam::Client::list_mfa_devices).then_output(|| {
            aws_sdk_iam::operation::list_mfa_devices::ListMfaDevicesOutput::builder()
                .set_mfa_devices(Some(Vec::new()))
                .is_truncated(false)
                .build()
                .expect("valid ListMfaDevicesOutput")
        });
        let login_rule = mock!(aws_sdk_iam::Client::get_login_profile)
            .then_error(access_denied_login_profile_error);
        let get_user_rule =
            mock!(aws_sdk_iam::Client::get_user).then_output(|| get_user_output("alice", None));
        let keys_rule =
            mock!(aws_sdk_iam::Client::list_access_keys).then_output(empty_access_keys_output);
        let client = mock_client!(
            aws_sdk_iam,
            RuleMode::MatchAny,
            &[&mfa_rule, &login_rule, &get_user_rule, &keys_rule]
        );

        let (enrichment, warnings) = enrich_user(&client, "alice").await;

        assert!(!enrichment.console_login_enabled);
        assert_eq!(warnings, vec![EnrichmentWarning::LoginProfile]);
    }

    #[tokio::test]
    async fn enrich_user_last_activity_is_max_of_password_and_key_last_used() {
        // password_last_used (T1) is older than the access key's last-used date (T2);
        // last_activity_date must be the max, T2.
        let t1 = 1_700_000_000;
        let t2 = 1_800_000_000;

        let mfa_rule = mock!(aws_sdk_iam::Client::list_mfa_devices).then_output(|| {
            aws_sdk_iam::operation::list_mfa_devices::ListMfaDevicesOutput::builder()
                .set_mfa_devices(Some(Vec::new()))
                .is_truncated(false)
                .build()
                .expect("valid ListMfaDevicesOutput")
        });
        let login_rule =
            mock!(aws_sdk_iam::Client::get_login_profile).then_error(no_such_entity_error);
        let get_user_rule = mock!(aws_sdk_iam::Client::get_user)
            .then_output(move || get_user_output("alice", Some(t1)));
        let keys_rule = mock!(aws_sdk_iam::Client::list_access_keys)
            .then_output(|| access_keys_output("alice", "AKIAEXAMPLE"));
        let last_used_rule = mock!(aws_sdk_iam::Client::get_access_key_last_used)
            .then_output(move || access_key_last_used_output(Some(t2)));
        let client = mock_client!(
            aws_sdk_iam,
            RuleMode::MatchAny,
            &[
                &mfa_rule,
                &login_rule,
                &get_user_rule,
                &keys_rule,
                &last_used_rule
            ]
        );

        let (enrichment, warnings) = enrich_user(&client, "alice").await;

        let expected = DateTime::from_timestamp(t2, 0).unwrap();
        assert_eq!(enrichment.last_activity_date, Some(expected));
        assert!(warnings.is_empty(), "no warnings expected: {warnings:?}");

        assert_eq!(enrichment.access_keys.len(), 1);
        let key = &enrichment.access_keys[0];
        assert_eq!(key.access_key_id, "AKIAEXAMPLE");
        assert_eq!(key.status, AccessKeyStatus::Active);
        assert_eq!(
            key.last_used_date,
            Some(DateTime::from_timestamp(t2, 0).unwrap())
        );
        assert_eq!(key.last_used_service, Some("s3".to_string()));
        assert_eq!(key.last_used_region, Some("us-east-1".to_string()));
    }

    #[tokio::test]
    async fn enrich_user_access_key_last_used_error_still_yields_key_with_no_last_used_date() {
        let mfa_rule = mock!(aws_sdk_iam::Client::list_mfa_devices).then_output(|| {
            aws_sdk_iam::operation::list_mfa_devices::ListMfaDevicesOutput::builder()
                .set_mfa_devices(Some(Vec::new()))
                .is_truncated(false)
                .build()
                .expect("valid ListMfaDevicesOutput")
        });
        let login_rule =
            mock!(aws_sdk_iam::Client::get_login_profile).then_error(no_such_entity_error);
        let get_user_rule =
            mock!(aws_sdk_iam::Client::get_user).then_output(|| get_user_output("alice", None));
        let keys_rule = mock!(aws_sdk_iam::Client::list_access_keys)
            .then_output(|| access_keys_output("alice", "AKIAEXAMPLE"));
        let last_used_rule = mock!(aws_sdk_iam::Client::get_access_key_last_used).then_error(
            || {
                aws_sdk_iam::operation::get_access_key_last_used::GetAccessKeyLastUsedError::generic(
                    aws_smithy_types::error::ErrorMetadata::builder()
                        .code("AccessDenied")
                        .build(),
                )
            },
        );
        let client = mock_client!(
            aws_sdk_iam,
            RuleMode::MatchAny,
            &[
                &mfa_rule,
                &login_rule,
                &get_user_rule,
                &keys_rule,
                &last_used_rule
            ]
        );

        let (enrichment, warnings) = enrich_user(&client, "alice").await;

        // A key we know exists but couldn't date is still signal — keep it in the
        // result with last_used_date: None, rather than dropping it.
        assert_eq!(enrichment.access_keys.len(), 1);
        let key = &enrichment.access_keys[0];
        assert_eq!(key.access_key_id, "AKIAEXAMPLE");
        assert_eq!(key.last_used_date, None);
        assert!(warnings.contains(&EnrichmentWarning::AccessKeyActivity));
    }

    #[tokio::test]
    async fn enrich_user_last_activity_prefers_password_last_used_when_more_recent() {
        let t1 = 1_800_000_000;
        let t2 = 1_700_000_000;

        let mfa_rule = mock!(aws_sdk_iam::Client::list_mfa_devices).then_output(|| {
            aws_sdk_iam::operation::list_mfa_devices::ListMfaDevicesOutput::builder()
                .set_mfa_devices(Some(Vec::new()))
                .is_truncated(false)
                .build()
                .expect("valid ListMfaDevicesOutput")
        });
        let login_rule =
            mock!(aws_sdk_iam::Client::get_login_profile).then_error(no_such_entity_error);
        let get_user_rule = mock!(aws_sdk_iam::Client::get_user)
            .then_output(move || get_user_output("alice", Some(t1)));
        let keys_rule = mock!(aws_sdk_iam::Client::list_access_keys)
            .then_output(|| access_keys_output("alice", "AKIAEXAMPLE"));
        let last_used_rule = mock!(aws_sdk_iam::Client::get_access_key_last_used)
            .then_output(move || access_key_last_used_output(Some(t2)));
        let client = mock_client!(
            aws_sdk_iam,
            RuleMode::MatchAny,
            &[
                &mfa_rule,
                &login_rule,
                &get_user_rule,
                &keys_rule,
                &last_used_rule
            ]
        );

        let (enrichment, warnings) = enrich_user(&client, "alice").await;

        let expected = DateTime::from_timestamp(t1, 0).unwrap();
        assert_eq!(enrichment.last_activity_date, Some(expected));
        assert!(warnings.is_empty(), "no warnings expected: {warnings:?}");
    }

    #[tokio::test]
    async fn enrich_user_list_access_keys_denied_pushes_warning() {
        let mfa_rule = mock!(aws_sdk_iam::Client::list_mfa_devices).then_output(|| {
            aws_sdk_iam::operation::list_mfa_devices::ListMfaDevicesOutput::builder()
                .set_mfa_devices(Some(Vec::new()))
                .is_truncated(false)
                .build()
                .expect("valid ListMfaDevicesOutput")
        });
        let login_rule =
            mock!(aws_sdk_iam::Client::get_login_profile).then_error(no_such_entity_error);
        let get_user_rule =
            mock!(aws_sdk_iam::Client::get_user).then_output(|| get_user_output("alice", None));
        let keys_rule = mock!(aws_sdk_iam::Client::list_access_keys).then_error(|| {
            aws_sdk_iam::operation::list_access_keys::ListAccessKeysError::generic(
                aws_smithy_types::error::ErrorMetadata::builder()
                    .code("AccessDenied")
                    .build(),
            )
        });
        let client = mock_client!(
            aws_sdk_iam,
            RuleMode::MatchAny,
            &[&mfa_rule, &login_rule, &get_user_rule, &keys_rule]
        );

        let (enrichment, warnings) = enrich_user(&client, "alice").await;

        assert!(enrichment.last_activity_date.is_none());
        assert_eq!(warnings, vec![EnrichmentWarning::AccessKeyActivity]);
    }
}
