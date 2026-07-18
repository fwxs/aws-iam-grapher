use crate::errors::{CollectorError, CollectorWarning};
use crate::live::LiveCollector;
use crate::traits::CollectedData;
use crate::traits::IamDataSource;
use crate::util::map_sdk_error;
use aws_sdk_iam::config::{Credentials, ProvideCredentials, Region};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::time::SystemTime;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// One AWS account enumerated from the organization, with its OU path (root id first).
#[derive(Debug, Clone)]
pub struct OrgAccount {
    pub id: String,
    pub name: String,
    pub ou_path: Vec<String>,
    /// Immediate parent OU id, or `None` if the account sits directly under the org root
    /// (the root itself is not an organizational unit).
    pub ou_id: Option<String>,
    /// Immediate parent OU display name, or `None` if the account sits directly under the
    /// org root.
    pub ou_name: Option<String>,
    /// Named local AWS profile to collect this account with instead of assume-role, resolved
    /// from `--ou-profile-override` against this account's OU ancestry (most specific/innermost
    /// matching OU wins). `None` means the default assume-role path applies.
    pub profile_override: Option<String>,
}

/// `--exclude-ou-id` / `--exclude-ou-name` entries that never matched any OU encountered
/// while walking the org tree.
#[derive(Debug, Default)]
struct UnmatchedExcludes {
    ids: Vec<String>,
    names: Vec<String>,
}

#[cfg(test)]
impl UnmatchedExcludes {
    fn is_empty(&self) -> bool {
        self.ids.is_empty() && self.names.is_empty()
    }
}

/// Tracks which `--exclude-ou-id` / `--exclude-ou-name` entries matched an OU during the walk,
/// so [`OrgCollector::enumerate_accounts`] can report the ones that never did.
#[derive(Debug, Default)]
struct MatchedExcludes {
    matched_ids: std::collections::HashSet<String>,
    matched_names: std::collections::HashSet<String>,
}

/// Mutable accumulators threaded through the recursive [`OrgCollector::collect_accounts_under`]
/// walk. Bundled into one struct so the walk stays under clippy's argument-count lint instead of
/// carrying three separate `&mut` accumulators as positional parameters.
struct WalkState<'a> {
    out: &'a mut Vec<OrgAccount>,
    matched_excludes: &'a mut MatchedExcludes,
    matched_overrides: &'a mut std::collections::HashSet<String>,
}

/// Result of one AWS Organizations collection run: one `CollectedData` per account that
/// was successfully collected, all tagged with a shared `run_id`.
#[derive(Debug, Clone)]
pub struct OrgCollectionResult {
    pub run_id: String,
    pub accounts: Vec<CollectedData>,
    pub warnings: Vec<CollectorWarning>,
}

/// Builds an IAM client from assumed-role credentials. Abstracted behind a trait so tests
/// can inject pre-built mock clients per account instead of exercising real config plumbing.
trait IamClientFactory: Send + Sync {
    fn build(&self, account_id: &str, creds: Credentials, region: Region) -> aws_sdk_iam::Client;
}

struct RealIamClientFactory;

impl IamClientFactory for RealIamClientFactory {
    fn build(&self, _account_id: &str, creds: Credentials, region: Region) -> aws_sdk_iam::Client {
        let config = aws_sdk_iam::Config::builder()
            .behavior_version_latest()
            .region(region)
            .credentials_provider(creds)
            .build();
        aws_sdk_iam::Client::from_conf(config)
    }
}

/// Resolves independent SDK configs for org discovery and jump-role assumption.
///
/// These must never share a credential chain: `management_profile` is allowed to resolve to an
/// already-assumed role (SSO, `role_arn`/`source_profile` chaining, ...), and reusing those
/// credentials to call `sts:AssumeRole` again into a member account would be a double-hop
/// assumption that most jump-role trust policies reject. `jump_from_profile` — or, if `None`,
/// the standard AWS credential chain — is used for role assumption instead, regardless of what
/// `management_profile` resolves to.
///
/// `regions` is the CLI `--region` flag (see [`crate::resolve_region`]): its first entry, if
/// any, overrides the region on *both* configs. Otherwise each config keeps its own
/// profile-resolved region; a config with none falls back to the other's region, then to
/// `us-east-1` — `jump_from_profile` in particular is often just static credentials with no
/// region of its own, since its only purpose is calling `sts:AssumeRole`.
async fn resolve_configs(
    management_profile: String,
    jump_from_profile: Option<String>,
    regions: &[String],
) -> (aws_config::SdkConfig, aws_config::SdkConfig) {
    let discovery_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .profile_name(management_profile)
        .load()
        .await;
    let discovery_region = crate::resolve_region(regions, discovery_config.region());
    let discovery_config = discovery_config
        .into_builder()
        .region(discovery_region.clone())
        .build();

    let mut jump_from_loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    if let Some(profile) = jump_from_profile {
        jump_from_loader = jump_from_loader.profile_name(profile);
    }
    let jump_from_config = jump_from_loader.load().await;
    let jump_from_region = if !regions.is_empty() {
        crate::resolve_region(regions, None)
    } else {
        crate::resolve_region(&[], jump_from_config.region().or(Some(&discovery_region)))
    };
    let jump_from_config = jump_from_config
        .into_builder()
        .region(jump_from_region)
        .build();

    (discovery_config, jump_from_config)
}

/// Collects IAM data across every member account of an AWS Organization.
///
/// Enumerates the OU tree and accounts from the management account, prunes excluded OUs
/// (and their descendants), then assumes `assume_role_name` into each remaining account and
/// runs the same per-account collection as [`LiveCollector`].
pub struct OrgCollector {
    orgs_client: aws_sdk_organizations::Client,
    sts_client: aws_sdk_sts::Client,
    assume_role_name: String,
    exclude_ou_ids: Vec<String>,
    exclude_ou_names: Vec<String>,
    /// `(ou_id_or_name, aws_profile)` pairs from `--ou-profile-override`, matched against both
    /// OU id and OU display name — same dual-match as `exclude_ou_ids`/`exclude_ou_names`.
    ou_profile_overrides: Vec<(String, String)>,
    region: Region,
    client_factory: Box<dyn IamClientFactory>,
}

impl OrgCollector {
    /// Build a collector for org-wide collection.
    ///
    /// `management_profile` is used only for Organizations discovery (enumerating OUs and
    /// accounts). Role assumption into member accounts always originates from
    /// `jump_from_profile` instead — never from `management_profile`'s resolved credentials.
    /// This matters because `management_profile` may itself already be an assumed role (e.g.
    /// an SSO profile or a profile with `role_arn`/`source_profile` chaining); reusing those
    /// credentials to call `sts:AssumeRole` again would be a double-hop assumption that most
    /// jump-role trust policies reject.
    ///
    /// `jump_from_profile` is the named AWS profile to use as that base identity. When `None`,
    /// it falls back to the standard AWS credential chain (`AWS_PROFILE` / the `default`
    /// profile) rather than `management_profile`.
    ///
    /// `regions` is the CLI `--region` flag; see [`resolve_configs`].
    pub async fn from_profile(
        management_profile: impl Into<String>,
        jump_from_profile: Option<impl Into<String>>,
        regions: &[String],
        assume_role_name: impl Into<String>,
        exclude_ou_ids: Vec<String>,
        exclude_ou_names: Vec<String>,
        ou_profile_overrides: Vec<(String, String)>,
    ) -> Result<Self, CollectorError> {
        let (discovery_config, jump_from_config) = resolve_configs(
            management_profile.into(),
            jump_from_profile.map(Into::into),
            regions,
        )
        .await;

        let region = discovery_config
            .region()
            .cloned()
            .expect("resolve_configs always sets a region on discovery_config");

        Ok(Self {
            orgs_client: aws_sdk_organizations::Client::new(&discovery_config),
            sts_client: aws_sdk_sts::Client::new(&jump_from_config),
            assume_role_name: assume_role_name.into(),
            exclude_ou_ids,
            exclude_ou_names,
            ou_profile_overrides,
            region,
            client_factory: Box::new(RealIamClientFactory),
        })
    }

    /// Resolves the credentials of a named local AWS profile eagerly (no network call for
    /// static-credential profiles), so an unresolvable `--ou-profile-override` profile fails
    /// fast as a validation error rather than surfacing later as an opaque per-account failure.
    ///
    /// Resolved once, up front, and reused for every account under that override for the rest
    /// of the run: fine for the intended static long-lived-credential use case, but a
    /// short-lived SSO/STS-backed override profile can expire mid-run on a large org. Revisit
    /// (e.g. re-resolve per account) if that use case is needed.
    async fn resolve_override_profile_credentials(
        profile: &str,
    ) -> Result<Credentials, CollectorError> {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .profile_name(profile)
            .load()
            .await;
        let provider = config.credentials_provider().ok_or_else(|| {
            CollectorError::InvalidOuProfileOverride(format!(
                "profile `{profile}` was not found in the local AWS config/credentials files"
            ))
        })?;
        provider.provide_credentials().await.map_err(|e| {
            CollectorError::InvalidOuProfileOverride(format!(
                "profile `{profile}` credentials could not be resolved: {e}"
            ))
        })
    }

    /// Run the org-wide collection: enumerate accounts, assume into each, collect.
    /// A single account's failure is recorded as a warning, not a fatal error.
    pub async fn collect(&self) -> Result<OrgCollectionResult, CollectorError> {
        let run_id = Uuid::new_v4().to_string();
        info!(run_id = %run_id, "starting org-wide collection: enumerating accounts");
        let (accounts, unmatched_excludes, unmatched_override_keys) =
            self.enumerate_accounts().await?;
        info!(accounts = accounts.len(), "enumerated org accounts");

        if !unmatched_override_keys.is_empty() {
            let keys = unmatched_override_keys.join("`, `");
            return Err(CollectorError::InvalidOuProfileOverride(format!(
                "--ou-profile-override key(s) `{keys}` did not match any organizational unit's \
                 id or display name in this organization — check spelling and that they are \
                 reachable from an enumerated root"
            )));
        }

        let mut override_credentials: HashMap<String, Credentials> = HashMap::new();
        for (_, profile) in &self.ou_profile_overrides {
            if !override_credentials.contains_key(profile) {
                let creds = Self::resolve_override_profile_credentials(profile).await?;
                override_credentials.insert(profile.clone(), creds);
            }
        }

        let mut collected = Vec::with_capacity(accounts.len());
        let mut warnings = Vec::new();

        let mut seen_override_keys = std::collections::HashSet::new();
        for (key, _) in &self.ou_profile_overrides {
            if !seen_override_keys.insert(key) {
                warn!(key = %key, "--ou-profile-override key given more than once; only the first profile for it is used");
                warnings.push(CollectorWarning::PartialData(format!(
                    "--ou-profile-override key `{key}` was given more than once — only its \
                     first `=<aws_profile>` value is used, the rest are ignored"
                )));
            }
        }

        for ou_id in &unmatched_excludes.ids {
            warn!(ou_id = %ou_id, "--exclude-ou-id did not match any OU encountered during enumeration");
            warnings.push(CollectorWarning::PartialData(format!(
                "--exclude-ou-id {ou_id} did not match any organizational unit in this \
                 organization — check that it is the OU's id (e.g. \"ou-xxxx-yyyyyyyy\") and that \
                 it is reachable from an enumerated root"
            )));
        }
        for ou_name in &unmatched_excludes.names {
            warn!(ou_name = %ou_name, "--exclude-ou-name did not match any OU encountered during enumeration");
            warnings.push(CollectorWarning::PartialData(format!(
                "--exclude-ou-name {ou_name} did not match any organizational unit's display \
                 name in this organization — check spelling and that it is reachable from an \
                 enumerated root"
            )));
        }

        for (index, account) in accounts.iter().enumerate() {
            info!(
                account_id = %account.id,
                account_name = %account.name,
                progress = format!("{}/{}", index + 1, accounts.len()),
                "collecting account"
            );
            match self.collect_account(account, &override_credentials).await {
                Ok(mut data) => {
                    data.ou_id = account.ou_id.clone();
                    data.ou_name = account.ou_name.clone();
                    collected.push(data);
                }
                Err(e) => {
                    warn!(account_id = %account.id, error = %e, "skipping account in org collection");
                    warnings.push(CollectorWarning::PartialData(format!(
                        "account {}: {e}",
                        account.id
                    )));
                }
            }
        }

        Ok(OrgCollectionResult {
            run_id,
            accounts: collected,
            warnings,
        })
    }

    /// Collects one account: via its `--ou-profile-override` credentials directly if
    /// `account.profile_override` is set (bypassing assume-role entirely), otherwise via the
    /// default `sts:AssumeRole` jump-role path.
    async fn collect_account(
        &self,
        account: &OrgAccount,
        override_credentials: &HashMap<String, Credentials>,
    ) -> Result<CollectedData, CollectorError> {
        let credentials = if let Some(profile) = &account.profile_override {
            override_credentials.get(profile).cloned().ok_or_else(|| {
                CollectorError::InvalidOuProfileOverride(format!(
                    "internal error: no resolved credentials cached for profile `{profile}`"
                ))
            })?
        } else {
            self.assume_jump_role(account).await?
        };

        let iam_client = self
            .client_factory
            .build(&account.id, credentials, self.region.clone());

        LiveCollector::new(iam_client).collect().await
    }

    async fn assume_jump_role(&self, account: &OrgAccount) -> Result<Credentials, CollectorError> {
        let role_arn = format!("arn:aws:iam::{}:role/{}", account.id, self.assume_role_name);
        info!(role_arn = %role_arn, region = %self.region, "assuming jump role");
        let assumed = self
            .sts_client
            .assume_role()
            .role_arn(&role_arn)
            .role_session_name("aws-iam-grapher-org-collect")
            .send()
            .await
            .map_err(map_sdk_error)?;

        let creds = assumed.credentials().ok_or_else(|| {
            CollectorError::AwsSdk(format!(
                "assume-role into {role_arn} returned no credentials"
            ))
        })?;

        let expires_after = SystemTime::try_from(*creds.expiration()).ok();
        Ok(Credentials::new(
            creds.access_key_id().to_string(),
            creds.secret_access_key().to_string(),
            Some(creds.session_token().to_string()),
            expires_after,
            "aws-iam-grapher-org-assume-role",
        ))
    }

    /// Enumerates every account reachable from the org roots, applying `--exclude-ou-id` /
    /// `--exclude-ou-name` pruning and `--ou-profile-override` tagging. Returns the surviving
    /// accounts, any exclude entries that never matched an OU encountered during the walk, and
    /// any override keys that never matched one either (a strong signal of a typo, both of
    /// which would otherwise silently collect everything / never apply).
    async fn enumerate_accounts(
        &self,
    ) -> Result<(Vec<OrgAccount>, UnmatchedExcludes, Vec<String>), CollectorError> {
        debug!("fetching ListRoots");
        let mut accounts = Vec::new();
        let mut matched_excludes = MatchedExcludes::default();
        let mut matched_overrides: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        {
            let mut state = WalkState {
                out: &mut accounts,
                matched_excludes: &mut matched_excludes,
                matched_overrides: &mut matched_overrides,
            };
            let mut root_paginator = self.orgs_client.list_roots().into_paginator().send();
            while let Some(page) = root_paginator.next().await {
                let page = page.map_err(map_sdk_error)?;
                for root in page.roots() {
                    let root_id = root.id().unwrap_or_default().to_string();
                    self.collect_accounts_under(
                        root_id.clone(),
                        vec![root_id],
                        None,
                        None,
                        &mut state,
                    )
                    .await?;
                }
            }
        }

        let unmatched_ids: Vec<String> = self
            .exclude_ou_ids
            .iter()
            .filter(|id| !matched_excludes.matched_ids.contains(*id))
            .cloned()
            .collect();
        let unmatched_names: Vec<String> = self
            .exclude_ou_names
            .iter()
            .filter(|name| !matched_excludes.matched_names.contains(*name))
            .cloned()
            .collect();
        let unmatched_override_keys: Vec<String> = self
            .ou_profile_overrides
            .iter()
            .map(|(key, _)| key)
            .filter(|key| !matched_overrides.contains(*key))
            .cloned()
            .collect();

        Ok((
            accounts,
            UnmatchedExcludes {
                ids: unmatched_ids,
                names: unmatched_names,
            },
            unmatched_override_keys,
        ))
    }

    /// Recursively walk OUs under `parent_id`, collecting accounts, pruning excluded OU
    /// subtrees, and tagging accounts with the innermost matching `--ou-profile-override`
    /// profile. Boxed because async fns cannot recurse directly (infinite-sized future).
    ///
    /// `current_ou` is the immediate parent OU's (id, name), or `None` while still directly
    /// under the org root — it is stamped onto every [`OrgAccount`] found at this level.
    /// `current_override` is the profile inherited from the nearest matching ancestor OU (or
    /// `None`); a nested OU with its own match replaces it for its own subtree.
    fn collect_accounts_under<'a, 'b>(
        &'a self,
        parent_id: String,
        ou_path: Vec<String>,
        current_ou: Option<(String, String)>,
        current_override: Option<String>,
        state: &'b mut WalkState<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<(), CollectorError>> + 'b>>
    where
        'a: 'b,
    {
        Box::pin(async move {
            debug!(parent_id = %parent_id, "fetching ListAccountsForParent");
            let mut acct_paginator = self
                .orgs_client
                .list_accounts_for_parent()
                .parent_id(&parent_id)
                .into_paginator()
                .send();
            while let Some(page) = acct_paginator.next().await {
                let page = page.map_err(map_sdk_error)?;
                for a in page.accounts() {
                    state.out.push(OrgAccount {
                        id: a.id().unwrap_or_default().to_string(),
                        name: a.name().unwrap_or_default().to_string(),
                        ou_path: ou_path.clone(),
                        ou_id: current_ou.as_ref().map(|(id, _)| id.clone()),
                        ou_name: current_ou.as_ref().map(|(_, name)| name.clone()),
                        profile_override: current_override.clone(),
                    });
                }
            }

            debug!(parent_id = %parent_id, "fetching ListOrganizationalUnitsForParent");
            let mut ou_paginator = self
                .orgs_client
                .list_organizational_units_for_parent()
                .parent_id(&parent_id)
                .into_paginator()
                .send();
            while let Some(page) = ou_paginator.next().await {
                let page = page.map_err(map_sdk_error)?;
                for ou in page.organizational_units() {
                    let ou_id = ou.id().unwrap_or_default().to_string();
                    let ou_name = ou.name().unwrap_or_default().to_string();
                    if self.exclude_ou_ids.contains(&ou_id) {
                        state.matched_excludes.matched_ids.insert(ou_id);
                        continue;
                    }
                    if let Some(name) = self
                        .exclude_ou_names
                        .iter()
                        .find(|name| name.as_str() == ou_name)
                    {
                        state.matched_excludes.matched_names.insert(name.clone());
                        continue;
                    }

                    let child_override = self
                        .ou_profile_overrides
                        .iter()
                        .find(|(key, _)| key == &ou_id || key == &ou_name)
                        .map(|(key, profile)| {
                            state.matched_overrides.insert(key.clone());
                            profile.clone()
                        })
                        .or_else(|| current_override.clone());

                    let mut child_path = ou_path.clone();
                    child_path.push(ou_id.clone());
                    self.collect_accounts_under(
                        ou_id.clone(),
                        child_path,
                        Some((ou_id, ou_name)),
                        child_override,
                        state,
                    )
                    .await?;
                }
            }

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_smithy_mocks::{mock, mock_client, RuleMode};
    use std::sync::Mutex;

    struct TestIamClientFactory {
        clients: Mutex<HashMap<String, aws_sdk_iam::Client>>,
    }

    impl IamClientFactory for TestIamClientFactory {
        fn build(
            &self,
            account_id: &str,
            _creds: Credentials,
            _region: Region,
        ) -> aws_sdk_iam::Client {
            self.clients
                .lock()
                .expect("lock not poisoned")
                .get(account_id)
                .cloned()
                .expect("test client registered for account")
        }
    }

    fn empty_auth_details_client() -> aws_sdk_iam::Client {
        let rule = mock!(aws_sdk_iam::Client::get_account_authorization_details)
            .then_output(|| aws_sdk_iam::operation::get_account_authorization_details::GetAccountAuthorizationDetailsOutput::builder().build());
        let list_profiles_rule =
            mock!(aws_sdk_iam::Client::list_instance_profiles).then_output(|| {
                aws_sdk_iam::operation::list_instance_profiles::ListInstanceProfilesOutput::builder(
                )
                .set_instance_profiles(Some(Vec::new()))
                .is_truncated(false)
                .build()
                .expect("valid ListInstanceProfilesOutput")
            });
        mock_client!(
            aws_sdk_iam,
            RuleMode::Sequential,
            &[&rule, &list_profiles_rule]
        )
    }

    fn org_collector_with(
        orgs_client: aws_sdk_organizations::Client,
        sts_client: aws_sdk_sts::Client,
        exclude_ou_ids: Vec<String>,
        client_factory: Box<dyn IamClientFactory>,
    ) -> OrgCollector {
        org_collector_with_excludes(
            orgs_client,
            sts_client,
            exclude_ou_ids,
            vec![],
            client_factory,
        )
    }

    fn org_collector_with_excludes(
        orgs_client: aws_sdk_organizations::Client,
        sts_client: aws_sdk_sts::Client,
        exclude_ou_ids: Vec<String>,
        exclude_ou_names: Vec<String>,
        client_factory: Box<dyn IamClientFactory>,
    ) -> OrgCollector {
        org_collector_with_overrides(
            orgs_client,
            sts_client,
            exclude_ou_ids,
            exclude_ou_names,
            vec![],
            client_factory,
        )
    }

    fn org_collector_with_overrides(
        orgs_client: aws_sdk_organizations::Client,
        sts_client: aws_sdk_sts::Client,
        exclude_ou_ids: Vec<String>,
        exclude_ou_names: Vec<String>,
        ou_profile_overrides: Vec<(String, String)>,
        client_factory: Box<dyn IamClientFactory>,
    ) -> OrgCollector {
        OrgCollector {
            orgs_client,
            sts_client,
            assume_role_name: "OrgJumpRole".to_string(),
            exclude_ou_ids,
            exclude_ou_names,
            ou_profile_overrides,
            region: Region::new("us-east-1"),
            client_factory,
        }
    }

    fn root_output() -> aws_sdk_organizations::operation::list_roots::ListRootsOutput {
        aws_sdk_organizations::operation::list_roots::ListRootsOutput::builder()
            .roots(
                aws_sdk_organizations::types::Root::builder()
                    .id("r-root1")
                    .name("Root")
                    .build(),
            )
            .build()
    }

    fn ou_output(
        units: Vec<(&str, &str)>,
    ) -> aws_sdk_organizations::operation::list_organizational_units_for_parent::ListOrganizationalUnitsForParentOutput
    {
        let mut builder =
            aws_sdk_organizations::operation::list_organizational_units_for_parent::ListOrganizationalUnitsForParentOutput::builder();
        for (id, name) in units {
            builder = builder.organizational_units(
                aws_sdk_organizations::types::OrganizationalUnit::builder()
                    .id(id)
                    .name(name)
                    .build(),
            );
        }
        builder.build()
    }

    fn accounts_output(
        accounts: Vec<(&str, &str)>,
    ) -> aws_sdk_organizations::operation::list_accounts_for_parent::ListAccountsForParentOutput
    {
        let mut builder =
            aws_sdk_organizations::operation::list_accounts_for_parent::ListAccountsForParentOutput::builder();
        for (id, name) in accounts {
            builder = builder.accounts(
                aws_sdk_organizations::types::Account::builder()
                    .id(id)
                    .name(name)
                    .build(),
            );
        }
        builder.build()
    }

    fn assume_role_output(
        access_key_id: &str,
    ) -> aws_sdk_sts::operation::assume_role::AssumeRoleOutput {
        aws_sdk_sts::operation::assume_role::AssumeRoleOutput::builder()
            .credentials(
                aws_sdk_sts::types::Credentials::builder()
                    .access_key_id(access_key_id)
                    .secret_access_key("secret")
                    .session_token("token")
                    .expiration(aws_smithy_types::DateTime::from_secs(9_999_999_999))
                    .build()
                    .expect("valid credentials"),
            )
            .build()
    }

    /// Serializes tests that mutate process-wide AWS credential env vars. `cargo test` runs
    /// unit tests within one binary concurrently by default, and no other test in this file
    /// (or this crate) touches these vars, but a mutex keeps the guarantee explicit rather
    /// than implicit. Async-aware because the critical section spans `.await` points.
    static AWS_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Regression test for the double-hop `AssumeRole` bug: `resolve_configs` (used by
    /// `from_profile`) must resolve org discovery credentials from `management_profile` and
    /// jump-role-assumption credentials from a completely separate profile, never falling back
    /// to `management_profile` for the latter. Uses two profiles with distinct static
    /// credentials (no network calls needed to resolve static keys) and asserts the two
    /// resolved configs end up with different identities.
    #[tokio::test]
    async fn resolve_configs_never_uses_management_profile_credentials_for_jump_from() {
        use aws_sdk_sts::config::ProvideCredentials;
        use std::io::Write;

        let _guard = AWS_ENV_LOCK.lock().await;

        let dir = tempfile::tempdir().expect("tempdir");
        let creds_path = dir.path().join("credentials");
        let mut file = std::fs::File::create(&creds_path).expect("create credentials file");
        writeln!(
            file,
            "[mgmt]\naws_access_key_id = MGMT_KEY\naws_secret_access_key = mgmt-secret\n\n\
             [default]\naws_access_key_id = JUMP_KEY\naws_secret_access_key = jump-secret\n"
        )
        .expect("write credentials file");

        std::env::set_var("AWS_SHARED_CREDENTIALS_FILE", &creds_path);
        std::env::remove_var("AWS_CONFIG_FILE");
        std::env::remove_var("AWS_PROFILE");
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_SESSION_TOKEN");

        let (discovery_config, jump_from_config) =
            resolve_configs("mgmt".to_string(), None, &[]).await;

        std::env::remove_var("AWS_SHARED_CREDENTIALS_FILE");

        let orgs_creds = discovery_config
            .credentials_provider()
            .expect("discovery config has a credentials provider")
            .provide_credentials()
            .await
            .expect("resolve org discovery credentials");
        let sts_creds = jump_from_config
            .credentials_provider()
            .expect("jump_from config has a credentials provider")
            .provide_credentials()
            .await
            .expect("resolve jump_from credentials");

        assert_eq!(orgs_creds.access_key_id(), "MGMT_KEY");
        assert_eq!(sts_creds.access_key_id(), "JUMP_KEY");
        assert_ne!(orgs_creds.access_key_id(), sts_creds.access_key_id());
    }

    /// Regression test for the "Missing Region" `DispatchFailure` seen in real-world use:
    /// `jump_from_profile` is often just static credentials with no `region` line, since its
    /// only purpose is to call `sts:AssumeRole`. `resolve_configs` must fall its region back
    /// to `management_profile`'s region rather than leaving `jump_from_config` with none.
    #[tokio::test]
    async fn resolve_configs_falls_back_jump_from_region_to_discovery_region() {
        let _guard = AWS_ENV_LOCK.lock().await;

        let dir = tempfile::tempdir().expect("tempdir");
        let creds_path = dir.path().join("credentials");
        std::fs::write(
            &creds_path,
            "[mgmt]\naws_access_key_id = MGMT_KEY\naws_secret_access_key = mgmt-secret\n\n\
             [default]\naws_access_key_id = JUMP_KEY\naws_secret_access_key = jump-secret\n",
        )
        .expect("write credentials file");

        // Only "mgmt" has a region configured; "default" (the jump_from fallback profile) has
        // none, mirroring a real base-credentials-only profile.
        let config_path = dir.path().join("config");
        std::fs::write(&config_path, "[profile mgmt]\nregion = eu-west-1\n")
            .expect("write config file");

        std::env::set_var("AWS_SHARED_CREDENTIALS_FILE", &creds_path);
        std::env::set_var("AWS_CONFIG_FILE", &config_path);
        std::env::remove_var("AWS_PROFILE");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_SESSION_TOKEN");

        let (discovery_config, jump_from_config) =
            resolve_configs("mgmt".to_string(), None, &[]).await;

        std::env::remove_var("AWS_SHARED_CREDENTIALS_FILE");
        std::env::remove_var("AWS_CONFIG_FILE");

        assert_eq!(discovery_config.region(), Some(&Region::new("eu-west-1")));
        assert_eq!(
            jump_from_config.region(),
            Some(&Region::new("eu-west-1")),
            "jump_from_config must fall back to the discovery region when its own profile has none"
        );
    }

    /// An explicit `--region` flag must override both configs' profile-resolved regions, not
    /// just fill in a missing one.
    #[tokio::test]
    async fn resolve_configs_explicit_regions_override_both_configs() {
        let _guard = AWS_ENV_LOCK.lock().await;

        let dir = tempfile::tempdir().expect("tempdir");
        let creds_path = dir.path().join("credentials");
        std::fs::write(
            &creds_path,
            "[mgmt]\naws_access_key_id = MGMT_KEY\naws_secret_access_key = mgmt-secret\n\n\
             [default]\naws_access_key_id = JUMP_KEY\naws_secret_access_key = jump-secret\n",
        )
        .expect("write credentials file");

        let config_path = dir.path().join("config");
        std::fs::write(
            &config_path,
            "[profile mgmt]\nregion = eu-west-1\n\n[default]\nregion = ap-southeast-2\n",
        )
        .expect("write config file");

        std::env::set_var("AWS_SHARED_CREDENTIALS_FILE", &creds_path);
        std::env::set_var("AWS_CONFIG_FILE", &config_path);
        std::env::remove_var("AWS_PROFILE");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_SESSION_TOKEN");

        let (discovery_config, jump_from_config) =
            resolve_configs("mgmt".to_string(), None, &["us-west-2".to_string()]).await;

        std::env::remove_var("AWS_SHARED_CREDENTIALS_FILE");
        std::env::remove_var("AWS_CONFIG_FILE");

        assert_eq!(discovery_config.region(), Some(&Region::new("us-west-2")));
        assert_eq!(jump_from_config.region(), Some(&Region::new("us-west-2")));
    }

    #[tokio::test]
    async fn enumerate_accounts_returns_accounts_across_root_and_nested_ou() {
        // Arrange: root has one direct account and one child OU with one account.
        let list_roots_rule =
            mock!(aws_sdk_organizations::Client::list_roots).then_output(root_output);
        let root_ous_rule =
            mock!(aws_sdk_organizations::Client::list_organizational_units_for_parent)
                .match_requests(|req| req.parent_id() == Some("r-root1"))
                .then_output(|| ou_output(vec![("ou-child1", "Child")]));
        let child_ous_rule =
            mock!(aws_sdk_organizations::Client::list_organizational_units_for_parent)
                .match_requests(|req| req.parent_id() == Some("ou-child1"))
                .then_output(|| ou_output(vec![]));
        let root_accounts_rule = mock!(aws_sdk_organizations::Client::list_accounts_for_parent)
            .match_requests(|req| req.parent_id() == Some("r-root1"))
            .then_output(|| accounts_output(vec![("111111111111", "root-account")]));
        let child_accounts_rule = mock!(aws_sdk_organizations::Client::list_accounts_for_parent)
            .match_requests(|req| req.parent_id() == Some("ou-child1"))
            .then_output(|| accounts_output(vec![("222222222222", "child-account")]));

        let orgs_client = mock_client!(
            aws_sdk_organizations,
            RuleMode::MatchAny,
            &[
                &list_roots_rule,
                &root_ous_rule,
                &child_ous_rule,
                &root_accounts_rule,
                &child_accounts_rule,
            ]
        );
        let sts_client = mock_client!(
            aws_sdk_sts,
            RuleMode::MatchAny,
            &[] as &[&aws_smithy_mocks::Rule]
        );
        let collector = org_collector_with(
            orgs_client,
            sts_client,
            vec![],
            Box::new(TestIamClientFactory {
                clients: Mutex::new(HashMap::new()),
            }),
        );

        // Act
        let (accounts, unmatched_excludes, unmatched_overrides) = collector
            .enumerate_accounts()
            .await
            .expect("enumeration succeeds");

        // Assert
        assert!(unmatched_excludes.is_empty());
        assert!(unmatched_overrides.is_empty());
        let mut ids: Vec<&str> = accounts.iter().map(|a| a.id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids, ["111111111111", "222222222222"]);
        let child = accounts
            .iter()
            .find(|a| a.id == "222222222222")
            .expect("child account present");
        assert_eq!(
            child.ou_path,
            vec!["r-root1".to_string(), "ou-child1".to_string()]
        );
        assert_eq!(child.ou_id, Some("ou-child1".to_string()));
        assert_eq!(child.ou_name, Some("Child".to_string()));

        let root_account = accounts
            .iter()
            .find(|a| a.id == "111111111111")
            .expect("root account present");
        assert_eq!(
            root_account.ou_id, None,
            "an account directly under the org root has no OU"
        );
        assert_eq!(root_account.ou_name, None);
    }

    #[tokio::test]
    async fn enumerate_accounts_excludes_ou_subtree() {
        // Arrange: root has child OU "ou-excluded" with its own nested OU + account — all pruned.
        let list_roots_rule =
            mock!(aws_sdk_organizations::Client::list_roots).then_output(root_output);
        let root_ous_rule =
            mock!(aws_sdk_organizations::Client::list_organizational_units_for_parent)
                .match_requests(|req| req.parent_id() == Some("r-root1"))
                .then_output(|| ou_output(vec![("ou-excluded", "Excluded"), ("ou-kept", "Kept")]));
        let kept_ous_rule =
            mock!(aws_sdk_organizations::Client::list_organizational_units_for_parent)
                .match_requests(|req| req.parent_id() == Some("ou-kept"))
                .then_output(|| ou_output(vec![]));
        let root_accounts_rule = mock!(aws_sdk_organizations::Client::list_accounts_for_parent)
            .match_requests(|req| req.parent_id() == Some("r-root1"))
            .then_output(|| accounts_output(vec![]));
        let kept_accounts_rule = mock!(aws_sdk_organizations::Client::list_accounts_for_parent)
            .match_requests(|req| req.parent_id() == Some("ou-kept"))
            .then_output(|| accounts_output(vec![("333333333333", "kept-account")]));

        let orgs_client = mock_client!(
            aws_sdk_organizations,
            RuleMode::MatchAny,
            &[
                &list_roots_rule,
                &root_ous_rule,
                &kept_ous_rule,
                &root_accounts_rule,
                &kept_accounts_rule,
            ]
        );
        let sts_client = mock_client!(
            aws_sdk_sts,
            RuleMode::MatchAny,
            &[] as &[&aws_smithy_mocks::Rule]
        );
        let collector = org_collector_with(
            orgs_client,
            sts_client,
            vec!["ou-excluded".to_string()],
            Box::new(TestIamClientFactory {
                clients: Mutex::new(HashMap::new()),
            }),
        );

        // Act
        let (accounts, unmatched_excludes, unmatched_overrides) = collector
            .enumerate_accounts()
            .await
            .expect("enumeration succeeds");

        // Assert: only the kept-OU account shows up; the excluded subtree was never queried
        // (no rule registered for parent_id == "ou-excluded", so a query there would panic).
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, "333333333333");
        assert!(unmatched_excludes.is_empty());
        assert!(unmatched_overrides.is_empty());
    }

    #[tokio::test]
    async fn enumerate_accounts_reports_exclude_ou_that_matched_nothing() {
        // Arrange: a plain org with no OUs at all — an `--exclude-ou` for an id that doesn't
        // exist anywhere in the tree (typo, wrong path, or an OU name instead of an OU id) must
        // be surfaced, not silently ignored, since a silent no-op looks identical to "the
        // exclusion did nothing" from the user's point of view.
        let list_roots_rule =
            mock!(aws_sdk_organizations::Client::list_roots).then_output(root_output);
        let root_ous_rule =
            mock!(aws_sdk_organizations::Client::list_organizational_units_for_parent)
                .then_output(|| ou_output(vec![]));
        let root_accounts_rule = mock!(aws_sdk_organizations::Client::list_accounts_for_parent)
            .then_output(|| accounts_output(vec![("111111111111", "a")]));
        let orgs_client = mock_client!(
            aws_sdk_organizations,
            RuleMode::MatchAny,
            &[&list_roots_rule, &root_ous_rule, &root_accounts_rule]
        );
        let sts_client = mock_client!(
            aws_sdk_sts,
            RuleMode::MatchAny,
            &[] as &[&aws_smithy_mocks::Rule]
        );
        let collector = org_collector_with(
            orgs_client,
            sts_client,
            vec!["ou-does-not-exist".to_string()],
            Box::new(TestIamClientFactory {
                clients: Mutex::new(HashMap::new()),
            }),
        );

        // Act
        let (accounts, unmatched_excludes, unmatched_overrides) = collector
            .enumerate_accounts()
            .await
            .expect("enumeration succeeds");

        // Assert
        assert_eq!(accounts.len(), 1);
        assert_eq!(
            unmatched_excludes.ids,
            vec!["ou-does-not-exist".to_string()]
        );
        assert!(unmatched_excludes.names.is_empty());
        assert!(unmatched_overrides.is_empty());
    }

    #[tokio::test]
    async fn enumerate_accounts_excludes_deeply_nested_ou_subtree() {
        // Arrange: root -> ou-a -> ou-excluded -> ou-nested -> account. Excluding ou-excluded
        // (two levels down) must prune everything beneath it, including ou-nested's account.
        let list_roots_rule =
            mock!(aws_sdk_organizations::Client::list_roots).then_output(root_output);
        let root_ous_rule =
            mock!(aws_sdk_organizations::Client::list_organizational_units_for_parent)
                .match_requests(|req| req.parent_id() == Some("r-root1"))
                .then_output(|| ou_output(vec![("ou-a", "A")]));
        let a_ous_rule = mock!(aws_sdk_organizations::Client::list_organizational_units_for_parent)
            .match_requests(|req| req.parent_id() == Some("ou-a"))
            .then_output(|| ou_output(vec![("ou-excluded", "Excluded")]));
        let root_accounts_rule = mock!(aws_sdk_organizations::Client::list_accounts_for_parent)
            .match_requests(|req| req.parent_id() == Some("r-root1"))
            .then_output(|| accounts_output(vec![]));
        let a_accounts_rule = mock!(aws_sdk_organizations::Client::list_accounts_for_parent)
            .match_requests(|req| req.parent_id() == Some("ou-a"))
            .then_output(|| accounts_output(vec![]));

        let orgs_client = mock_client!(
            aws_sdk_organizations,
            RuleMode::MatchAny,
            &[
                &list_roots_rule,
                &root_ous_rule,
                &a_ous_rule,
                &root_accounts_rule,
                &a_accounts_rule,
            ]
        );
        let sts_client = mock_client!(
            aws_sdk_sts,
            RuleMode::MatchAny,
            &[] as &[&aws_smithy_mocks::Rule]
        );
        let collector = org_collector_with(
            orgs_client,
            sts_client,
            vec!["ou-excluded".to_string()],
            Box::new(TestIamClientFactory {
                clients: Mutex::new(HashMap::new()),
            }),
        );

        // Act: if pruning fails, this panics (no rule registered for parent_id == "ou-excluded"
        // or "ou-nested").
        let (accounts, unmatched_excludes, unmatched_overrides) = collector
            .enumerate_accounts()
            .await
            .expect("enumeration succeeds");

        // Assert
        assert_eq!(accounts.len(), 0);
        assert!(unmatched_excludes.is_empty());
        assert!(unmatched_overrides.is_empty());
    }

    #[tokio::test]
    async fn enumerate_accounts_excludes_ou_subtree_by_name() {
        // Arrange: root has child OU "ou-excluded" (name "Excluded") with its own nested OU +
        // account — all pruned by matching the display name, not the id.
        let list_roots_rule =
            mock!(aws_sdk_organizations::Client::list_roots).then_output(root_output);
        let root_ous_rule =
            mock!(aws_sdk_organizations::Client::list_organizational_units_for_parent)
                .match_requests(|req| req.parent_id() == Some("r-root1"))
                .then_output(|| ou_output(vec![("ou-excluded", "Excluded"), ("ou-kept", "Kept")]));
        let kept_ous_rule =
            mock!(aws_sdk_organizations::Client::list_organizational_units_for_parent)
                .match_requests(|req| req.parent_id() == Some("ou-kept"))
                .then_output(|| ou_output(vec![]));
        let root_accounts_rule = mock!(aws_sdk_organizations::Client::list_accounts_for_parent)
            .match_requests(|req| req.parent_id() == Some("r-root1"))
            .then_output(|| accounts_output(vec![]));
        let kept_accounts_rule = mock!(aws_sdk_organizations::Client::list_accounts_for_parent)
            .match_requests(|req| req.parent_id() == Some("ou-kept"))
            .then_output(|| accounts_output(vec![("333333333333", "kept-account")]));

        let orgs_client = mock_client!(
            aws_sdk_organizations,
            RuleMode::MatchAny,
            &[
                &list_roots_rule,
                &root_ous_rule,
                &kept_ous_rule,
                &root_accounts_rule,
                &kept_accounts_rule,
            ]
        );
        let sts_client = mock_client!(
            aws_sdk_sts,
            RuleMode::MatchAny,
            &[] as &[&aws_smithy_mocks::Rule]
        );
        let collector = org_collector_with_excludes(
            orgs_client,
            sts_client,
            vec![],
            vec!["Excluded".to_string()],
            Box::new(TestIamClientFactory {
                clients: Mutex::new(HashMap::new()),
            }),
        );

        // Act
        let (accounts, unmatched_excludes, unmatched_overrides) = collector
            .enumerate_accounts()
            .await
            .expect("enumeration succeeds");

        // Assert: only the kept-OU account shows up; the excluded subtree was never queried
        // (no rule registered for parent_id == "ou-excluded", so a query there would panic).
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, "333333333333");
        assert!(unmatched_excludes.is_empty());
        assert!(unmatched_overrides.is_empty());
    }

    #[tokio::test]
    async fn collect_fans_out_one_collected_data_per_account_sharing_run_id() {
        // Arrange: org with two accounts directly under root, both assumable.
        let list_roots_rule =
            mock!(aws_sdk_organizations::Client::list_roots).then_output(root_output);
        let root_ous_rule =
            mock!(aws_sdk_organizations::Client::list_organizational_units_for_parent)
                .then_output(|| ou_output(vec![]));
        let root_accounts_rule = mock!(aws_sdk_organizations::Client::list_accounts_for_parent)
            .then_output(|| accounts_output(vec![("111111111111", "a"), ("222222222222", "b")]));
        let orgs_client = mock_client!(
            aws_sdk_organizations,
            RuleMode::MatchAny,
            &[&list_roots_rule, &root_ous_rule, &root_accounts_rule]
        );

        let assume_rule =
            mock!(aws_sdk_sts::Client::assume_role).then_output(|| assume_role_output("AKIATEST"));
        let sts_client = mock_client!(aws_sdk_sts, RuleMode::MatchAny, &[&assume_rule]);

        let mut clients = HashMap::new();
        clients.insert("111111111111".to_string(), empty_auth_details_client());
        clients.insert("222222222222".to_string(), empty_auth_details_client());

        let collector = org_collector_with(
            orgs_client,
            sts_client,
            vec![],
            Box::new(TestIamClientFactory {
                clients: Mutex::new(clients),
            }),
        );

        // Act
        let result = collector.collect().await.expect("org collection succeeds");

        // Assert
        assert_eq!(result.accounts.len(), 2);
        assert!(result.warnings.is_empty());
        assert!(!result.run_id.is_empty());
    }

    #[tokio::test]
    async fn collect_one_account_access_denied_yields_warning_not_failure() {
        // Arrange: two accounts; assume-role into the second fails with AccessDenied.
        let list_roots_rule =
            mock!(aws_sdk_organizations::Client::list_roots).then_output(root_output);
        let root_ous_rule =
            mock!(aws_sdk_organizations::Client::list_organizational_units_for_parent)
                .then_output(|| ou_output(vec![]));
        let root_accounts_rule = mock!(aws_sdk_organizations::Client::list_accounts_for_parent)
            .then_output(|| accounts_output(vec![("111111111111", "a"), ("222222222222", "b")]));
        let orgs_client = mock_client!(
            aws_sdk_organizations,
            RuleMode::MatchAny,
            &[&list_roots_rule, &root_ous_rule, &root_accounts_rule]
        );

        let assume_ok_rule = mock!(aws_sdk_sts::Client::assume_role)
            .match_requests(|req| {
                req.role_arn() == Some("arn:aws:iam::111111111111:role/OrgJumpRole")
            })
            .then_output(|| assume_role_output("AKIATEST"));
        let assume_denied_rule = mock!(aws_sdk_sts::Client::assume_role)
            .match_requests(|req| {
                req.role_arn() == Some("arn:aws:iam::222222222222:role/OrgJumpRole")
            })
            .then_error(|| {
                aws_sdk_sts::operation::assume_role::AssumeRoleError::generic(
                    aws_smithy_types::error::ErrorMetadata::builder()
                        .code("AccessDenied")
                        .build(),
                )
            });
        let sts_client = mock_client!(
            aws_sdk_sts,
            RuleMode::MatchAny,
            &[&assume_ok_rule, &assume_denied_rule]
        );

        let mut clients = HashMap::new();
        clients.insert("111111111111".to_string(), empty_auth_details_client());

        let collector = org_collector_with(
            orgs_client,
            sts_client,
            vec![],
            Box::new(TestIamClientFactory {
                clients: Mutex::new(clients),
            }),
        );

        // Act
        let result = collector
            .collect()
            .await
            .expect("org run does not fail outright");

        // Assert
        assert_eq!(result.accounts.len(), 1);
        assert_eq!(result.warnings.len(), 1);
        assert!(
            matches!(&result.warnings[0], CollectorWarning::PartialData(msg) if msg.contains("222222222222"))
        );
    }

    #[tokio::test]
    async fn collect_surfaces_warning_for_exclude_ou_that_matched_nothing() {
        // Arrange: no OUs exist at all, but the caller passed --exclude-ou for one anyway
        // (typo'd id, or an OU name instead of an id). Without a warning this looks exactly
        // like a working exclusion that simply had nothing to exclude — the caller can't tell
        // the difference between "correctly excluded" and "silently ignored".
        let list_roots_rule =
            mock!(aws_sdk_organizations::Client::list_roots).then_output(root_output);
        let root_ous_rule =
            mock!(aws_sdk_organizations::Client::list_organizational_units_for_parent)
                .then_output(|| ou_output(vec![]));
        let root_accounts_rule = mock!(aws_sdk_organizations::Client::list_accounts_for_parent)
            .then_output(|| accounts_output(vec![("111111111111", "a")]));
        let orgs_client = mock_client!(
            aws_sdk_organizations,
            RuleMode::MatchAny,
            &[&list_roots_rule, &root_ous_rule, &root_accounts_rule]
        );

        let assume_rule =
            mock!(aws_sdk_sts::Client::assume_role).then_output(|| assume_role_output("AKIATEST"));
        let sts_client = mock_client!(aws_sdk_sts, RuleMode::MatchAny, &[&assume_rule]);

        let mut clients = HashMap::new();
        clients.insert("111111111111".to_string(), empty_auth_details_client());

        let collector = org_collector_with(
            orgs_client,
            sts_client,
            vec!["ou-typo".to_string()],
            Box::new(TestIamClientFactory {
                clients: Mutex::new(clients),
            }),
        );

        // Act
        let result = collector.collect().await.expect("org collection succeeds");

        // Assert
        assert_eq!(result.accounts.len(), 1);
        assert_eq!(result.warnings.len(), 1);
        assert!(
            matches!(&result.warnings[0], CollectorWarning::PartialData(msg) if msg.contains("ou-typo"))
        );
    }

    #[tokio::test]
    async fn enumerate_accounts_tags_override_ou_subtree_by_name() {
        // Arrange: root has child OU "ou-legacy" (name "Legacy") overridden by name; sibling
        // OU "ou-kept" is untouched.
        let list_roots_rule =
            mock!(aws_sdk_organizations::Client::list_roots).then_output(root_output);
        let root_ous_rule =
            mock!(aws_sdk_organizations::Client::list_organizational_units_for_parent)
                .match_requests(|req| req.parent_id() == Some("r-root1"))
                .then_output(|| ou_output(vec![("ou-legacy", "Legacy"), ("ou-kept", "Kept")]));
        let legacy_ous_rule =
            mock!(aws_sdk_organizations::Client::list_organizational_units_for_parent)
                .match_requests(|req| req.parent_id() == Some("ou-legacy"))
                .then_output(|| ou_output(vec![]));
        let kept_ous_rule =
            mock!(aws_sdk_organizations::Client::list_organizational_units_for_parent)
                .match_requests(|req| req.parent_id() == Some("ou-kept"))
                .then_output(|| ou_output(vec![]));
        let root_accounts_rule = mock!(aws_sdk_organizations::Client::list_accounts_for_parent)
            .match_requests(|req| req.parent_id() == Some("r-root1"))
            .then_output(|| accounts_output(vec![]));
        let legacy_accounts_rule = mock!(aws_sdk_organizations::Client::list_accounts_for_parent)
            .match_requests(|req| req.parent_id() == Some("ou-legacy"))
            .then_output(|| accounts_output(vec![("333333333333", "legacy-account")]));
        let kept_accounts_rule = mock!(aws_sdk_organizations::Client::list_accounts_for_parent)
            .match_requests(|req| req.parent_id() == Some("ou-kept"))
            .then_output(|| accounts_output(vec![("444444444444", "kept-account")]));

        let orgs_client = mock_client!(
            aws_sdk_organizations,
            RuleMode::MatchAny,
            &[
                &list_roots_rule,
                &root_ous_rule,
                &legacy_ous_rule,
                &kept_ous_rule,
                &root_accounts_rule,
                &legacy_accounts_rule,
                &kept_accounts_rule,
            ]
        );
        let sts_client = mock_client!(
            aws_sdk_sts,
            RuleMode::MatchAny,
            &[] as &[&aws_smithy_mocks::Rule]
        );
        let collector = org_collector_with_overrides(
            orgs_client,
            sts_client,
            vec![],
            vec![],
            vec![("Legacy".to_string(), "legacy-profile".to_string())],
            Box::new(TestIamClientFactory {
                clients: Mutex::new(HashMap::new()),
            }),
        );

        // Act
        let (accounts, unmatched_excludes, unmatched_overrides) = collector
            .enumerate_accounts()
            .await
            .expect("enumeration succeeds");

        // Assert
        assert!(unmatched_excludes.is_empty());
        assert!(unmatched_overrides.is_empty());
        let legacy_account = accounts
            .iter()
            .find(|a| a.id == "333333333333")
            .expect("legacy account present");
        assert_eq!(
            legacy_account.profile_override,
            Some("legacy-profile".to_string())
        );
        let kept_account = accounts
            .iter()
            .find(|a| a.id == "444444444444")
            .expect("kept account present");
        assert_eq!(kept_account.profile_override, None);
    }

    #[tokio::test]
    async fn enumerate_accounts_nested_override_replaces_ancestor_override() {
        // Arrange: root -> ou-outer (override "outer-profile") -> ou-inner (override
        // "inner-profile") -> account. The account must get the innermost match, not the
        // outer one.
        let list_roots_rule =
            mock!(aws_sdk_organizations::Client::list_roots).then_output(root_output);
        let root_ous_rule =
            mock!(aws_sdk_organizations::Client::list_organizational_units_for_parent)
                .match_requests(|req| req.parent_id() == Some("r-root1"))
                .then_output(|| ou_output(vec![("ou-outer", "Outer")]));
        let outer_ous_rule =
            mock!(aws_sdk_organizations::Client::list_organizational_units_for_parent)
                .match_requests(|req| req.parent_id() == Some("ou-outer"))
                .then_output(|| ou_output(vec![("ou-inner", "Inner")]));
        let inner_ous_rule =
            mock!(aws_sdk_organizations::Client::list_organizational_units_for_parent)
                .match_requests(|req| req.parent_id() == Some("ou-inner"))
                .then_output(|| ou_output(vec![]));
        let root_accounts_rule = mock!(aws_sdk_organizations::Client::list_accounts_for_parent)
            .match_requests(|req| req.parent_id() == Some("r-root1"))
            .then_output(|| accounts_output(vec![]));
        let outer_accounts_rule = mock!(aws_sdk_organizations::Client::list_accounts_for_parent)
            .match_requests(|req| req.parent_id() == Some("ou-outer"))
            .then_output(|| accounts_output(vec![]));
        let inner_accounts_rule = mock!(aws_sdk_organizations::Client::list_accounts_for_parent)
            .match_requests(|req| req.parent_id() == Some("ou-inner"))
            .then_output(|| accounts_output(vec![("555555555555", "inner-account")]));

        let orgs_client = mock_client!(
            aws_sdk_organizations,
            RuleMode::MatchAny,
            &[
                &list_roots_rule,
                &root_ous_rule,
                &outer_ous_rule,
                &inner_ous_rule,
                &root_accounts_rule,
                &outer_accounts_rule,
                &inner_accounts_rule,
            ]
        );
        let sts_client = mock_client!(
            aws_sdk_sts,
            RuleMode::MatchAny,
            &[] as &[&aws_smithy_mocks::Rule]
        );
        let collector = org_collector_with_overrides(
            orgs_client,
            sts_client,
            vec![],
            vec![],
            vec![
                ("Outer".to_string(), "outer-profile".to_string()),
                ("Inner".to_string(), "inner-profile".to_string()),
            ],
            Box::new(TestIamClientFactory {
                clients: Mutex::new(HashMap::new()),
            }),
        );

        // Act
        let (accounts, unmatched_excludes, unmatched_overrides) = collector
            .enumerate_accounts()
            .await
            .expect("enumeration succeeds");

        // Assert
        assert!(unmatched_excludes.is_empty());
        assert!(unmatched_overrides.is_empty());
        assert_eq!(accounts.len(), 1);
        assert_eq!(
            accounts[0].profile_override,
            Some("inner-profile".to_string())
        );
    }

    #[tokio::test]
    async fn collect_returns_fatal_error_for_ou_profile_override_that_matched_nothing() {
        // Arrange: no OUs exist at all, but the caller passed --ou-profile-override for one
        // anyway (typo'd id/name). Unlike --exclude-ou (warning-only), an unmatched override
        // must be a fatal error per the issue's acceptance criteria — a silent no-op here would
        // mean the account still goes through assume-role despite the user asking for a
        // different credential path entirely.
        let list_roots_rule =
            mock!(aws_sdk_organizations::Client::list_roots).then_output(root_output);
        let root_ous_rule =
            mock!(aws_sdk_organizations::Client::list_organizational_units_for_parent)
                .then_output(|| ou_output(vec![]));
        let root_accounts_rule = mock!(aws_sdk_organizations::Client::list_accounts_for_parent)
            .then_output(|| accounts_output(vec![("111111111111", "a")]));
        let orgs_client = mock_client!(
            aws_sdk_organizations,
            RuleMode::MatchAny,
            &[&list_roots_rule, &root_ous_rule, &root_accounts_rule]
        );
        let sts_client = mock_client!(
            aws_sdk_sts,
            RuleMode::MatchAny,
            &[] as &[&aws_smithy_mocks::Rule]
        );
        let collector = org_collector_with_overrides(
            orgs_client,
            sts_client,
            vec![],
            vec![],
            vec![("ou-does-not-exist".to_string(), "some-profile".to_string())],
            Box::new(TestIamClientFactory {
                clients: Mutex::new(HashMap::new()),
            }),
        );

        // Act: if this incorrectly proceeded to collection, it would panic — no assume_role or
        // IAM mock rule is registered.
        let result = collector.collect().await;

        // Assert
        assert!(matches!(
            result,
            Err(CollectorError::InvalidOuProfileOverride(msg)) if msg.contains("ou-does-not-exist")
        ));
    }

    #[tokio::test]
    async fn collect_mixed_org_assume_role_and_profile_override_share_run_id() {
        // Arrange: root -> ou-sso (default assume-role account) ; root -> ou-legacy (account
        // collected via a static-credential profile override). Both must land in one
        // OrgCollectionResult sharing run_id, satisfying the issue's mixed-auth acceptance
        // criterion.
        let _guard = AWS_ENV_LOCK.lock().await;

        let dir = tempfile::tempdir().expect("tempdir");
        let creds_path = dir.path().join("credentials");
        std::fs::write(
            &creds_path,
            "[legacy]\naws_access_key_id = LEGACY_KEY\naws_secret_access_key = legacy-secret\n",
        )
        .expect("write credentials file");
        std::env::set_var("AWS_SHARED_CREDENTIALS_FILE", &creds_path);
        std::env::remove_var("AWS_CONFIG_FILE");
        std::env::remove_var("AWS_PROFILE");
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_SESSION_TOKEN");

        let list_roots_rule =
            mock!(aws_sdk_organizations::Client::list_roots).then_output(root_output);
        let root_ous_rule =
            mock!(aws_sdk_organizations::Client::list_organizational_units_for_parent)
                .match_requests(|req| req.parent_id() == Some("r-root1"))
                .then_output(|| ou_output(vec![("ou-sso", "Sso"), ("ou-legacy", "Legacy")]));
        let sso_ous_rule =
            mock!(aws_sdk_organizations::Client::list_organizational_units_for_parent)
                .match_requests(|req| req.parent_id() == Some("ou-sso"))
                .then_output(|| ou_output(vec![]));
        let legacy_ous_rule =
            mock!(aws_sdk_organizations::Client::list_organizational_units_for_parent)
                .match_requests(|req| req.parent_id() == Some("ou-legacy"))
                .then_output(|| ou_output(vec![]));
        let root_accounts_rule = mock!(aws_sdk_organizations::Client::list_accounts_for_parent)
            .match_requests(|req| req.parent_id() == Some("r-root1"))
            .then_output(|| accounts_output(vec![]));
        let sso_accounts_rule = mock!(aws_sdk_organizations::Client::list_accounts_for_parent)
            .match_requests(|req| req.parent_id() == Some("ou-sso"))
            .then_output(|| accounts_output(vec![("111111111111", "sso-account")]));
        let legacy_accounts_rule = mock!(aws_sdk_organizations::Client::list_accounts_for_parent)
            .match_requests(|req| req.parent_id() == Some("ou-legacy"))
            .then_output(|| accounts_output(vec![("222222222222", "legacy-account")]));

        let orgs_client = mock_client!(
            aws_sdk_organizations,
            RuleMode::MatchAny,
            &[
                &list_roots_rule,
                &root_ous_rule,
                &sso_ous_rule,
                &legacy_ous_rule,
                &root_accounts_rule,
                &sso_accounts_rule,
                &legacy_accounts_rule,
            ]
        );

        // Only the ou-sso account may ever call sts:AssumeRole — a mock rule scoped to its
        // role ARN means a regression that routes the override account through assume-role too
        // panics on an unmatched request instead of silently passing.
        let assume_rule = mock!(aws_sdk_sts::Client::assume_role)
            .match_requests(|req| {
                req.role_arn() == Some("arn:aws:iam::111111111111:role/OrgJumpRole")
            })
            .then_output(|| assume_role_output("AKIATEST"));
        let sts_client = mock_client!(aws_sdk_sts, RuleMode::MatchAny, &[&assume_rule]);

        let mut clients = HashMap::new();
        clients.insert("111111111111".to_string(), empty_auth_details_client());
        clients.insert("222222222222".to_string(), empty_auth_details_client());

        let collector = org_collector_with_overrides(
            orgs_client,
            sts_client,
            vec![],
            vec![],
            vec![("Legacy".to_string(), "legacy".to_string())],
            Box::new(TestIamClientFactory {
                clients: Mutex::new(clients),
            }),
        );

        // Act
        let result = collector.collect().await;

        std::env::remove_var("AWS_SHARED_CREDENTIALS_FILE");
        let result = result.expect("mixed-auth org collection succeeds");

        // Assert
        assert_eq!(result.accounts.len(), 2);
        assert!(result.warnings.is_empty());
        assert!(!result.run_id.is_empty());
    }
}
