use crate::errors::{CollectorError, CollectorWarning};
use crate::live::LiveCollector;
use crate::traits::CollectedData;
use crate::traits::IamDataSource;
use crate::util::map_sdk_error;
use aws_sdk_iam::config::{Credentials, Region};
use std::future::Future;
use std::pin::Pin;
use std::time::SystemTime;
use tracing::{info, warn};
use uuid::Uuid;

/// One AWS account enumerated from the organization, with its OU path (root id first).
#[derive(Debug, Clone)]
pub struct OrgAccount {
    pub id: String,
    pub name: String,
    pub ou_path: Vec<String>,
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
async fn resolve_configs(
    management_profile: String,
    jump_from_profile: Option<String>,
) -> (aws_config::SdkConfig, aws_config::SdkConfig) {
    let discovery_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .profile_name(management_profile)
        .load()
        .await;

    let mut jump_from_loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    if let Some(profile) = jump_from_profile {
        jump_from_loader = jump_from_loader.profile_name(profile);
    }
    let jump_from_config = jump_from_loader.load().await;

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
    exclude_ous: Vec<String>,
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
    pub async fn from_profile(
        management_profile: impl Into<String>,
        jump_from_profile: Option<impl Into<String>>,
        assume_role_name: impl Into<String>,
        exclude_ous: Vec<String>,
    ) -> Result<Self, CollectorError> {
        let (discovery_config, jump_from_config) =
            resolve_configs(management_profile.into(), jump_from_profile.map(Into::into)).await;

        let region = discovery_config
            .region()
            .cloned()
            .unwrap_or_else(|| Region::new("us-east-1"));

        Ok(Self {
            orgs_client: aws_sdk_organizations::Client::new(&discovery_config),
            sts_client: aws_sdk_sts::Client::new(&jump_from_config),
            assume_role_name: assume_role_name.into(),
            exclude_ous,
            region,
            client_factory: Box::new(RealIamClientFactory),
        })
    }

    /// Run the org-wide collection: enumerate accounts, assume into each, collect.
    /// A single account's failure is recorded as a warning, not a fatal error.
    pub async fn collect(&self) -> Result<OrgCollectionResult, CollectorError> {
        let run_id = Uuid::new_v4().to_string();
        let accounts = self.enumerate_accounts().await?;
        info!(accounts = accounts.len(), "enumerated org accounts");

        let mut collected = Vec::with_capacity(accounts.len());
        let mut warnings = Vec::new();

        for account in &accounts {
            match self.collect_account(account).await {
                Ok(data) => collected.push(data),
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

    async fn collect_account(&self, account: &OrgAccount) -> Result<CollectedData, CollectorError> {
        let role_arn = format!("arn:aws:iam::{}:role/{}", account.id, self.assume_role_name);
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
        let credentials = Credentials::new(
            creds.access_key_id().to_string(),
            creds.secret_access_key().to_string(),
            Some(creds.session_token().to_string()),
            expires_after,
            "aws-iam-grapher-org-assume-role",
        );

        let iam_client = self
            .client_factory
            .build(&account.id, credentials, self.region.clone());

        LiveCollector::new(iam_client).collect().await
    }

    async fn enumerate_accounts(&self) -> Result<Vec<OrgAccount>, CollectorError> {
        let mut accounts = Vec::new();
        let mut root_paginator = self.orgs_client.list_roots().into_paginator().send();
        while let Some(page) = root_paginator.next().await {
            let page = page.map_err(map_sdk_error)?;
            for root in page.roots() {
                let root_id = root.id().unwrap_or_default().to_string();
                self.collect_accounts_under(root_id.clone(), vec![root_id], &mut accounts)
                    .await?;
            }
        }
        Ok(accounts)
    }

    /// Recursively walk OUs under `parent_id`, collecting accounts and pruning excluded
    /// OU subtrees. Boxed because async fns cannot recurse directly (infinite-sized future).
    fn collect_accounts_under<'a>(
        &'a self,
        parent_id: String,
        ou_path: Vec<String>,
        out: &'a mut Vec<OrgAccount>,
    ) -> Pin<Box<dyn Future<Output = Result<(), CollectorError>> + 'a>> {
        Box::pin(async move {
            let mut acct_paginator = self
                .orgs_client
                .list_accounts_for_parent()
                .parent_id(&parent_id)
                .into_paginator()
                .send();
            while let Some(page) = acct_paginator.next().await {
                let page = page.map_err(map_sdk_error)?;
                for a in page.accounts() {
                    out.push(OrgAccount {
                        id: a.id().unwrap_or_default().to_string(),
                        name: a.name().unwrap_or_default().to_string(),
                        ou_path: ou_path.clone(),
                    });
                }
            }

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
                    if self.exclude_ous.contains(&ou_id) {
                        continue;
                    }
                    let mut child_path = ou_path.clone();
                    child_path.push(ou_id.clone());
                    self.collect_accounts_under(ou_id, child_path, out).await?;
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
    use std::collections::HashMap;
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
        exclude_ous: Vec<String>,
        client_factory: Box<dyn IamClientFactory>,
    ) -> OrgCollector {
        OrgCollector {
            orgs_client,
            sts_client,
            assume_role_name: "OrgJumpRole".to_string(),
            exclude_ous,
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

        let (discovery_config, jump_from_config) = resolve_configs("mgmt".to_string(), None).await;

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
        let accounts = collector
            .enumerate_accounts()
            .await
            .expect("enumeration succeeds");

        // Assert
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
        let accounts = collector
            .enumerate_accounts()
            .await
            .expect("enumeration succeeds");

        // Assert: only the kept-OU account shows up; the excluded subtree was never queried
        // (no rule registered for parent_id == "ou-excluded", so a query there would panic).
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, "333333333333");
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
}
