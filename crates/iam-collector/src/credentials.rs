use crate::errors::CollectorError;
use aws_sdk_iam::config::ProvideCredentials;
use tracing::info;

/// Where resolved AWS credentials for a single-account collection run came from — logged
/// (never with key material) so a wrong-account run is diagnosable after the fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialSource {
    Profile,
    Environment,
    DefaultChain,
}

impl CredentialSource {
    fn as_str(self) -> &'static str {
        match self {
            CredentialSource::Profile => "profile",
            CredentialSource::Environment => "environment",
            CredentialSource::DefaultChain => "default-chain",
        }
    }
}

/// Outcome of eagerly resolving a config's credentials, distinguishing "no provider
/// configured" (e.g. an unknown `--profile`) from "provider configured but resolution failed"
/// (e.g. an expired SSO session) so callers can compose a targeted message.
pub(crate) enum CredentialResolutionFailure {
    NotFound,
    ResolveFailed(String),
}

/// Eagerly resolves `config`'s credentials once. Shared by single-account ([`resolve_config`])
/// and org (`OrgCollector::resolve_override_profile_config`) credential validation so both fail
/// fast, before any IAM/STS call, instead of surfacing an opaque SDK error mid-collection.
pub(crate) async fn eager_resolve(
    config: &aws_config::SdkConfig,
) -> Result<(), CredentialResolutionFailure> {
    let provider = config
        .credentials_provider()
        .ok_or(CredentialResolutionFailure::NotFound)?;
    provider
        .provide_credentials()
        .await
        .map_err(|e| CredentialResolutionFailure::ResolveFailed(e.to_string()))?;
    Ok(())
}

/// Builds the `SdkConfig` for single-account (`live`/`hybrid`) collection and eagerly
/// validates its credentials.
///
/// Precedence: `profile`, if given, wins outright. Otherwise, if `AWS_ACCESS_KEY_ID` and
/// `AWS_SECRET_ACCESS_KEY` are both set, the environment is used (the default chain's own first
/// rung — this just makes that fact explicit and logged). Otherwise the standard AWS credential
/// chain (`AWS_PROFILE` / the `[default]` profile / a container or IMDS role) applies unchanged.
pub(crate) async fn resolve_config(
    profile: Option<&str>,
) -> Result<aws_config::SdkConfig, CollectorError> {
    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    let source = if let Some(name) = profile {
        loader = loader.profile_name(name);
        CredentialSource::Profile
    } else if std::env::var_os("AWS_ACCESS_KEY_ID").is_some()
        && std::env::var_os("AWS_SECRET_ACCESS_KEY").is_some()
    {
        CredentialSource::Environment
    } else {
        CredentialSource::DefaultChain
    };

    let config = loader.load().await;
    eager_resolve(&config).await.map_err(|failure| {
        let detail = match failure {
            CredentialResolutionFailure::NotFound => match profile {
                Some(name) => format!(
                    "profile `{name}` was not found in the local AWS config/credentials files"
                ),
                None => "no AWS credential provider could be resolved".to_string(),
            },
            CredentialResolutionFailure::ResolveFailed(e) => match profile {
                Some(name) => format!("profile `{name}` credentials could not be resolved: {e}"),
                None => format!("AWS credentials could not be resolved: {e}"),
            },
        };
        CollectorError::InvalidProfile(detail)
    })?;

    match profile {
        Some(name) => {
            info!(credential_source = source.as_str(), profile = %name, "resolved AWS credentials")
        }
        None => info!(
            credential_source = source.as_str(),
            "resolved AWS credentials"
        ),
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::AWS_ENV_LOCK;
    use std::io::Write;

    #[tokio::test]
    async fn resolve_config_profile_given_uses_named_profile() {
        let _guard = AWS_ENV_LOCK.lock().await;

        let dir = tempfile::tempdir().expect("tempdir");
        let creds_path = dir.path().join("credentials");
        let mut file = std::fs::File::create(&creds_path).expect("create credentials file");
        writeln!(
            file,
            "[work]\naws_access_key_id = WORK_KEY\naws_secret_access_key = work-secret\n\n\
             [default]\naws_access_key_id = DEFAULT_KEY\naws_secret_access_key = default-secret\n"
        )
        .expect("write credentials file");

        std::env::set_var("AWS_SHARED_CREDENTIALS_FILE", &creds_path);
        std::env::remove_var("AWS_CONFIG_FILE");
        std::env::set_var("AWS_PROFILE", "default");
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_SESSION_TOKEN");

        let config = resolve_config(Some("work")).await.expect("resolve config");

        std::env::remove_var("AWS_SHARED_CREDENTIALS_FILE");
        std::env::remove_var("AWS_PROFILE");

        let creds = config
            .credentials_provider()
            .expect("has credentials provider")
            .provide_credentials()
            .await
            .expect("resolve credentials");
        assert_eq!(
            creds.access_key_id(),
            "WORK_KEY",
            "--profile must win over AWS_PROFILE set in the environment"
        );
    }

    #[tokio::test]
    async fn resolve_config_env_vars_given_are_used_when_no_profile() {
        let _guard = AWS_ENV_LOCK.lock().await;

        std::env::remove_var("AWS_SHARED_CREDENTIALS_FILE");
        std::env::remove_var("AWS_CONFIG_FILE");
        std::env::remove_var("AWS_PROFILE");
        std::env::set_var("AWS_ACCESS_KEY_ID", "ENV_KEY");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "env-secret");
        std::env::remove_var("AWS_SESSION_TOKEN");

        let config = resolve_config(None).await.expect("resolve config");
        // The environment provider re-reads its vars on every call rather than caching the
        // first resolution, so they must still be set for this second lookup too.
        let creds = config
            .credentials_provider()
            .expect("has credentials provider")
            .provide_credentials()
            .await
            .expect("resolve credentials");

        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");

        assert_eq!(creds.access_key_id(), "ENV_KEY");
    }

    #[tokio::test]
    async fn resolve_config_neither_given_falls_back_to_default_chain() {
        let _guard = AWS_ENV_LOCK.lock().await;

        let dir = tempfile::tempdir().expect("tempdir");
        let creds_path = dir.path().join("credentials");
        std::fs::write(
            &creds_path,
            "[default]\naws_access_key_id = DEFAULT_KEY\naws_secret_access_key = default-secret\n",
        )
        .expect("write credentials file");

        std::env::set_var("AWS_SHARED_CREDENTIALS_FILE", &creds_path);
        std::env::remove_var("AWS_CONFIG_FILE");
        std::env::remove_var("AWS_PROFILE");
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_SESSION_TOKEN");

        let config = resolve_config(None).await.expect("resolve config");

        std::env::remove_var("AWS_SHARED_CREDENTIALS_FILE");

        let creds = config
            .credentials_provider()
            .expect("has credentials provider")
            .provide_credentials()
            .await
            .expect("resolve credentials");
        assert_eq!(creds.access_key_id(), "DEFAULT_KEY");
    }

    #[tokio::test]
    async fn resolve_config_invalid_profile_fails_fast_naming_profile() {
        let _guard = AWS_ENV_LOCK.lock().await;

        let dir = tempfile::tempdir().expect("tempdir");
        let creds_path = dir.path().join("credentials");
        std::fs::write(
            &creds_path,
            "[default]\naws_access_key_id = DEFAULT_KEY\naws_secret_access_key = default-secret\n",
        )
        .expect("write credentials file");

        std::env::set_var("AWS_SHARED_CREDENTIALS_FILE", &creds_path);
        std::env::remove_var("AWS_CONFIG_FILE");
        std::env::remove_var("AWS_PROFILE");
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_SESSION_TOKEN");

        let err = resolve_config(Some("does-not-exist"))
            .await
            .expect_err("unknown profile must fail eagerly");

        std::env::remove_var("AWS_SHARED_CREDENTIALS_FILE");

        match err {
            CollectorError::InvalidProfile(msg) => assert!(
                msg.contains("does-not-exist"),
                "error must name the profile: {msg}"
            ),
            other => panic!("expected InvalidProfile, got {other:?}"),
        }
    }
}
