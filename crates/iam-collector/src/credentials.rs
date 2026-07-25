use crate::errors::CollectorError;
use aws_config::profile::ProfileFileCredentialsProvider;
use aws_sdk_iam::config::ProvideCredentials;
use tracing::info;

/// Binds `loader` to `name` both for region/config resolution (`.profile_name`) and for
/// credential resolution (an explicit [`ProfileFileCredentialsProvider`] scoped to that
/// profile). Binding only `.profile_name` is not enough: it tells the profile *provider*
/// which section to read, but does not reorder `aws-config`'s fixed default chain (env vars
/// → profile file → web identity → ECS → IMDS) — without the explicit provider, a named
/// profile would silently lose to `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` in the
/// environment, or fall through to a container/IMDS role if the profile doesn't exist.
pub(crate) fn bind_profile(
    loader: aws_config::ConfigLoader,
    name: &str,
) -> aws_config::ConfigLoader {
    loader.profile_name(name).credentials_provider(
        ProfileFileCredentialsProvider::builder()
            .profile_name(name)
            .build(),
    )
}

/// Eagerly resolves `config`'s credentials once. Shared by single-account ([`resolve_config`])
/// and org (`OrgCollector::resolve_override_profile_config`) credential validation so both fail
/// fast, before any IAM/STS call, instead of surfacing an opaque SDK error mid-collection.
pub(crate) async fn eager_resolve(config: &aws_config::SdkConfig) -> Result<(), String> {
    let provider = config.credentials_provider().expect(
        "SdkConfig from aws_config::defaults(..) or bind_profile(..) always sets a credentials provider",
    );
    provider
        .provide_credentials()
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Builds the `SdkConfig` for single-account (`live`/`hybrid`) collection and eagerly
/// validates its credentials.
///
/// Precedence: `profile`, if given, wins outright via [`bind_profile`]. Otherwise the standard
/// AWS credential chain applies unchanged (env vars / `AWS_PROFILE` / the `[default]` profile /
/// a container or IMDS role).
pub(crate) async fn resolve_config(
    profile: Option<&str>,
) -> Result<aws_config::SdkConfig, CollectorError> {
    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    if let Some(name) = profile {
        loader = bind_profile(loader, name);
    }

    let config = loader.load().await;
    eager_resolve(&config).await.map_err(|e| match profile {
        Some(name) => CollectorError::InvalidProfile(format!(
            "profile `{name}` credentials could not be resolved: {e}"
        )),
        None => CollectorError::CredentialsUnavailable(format!(
            "AWS credentials could not be resolved: {e}"
        )),
    })?;

    let source = if profile.is_some() {
        "profile"
    } else {
        "default-chain"
    };
    match profile {
        Some(name) => {
            info!(credential_source = source, profile = %name, "resolved AWS credentials")
        }
        None => info!(credential_source = source, "resolved AWS credentials"),
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{EnvGuard, AWS_ENV_LOCK};
    use std::io::Write;

    #[tokio::test]
    async fn resolve_config_profile_given_uses_named_profile() {
        let _guard = AWS_ENV_LOCK.lock().await;
        let _env = EnvGuard;

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
        std::env::set_var("AWS_PROFILE", "default");

        let config = resolve_config(Some("work")).await.expect("resolve config");
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

    /// Regression test: `.profile_name()` alone does not reorder `aws-config`'s fixed default
    /// chain (env vars are tried before the profile file), so `--profile` would silently lose
    /// to exported `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` without the explicit
    /// `ProfileFileCredentialsProvider` binding in [`bind_profile`].
    #[tokio::test]
    async fn resolve_config_profile_wins_over_env_vars() {
        let _guard = AWS_ENV_LOCK.lock().await;
        let _env = EnvGuard;

        let dir = tempfile::tempdir().expect("tempdir");
        let creds_path = dir.path().join("credentials");
        std::fs::write(
            &creds_path,
            "[work]\naws_access_key_id = WORK_KEY\naws_secret_access_key = work-secret\n",
        )
        .expect("write credentials file");

        std::env::set_var("AWS_SHARED_CREDENTIALS_FILE", &creds_path);
        std::env::set_var("AWS_ACCESS_KEY_ID", "ENV_KEY");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "env-secret");

        let config = resolve_config(Some("work")).await.expect("resolve config");
        let creds = config
            .credentials_provider()
            .expect("has credentials provider")
            .provide_credentials()
            .await
            .expect("resolve credentials");
        assert_eq!(
            creds.access_key_id(),
            "WORK_KEY",
            "--profile must win over AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY in the environment"
        );
    }

    #[tokio::test]
    async fn resolve_config_invalid_profile_fails_fast_naming_profile() {
        let _guard = AWS_ENV_LOCK.lock().await;
        let _env = EnvGuard;

        let dir = tempfile::tempdir().expect("tempdir");
        let creds_path = dir.path().join("credentials");
        std::fs::write(
            &creds_path,
            "[default]\naws_access_key_id = DEFAULT_KEY\naws_secret_access_key = default-secret\n",
        )
        .expect("write credentials file");

        std::env::set_var("AWS_SHARED_CREDENTIALS_FILE", &creds_path);

        let err = resolve_config(Some("does-not-exist"))
            .await
            .expect_err("unknown profile must fail eagerly");

        match err {
            CollectorError::InvalidProfile(msg) => assert!(
                msg.contains("does-not-exist"),
                "error must name the profile: {msg}"
            ),
            other => panic!("expected InvalidProfile, got {other:?}"),
        }
    }
}
