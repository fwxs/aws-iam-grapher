/// Serializes every test in this crate that mutates process-wide AWS credential env vars.
/// Env vars are process-global, so `org.rs`'s and `credentials.rs`'s env-mutating tests must
/// share one lock rather than one each.
pub(crate) static AWS_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Removes every AWS credential env var a test may have set, unconditionally, on drop — so a
/// failed assertion mid-test (the `tokio::Mutex` guard above isn't poisoned by a panic) can't
/// leak env state into the next test.
pub(crate) struct EnvGuard;

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for key in [
            "AWS_SHARED_CREDENTIALS_FILE",
            "AWS_CONFIG_FILE",
            "AWS_PROFILE",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
        ] {
            std::env::remove_var(key);
        }
    }
}
