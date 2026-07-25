/// Serializes every test in this crate that mutates process-wide AWS credential env vars
/// (`AWS_PROFILE`, `AWS_ACCESS_KEY_ID`, `AWS_SHARED_CREDENTIALS_FILE`, ...). `cargo test` runs
/// unit tests within one binary concurrently by default; a per-module lock isn't enough since
/// env vars are process-global and `org.rs`'s and `credentials.rs`'s env-mutating tests would
/// otherwise race each other.
pub(crate) static AWS_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
