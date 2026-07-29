use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{client, trie::Trie, ExpanderError};

/// Env var overriding [`DEFAULT_CACHE_TTL_DAYS`]. Invalid values (non-numeric or non-positive)
/// fall back to the default with a logged warning.
const CACHE_TTL_ENV_VAR: &str = "AWS_IAM_EXPANDER_CACHE_TTL_DAYS";

/// How long a full-catalog fetch is trusted before an unknown-service lookup triggers a
/// refetch, even though the disk cache is otherwise complete. AWS adds actions to services
/// regularly, so a cache trusted forever would silently miss new actions — for a security
/// tool that under-reports permissions, that's a correctness bug, not just a perf one. 30 days
/// balances that staleness risk against the point of this cache: avoiding a network round trip
/// (and offline-run failures) on every process start.
const DEFAULT_CACHE_TTL_DAYS: i64 = 30;

/// Disk-backed cache of IAM action lists, keyed by service name.
///
/// Actions are stored as a flat JSON map so they can be read back without
/// network access.  The in-memory tries are rebuilt from that map on load.
pub struct ActionCache {
    path: PathBuf,
    raw: RawCache,
    tries: HashMap<String, Trie>,
    // Whether the full catalog is known to already be on disk and fresh. Computed once in
    // `load()` from `raw.fetched_at`, and flipped to `true` after any in-run full fetch.
    fetched_all: bool,
}

#[derive(Default, Serialize, Deserialize)]
struct RawCache {
    actions: HashMap<String, Vec<String>>,
    /// When the full catalog was last fetched. `#[serde(default)]` so cache files written
    /// before this field existed deserialize as `None` (treated as stale — see [`is_fresh`]).
    #[serde(default)]
    fetched_at: Option<DateTime<Utc>>,
}

impl ActionCache {
    /// Loads the cache from the default path, or starts with an empty cache.
    pub async fn load() -> Result<Self, ExpanderError> {
        let path = default_cache_path()?;
        let raw: RawCache = if path.exists() {
            let text = tokio::fs::read_to_string(&path).await?;
            serde_json::from_str(&text)?
        } else {
            RawCache::default()
        };
        let tries = build_tries(&raw.actions);
        let fetched_all = is_fresh(&raw, resolve_ttl_days());
        Ok(Self {
            path,
            raw,
            tries,
            fetched_all,
        })
    }

    /// Returns the trie for `service`, fetching the full catalog from the
    /// network when missing.
    ///
    /// The remote API only exposes a bulk endpoint, so the first miss fetches
    /// every service at once and populates the cache; subsequent misses in
    /// the same run are treated as unknown services without another request.
    /// No longer persists on every miss — call [`flush`] once at end of run.
    pub(crate) async fn get_or_fetch(&mut self, service: &str) -> Result<&Trie, ExpanderError> {
        self.get_or_fetch_with(service, client::fetch_all_actions)
            .await
    }

    /// Same as [`get_or_fetch`], but takes the full-catalog fetcher as a parameter so tests can
    /// assert exactly how many times (and whether at all) it gets called, without performing
    /// real network I/O.
    async fn get_or_fetch_with<F, Fut>(
        &mut self,
        service: &str,
        fetch_all: F,
    ) -> Result<&Trie, ExpanderError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<HashMap<String, Vec<String>>, ExpanderError>>,
    {
        if !self.tries.contains_key(service) {
            if self.fetched_all {
                return Err(ExpanderError::UnknownService(service.to_string()));
            }
            let all = fetch_all().await?;
            self.fetched_all = true;
            self.raw.fetched_at = Some(Utc::now());
            for (svc, actions) in all {
                let mut trie = Trie::new();
                for action in &actions {
                    trie.insert(&format!("{svc}:{action}"));
                }
                self.raw.actions.insert(svc.clone(), actions);
                self.tries.insert(svc, trie);
            }
            if !self.tries.contains_key(service) {
                return Err(ExpanderError::UnknownService(service.to_string()));
            }
        }
        // safe: we just inserted it above if it was missing
        Ok(self.tries.get(service).expect("service was just inserted"))
    }

    /// Atomically persists the cache to disk.
    ///
    /// Writes to a uniquely named `.tmp` file then renames so a crash during write leaves the
    /// previous cache file intact.  The tmp name carries a fresh UUID because `collect org`
    /// flushes concurrently from several accounts at once — a shared tmp path would let those
    /// writes interleave and publish corrupt JSON.  Concurrent flushes still race on the
    /// rename, so the last one wins and the others' additions are lost; that only costs cache
    /// misses on the next run.  Call once at the end of a collection run.
    pub async fn flush(&self) -> Result<(), ExpanderError> {
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let tmp = self
            .path
            .with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let json = serde_json::to_string_pretty(&self.raw)?;
        tokio::fs::write(&tmp, &json).await?;
        tokio::fs::rename(&tmp, &self.path).await?;
        Ok(())
    }

    /// Constructs an `ActionCache` directly from pre-built tries (test helper).
    #[cfg(test)]
    pub(crate) fn from_parts(path: PathBuf, tries: HashMap<String, Trie>) -> Self {
        let actions: HashMap<String, Vec<String>> =
            tries.keys().map(|k| (k.clone(), vec![])).collect();
        Self {
            path,
            raw: RawCache {
                actions,
                fetched_at: None,
            },
            tries,
            fetched_all: false,
        }
    }
}

fn build_tries(actions: &HashMap<String, Vec<String>>) -> HashMap<String, Trie> {
    actions
        .iter()
        .map(|(service, acts)| {
            let mut trie = Trie::new();
            for action in acts {
                trie.insert(&format!("{service}:{action}"));
            }
            (service.clone(), trie)
        })
        .collect()
}

/// A loaded cache counts as fresh (safe to skip re-fetching on an unknown-service miss) only
/// when it actually holds a full catalog (`fetched_at` set — legacy cache files without the
/// field parse to `None` and are treated as stale) and that fetch is younger than `ttl_days`.
/// An empty `actions` map (fresh install, or a previous run whose fetch never completed) is
/// never fresh regardless of `fetched_at`.
fn is_fresh(raw: &RawCache, ttl_days: i64) -> bool {
    if raw.actions.is_empty() {
        return false;
    }
    let Some(fetched_at) = raw.fetched_at else {
        return false;
    };
    Utc::now().signed_duration_since(fetched_at) < chrono::Duration::days(ttl_days)
}

/// Resolves the cache TTL in days from [`CACHE_TTL_ENV_VAR`], falling back to
/// [`DEFAULT_CACHE_TTL_DAYS`] on an unset or invalid value.
fn resolve_ttl_days() -> i64 {
    parse_ttl_days(std::env::var(CACHE_TTL_ENV_VAR).ok())
}

/// Pure parsing logic behind [`resolve_ttl_days`], split out so tests can exercise every case
/// without mutating process-global environment state.
fn parse_ttl_days(raw: Option<String>) -> i64 {
    match raw {
        None => DEFAULT_CACHE_TTL_DAYS,
        Some(value) => match value.parse::<i64>() {
            Ok(days) if days > 0 => days,
            _ => {
                tracing::warn!(
                    "invalid {CACHE_TTL_ENV_VAR} value {value:?}; using default of {DEFAULT_CACHE_TTL_DAYS} days"
                );
                DEFAULT_CACHE_TTL_DAYS
            }
        },
    }
}

fn default_cache_path() -> Result<PathBuf, ExpanderError> {
    let home = std::env::var("HOME").map_err(|_| {
        ExpanderError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "HOME environment variable is not set",
        ))
    })?;
    Ok(PathBuf::from(home)
        .join(".cache")
        .join("aws-iam-expansion")
        .join("actions.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache_with(path: PathBuf, service: &str, action_count: usize) -> ActionCache {
        let actions: Vec<String> = (0..action_count)
            .map(|index| format!("{service}Action{index:06}"))
            .collect();
        let raw = RawCache {
            actions: HashMap::from([(service.to_string(), actions)]),
            fetched_at: None,
        };
        let tries = build_tries(&raw.actions);
        ActionCache {
            path,
            raw,
            tries,
            fetched_all: false,
        }
    }

    #[tokio::test]
    async fn flush_concurrent_writers_leaves_parseable_cache_file() {
        // Arrange: three caches sharing one path, as `collect org` produces when several
        // accounts finish expansion at once. The payloads are large enough that a shared tmp
        // path would interleave mid-write rather than landing in one atomic block.
        let directory = std::env::temp_dir().join(format!("iam-expander-{}", uuid::Uuid::new_v4()));
        let path = directory.join("actions.json");
        let caches = [
            cache_with(path.clone(), "alpha", 20_000),
            cache_with(path.clone(), "beta", 20_000),
            cache_with(path.clone(), "gamma", 20_000),
        ];

        // Act
        let (first, second, third) =
            tokio::join!(caches[0].flush(), caches[1].flush(), caches[2].flush());

        // Assert: every flush succeeded and the published file is intact JSON holding exactly
        // one writer's payload — never a mix of two.
        assert!(first.is_ok() && second.is_ok() && third.is_ok());
        let text = tokio::fs::read_to_string(&path)
            .await
            .expect("cache file exists after flush");
        let parsed: RawCache = serde_json::from_str(&text).expect("published cache is valid JSON");
        assert_eq!(parsed.actions.len(), 1);

        let leftovers = std::fs::read_dir(&directory)
            .expect("cache directory exists")
            .count();
        assert_eq!(
            leftovers, 1,
            "tmp files should be renamed away, not left behind"
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    fn raw_with(fetched_at: Option<DateTime<Utc>>, has_actions: bool) -> RawCache {
        RawCache {
            actions: if has_actions {
                HashMap::from([("s3".to_string(), vec!["GetObject".to_string()])])
            } else {
                HashMap::new()
            },
            fetched_at,
        }
    }

    #[test]
    fn is_fresh_true_for_recent_fetch_within_ttl() {
        let raw = raw_with(Some(Utc::now() - chrono::Duration::days(1)), true);
        assert!(is_fresh(&raw, 30));
    }

    #[test]
    fn is_fresh_false_for_fetch_older_than_ttl() {
        let raw = raw_with(Some(Utc::now() - chrono::Duration::days(31)), true);
        assert!(!is_fresh(&raw, 30));
    }

    #[test]
    fn is_fresh_false_when_fetched_at_missing_legacy_cache() {
        let raw = raw_with(None, true);
        assert!(!is_fresh(&raw, 30));
    }

    #[test]
    fn is_fresh_false_when_actions_empty_even_with_recent_fetched_at() {
        let raw = raw_with(Some(Utc::now()), false);
        assert!(!is_fresh(&raw, 30));
    }

    #[test]
    fn legacy_cache_json_without_fetched_at_deserializes_as_stale() {
        let json = r#"{"actions":{"s3":["GetObject"]}}"#;
        let raw: RawCache = serde_json::from_str(json).expect("legacy cache file must parse");
        assert_eq!(raw.fetched_at, None);
        assert!(!is_fresh(&raw, 30));
    }

    #[test]
    fn parse_ttl_days_defaults_when_env_unset() {
        assert_eq!(parse_ttl_days(None), DEFAULT_CACHE_TTL_DAYS);
    }

    #[test]
    fn parse_ttl_days_honors_valid_override() {
        assert_eq!(parse_ttl_days(Some("7".to_string())), 7);
    }

    #[test]
    fn parse_ttl_days_falls_back_on_non_numeric_value() {
        assert_eq!(
            parse_ttl_days(Some("banana".to_string())),
            DEFAULT_CACHE_TTL_DAYS
        );
    }

    #[test]
    fn parse_ttl_days_falls_back_on_non_positive_value() {
        assert_eq!(
            parse_ttl_days(Some("0".to_string())),
            DEFAULT_CACHE_TTL_DAYS
        );
        assert_eq!(
            parse_ttl_days(Some("-5".to_string())),
            DEFAULT_CACHE_TTL_DAYS
        );
    }

    #[tokio::test]
    async fn fresh_cache_skips_network_on_unknown_service_miss() {
        // A cache that already believes it holds the full catalog must never call the
        // fetcher on an unknown-service miss — the panic in the closure proves it wasn't.
        let mut cache = cache_with(PathBuf::from("/tmp/unused"), "s3", 1);
        cache.fetched_all = true;

        let result = cache
            .get_or_fetch_with("totally-unknown-service", || async {
                panic!("fetch_all must not be called when the cache is already fresh")
            })
            .await;

        assert!(matches!(result, Err(ExpanderError::UnknownService(_))));
    }

    #[tokio::test]
    async fn stale_cache_refetches_exactly_once_per_run() {
        let mut cache = cache_with(PathBuf::from("/tmp/unused"), "s3", 1);
        assert!(!cache.fetched_all);
        let call_count = std::sync::atomic::AtomicUsize::new(0);

        // First miss: fetches, but the mock catalog still doesn't contain "unknown-a".
        let first = cache
            .get_or_fetch_with("unknown-a", || async {
                call_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(HashMap::from([(
                    "ec2".to_string(),
                    vec!["DescribeInstances".to_string()],
                )]))
            })
            .await;
        assert!(matches!(first, Err(ExpanderError::UnknownService(_))));
        assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Second miss in the same run: cache now believes it holds the full catalog, so the
        // fetcher must not run again.
        let second = cache
            .get_or_fetch_with("unknown-b", || async {
                panic!("fetch_all must not be called a second time in the same run")
            })
            .await;
        assert!(matches!(second, Err(ExpanderError::UnknownService(_))));
        assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
