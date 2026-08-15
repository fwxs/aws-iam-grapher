use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{client, trie::Trie, ExpanderError};

/// Env var overriding [`DEFAULT_CACHE_TTL_DAYS`]. Invalid values (non-numeric, non-positive, or
/// outside [`MAX_CACHE_TTL_DAYS`]) fall back to the default with a logged warning.
const CACHE_TTL_ENV_VAR: &str = "AWS_IAM_EXPANDER_CACHE_TTL_DAYS";

/// Upper bound accepted for the TTL override (~100 years). Exists so an absurd env value (e.g.
/// `i64::MAX`) takes the invalid-value fallback path instead of overflowing
/// `chrono::Duration::days`, which panics past ~1.06e11 days.
const MAX_CACHE_TTL_DAYS: i64 = 36_500;

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
    // Set only when the catalog was actually (re)fetched from the network this run. `flush()`
    // no-ops when this is `false`, so a pure-read run (every service already cached and fresh)
    // never rewrites the catalog file.
    dirty: bool,
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
            dirty: false,
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
            self.dirty = true;
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
    ///
    /// No-ops (logged at debug) when the catalog was never fetched/mutated this run — a
    /// pure-read run must not rewrite the file on disk.
    pub async fn flush(&mut self) -> Result<(), ExpanderError> {
        if !self.dirty {
            tracing::debug!("cache unchanged; skipping flush");
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let tmp = self
            .path
            .with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let json = serde_json::to_string_pretty(&self.raw)?;
        tokio::fs::write(&tmp, &json).await?;
        tokio::fs::rename(&tmp, &self.path).await?;
        self.dirty = false;
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
            dirty: false,
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
    let age = Utc::now().signed_duration_since(fetched_at);
    // A future `fetched_at` (clock skew, restored snapshot, hand-edited cache file) yields a
    // negative age, which must not read as fresh — that would pin the cache "fresh" forever,
    // silently under-reporting newly added actions until the wall clock catches up.
    !age.num_seconds().is_negative() && age < chrono::Duration::days(ttl_days)
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
            Ok(days) if (1..=MAX_CACHE_TTL_DAYS).contains(&days) => days,
            _ => {
                tracing::warn!(
                    value = %value,
                    default_days = DEFAULT_CACHE_TTL_DAYS,
                    "invalid {CACHE_TTL_ENV_VAR} value; using default"
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
            dirty: true,
        }
    }

    #[tokio::test]
    async fn flush_concurrent_writers_leaves_parseable_cache_file() {
        // Arrange: three caches sharing one path, as `collect org` produces when several
        // accounts finish expansion at once. The payloads are large enough that a shared tmp
        // path would interleave mid-write rather than landing in one atomic block.
        let directory = std::env::temp_dir().join(format!("iam-expander-{}", uuid::Uuid::new_v4()));
        let path = directory.join("actions.json");
        let mut cache_a = cache_with(path.clone(), "alpha", 20_000);
        let mut cache_b = cache_with(path.clone(), "beta", 20_000);
        let mut cache_c = cache_with(path.clone(), "gamma", 20_000);

        // Act
        let (first, second, third) =
            tokio::join!(cache_a.flush(), cache_b.flush(), cache_c.flush());

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
        // Neither test in this pair calls `flush()`, so the path is never written to; it's
        // still a fresh temp path (not a shared hardcoded one) so nothing later that adds a
        // `flush()` call here starts writing into a shared location.
        let path = std::env::temp_dir().join(format!("iam-expander-{}.json", uuid::Uuid::new_v4()));
        let mut cache = cache_with(path, "s3", 1);
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
        let path = std::env::temp_dir().join(format!("iam-expander-{}.json", uuid::Uuid::new_v4()));
        let mut cache = cache_with(path, "s3", 1);
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

    #[tokio::test]
    async fn fetch_stamps_fetched_at_and_survives_flush_and_reload() {
        // This is the write-side counterpart to the freshness tests above: a fetch must
        // actually persist `fetched_at` through `flush()`, or the next `load()` never sees the
        // cache as fresh and the original re-fetch-every-run bug is back — with every read-side
        // test above still green.
        let directory = std::env::temp_dir().join(format!("iam-expander-{}", uuid::Uuid::new_v4()));
        let path = directory.join("actions.json");
        let mut cache = ActionCache {
            path: path.clone(),
            raw: RawCache {
                actions: HashMap::new(),
                fetched_at: None,
            },
            tries: HashMap::new(),
            fetched_all: false,
            dirty: false,
        };

        cache
            .get_or_fetch_with("s3", || async {
                Ok(HashMap::from([(
                    "s3".to_string(),
                    vec!["GetObject".to_string()],
                )]))
            })
            .await
            .expect("service just fetched must be found");

        cache.flush().await.expect("flush must succeed");

        let text = tokio::fs::read_to_string(&path)
            .await
            .expect("cache file exists after flush");
        let parsed: RawCache = serde_json::from_str(&text).expect("published cache is valid JSON");
        assert!(
            parsed.fetched_at.is_some(),
            "fetched_at must survive the flush round trip"
        );
        assert!(
            is_fresh(&parsed, DEFAULT_CACHE_TTL_DAYS),
            "a cache just fetched and flushed must be seen as fresh on the next load"
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    // ── dirty flag: flush() must no-op on a pure-read run, and persist exactly once on a
    // fetching run (issue #87) ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn flush_pure_read_run_leaves_cache_file_untouched() {
        // Arrange: a cache file already on disk with the only service the run will look up.
        let directory = std::env::temp_dir().join(format!("iam-expander-{}", uuid::Uuid::new_v4()));
        let path = directory.join("actions.json");
        tokio::fs::create_dir_all(&directory)
            .await
            .expect("create test dir");
        let seed = RawCache {
            actions: HashMap::from([("s3".to_string(), vec!["GetObject".to_string()])]),
            fetched_at: Some(Utc::now()),
        };
        let seed_json = serde_json::to_string_pretty(&seed).expect("serialize seed cache");
        tokio::fs::write(&path, &seed_json)
            .await
            .expect("write seed cache");
        let original_content = tokio::fs::read_to_string(&path)
            .await
            .expect("read seed cache back");
        let original_mtime = tokio::fs::metadata(&path)
            .await
            .expect("stat seed cache")
            .modified()
            .expect("seed cache has an mtime");

        // Act: a read-only run — build the cache directly against the seeded temp `path`
        // (mirroring `flush_after_fetch_persists_exactly_once`), not via `ActionCache::load()`,
        // which would read the real default cache path instead of this test's temp file.
        let tries = build_tries(&seed.actions);
        let fetched_all = is_fresh(&seed, DEFAULT_CACHE_TTL_DAYS);
        let mut cache = ActionCache {
            path: path.clone(),
            raw: seed,
            tries,
            fetched_all,
            dirty: false,
        };
        cache
            .get_or_fetch_with("s3", || async {
                panic!("fetch must not run — s3 is already cached and fresh")
            })
            .await
            .expect("s3 trie must already be present");
        assert!(
            !cache.dirty,
            "a pure-read lookup must never mark the cache dirty"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        cache.flush().await.expect("flush must succeed as a no-op");

        // Assert: the file on disk was never touched.
        let final_content = tokio::fs::read_to_string(&path)
            .await
            .expect("cache file still readable");
        let final_mtime = tokio::fs::metadata(&path)
            .await
            .expect("stat cache after flush")
            .modified()
            .expect("cache still has an mtime");
        assert_eq!(
            original_content, final_content,
            "pure-read flush must not rewrite the cache file"
        );
        assert_eq!(
            original_mtime, final_mtime,
            "pure-read flush must not touch the cache file"
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[tokio::test]
    async fn flush_after_fetch_persists_exactly_once() {
        // Arrange: an empty cache with no file on disk yet.
        let directory = std::env::temp_dir().join(format!("iam-expander-{}", uuid::Uuid::new_v4()));
        let path = directory.join("actions.json");
        let mut cache = ActionCache {
            path: path.clone(),
            raw: RawCache {
                actions: HashMap::new(),
                fetched_at: None,
            },
            tries: HashMap::new(),
            fetched_all: false,
            dirty: false,
        };

        // Act: one fetch, then flush twice — the first flush must persist, the second
        // (nothing changed since) must be a no-op.
        cache
            .get_or_fetch_with("s3", || async {
                Ok(HashMap::from([(
                    "s3".to_string(),
                    vec!["GetObject".to_string()],
                )]))
            })
            .await
            .expect("service just fetched must be found");

        cache.flush().await.expect("first flush should persist");
        let content_after_first = tokio::fs::read_to_string(&path)
            .await
            .expect("cache file exists after first flush");
        let mtime_after_first = tokio::fs::metadata(&path)
            .await
            .expect("stat cache after first flush")
            .modified()
            .expect("cache has an mtime after first flush");

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        cache
            .flush()
            .await
            .expect("second flush should no-op, not error");

        // Assert: the second flush wrote nothing further.
        let content_after_second = tokio::fs::read_to_string(&path)
            .await
            .expect("cache file still readable after second flush");
        let mtime_after_second = tokio::fs::metadata(&path)
            .await
            .expect("stat cache after second flush")
            .modified()
            .expect("cache has an mtime after second flush");
        assert_eq!(
            content_after_first, content_after_second,
            "second flush must not rewrite content"
        );
        assert_eq!(
            mtime_after_first, mtime_after_second,
            "second flush must not touch the file — cache was clean"
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    // ── fixes for review feedback on the fetched_at freshness check ──────────────────────────

    #[test]
    fn parse_ttl_days_clamps_absurdly_large_value_instead_of_overflowing() {
        // i64::MAX days would panic inside `chrono::Duration::days` if it reached `is_fresh`
        // unclamped; it must take the invalid-value fallback path instead.
        assert_eq!(
            parse_ttl_days(Some(i64::MAX.to_string())),
            DEFAULT_CACHE_TTL_DAYS
        );
    }

    #[test]
    fn parse_ttl_days_accepts_max_boundary() {
        assert_eq!(
            parse_ttl_days(Some(MAX_CACHE_TTL_DAYS.to_string())),
            MAX_CACHE_TTL_DAYS
        );
    }

    #[test]
    fn is_fresh_does_not_panic_on_clamped_max_ttl() {
        let raw = raw_with(Some(Utc::now()), true);
        assert!(is_fresh(&raw, MAX_CACHE_TTL_DAYS));
    }

    #[test]
    fn is_fresh_false_when_fetched_at_is_in_the_future() {
        // Clock skew, a restored VM snapshot, or a hand-edited cache file can put `fetched_at`
        // ahead of `Utc::now()`. That must read as stale, not as fresh-forever.
        let raw = raw_with(Some(Utc::now() + chrono::Duration::days(1)), true);
        assert!(!is_fresh(&raw, 30));
    }
}
