use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{client, trie::Trie, ExpanderError};

/// Disk-backed cache of IAM action lists, keyed by service name.
///
/// Actions are stored as a flat JSON map so they can be read back without
/// network access.  The in-memory tries are rebuilt from that map on load.
pub struct ActionCache {
    path: PathBuf,
    raw: RawCache,
    tries: HashMap<String, Trie>,
    // ponytail: fetched_all resets every run even when the disk cache already
    // holds all services, so an unknown-service query re-fetches the full
    // catalog once per run. Gate on `!raw.actions.is_empty()` in `load` if
    // that per-run refetch shows up as real cost.
    fetched_all: bool,
}

#[derive(Default, Serialize, Deserialize)]
struct RawCache {
    actions: HashMap<String, Vec<String>>,
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
        Ok(Self {
            path,
            raw,
            tries,
            fetched_all: false,
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
        if !self.tries.contains_key(service) {
            if self.fetched_all {
                return Err(ExpanderError::UnknownService(service.to_string()));
            }
            let all = client::fetch_all_actions().await?;
            self.fetched_all = true;
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
            raw: RawCache { actions },
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
}
