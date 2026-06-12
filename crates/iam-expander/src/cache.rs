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
        Ok(Self { path, raw, tries })
    }

    /// Returns the trie for `service`, fetching from the network when missing.
    pub(crate) async fn get_or_fetch(&mut self, service: &str) -> Result<&Trie, ExpanderError> {
        if !self.tries.contains_key(service) {
            let actions = client::fetch_actions(service).await?;
            let mut trie = Trie::new();
            for action in &actions {
                trie.insert(&format!("{service}:{action}"));
            }
            self.raw.actions.insert(service.to_string(), actions);
            self.tries.insert(service.to_string(), trie);
            self.persist().await?;
        }
        // safe: we just inserted it above if it was missing
        Ok(self.tries.get(service).expect("service was just inserted"))
    }

    async fn persist(&self) -> Result<(), ExpanderError> {
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let json = serde_json::to_string_pretty(&self.raw)?;
        tokio::fs::write(&self.path, json).await?;
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
