use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{client, ExpanderError};

/// Disk-backed cache of IAM action lists, keyed by service name.
///
/// Actions are stored unqualified (e.g. `"GetObject"`, not `"s3:GetObject"`).
pub struct ActionCache {
    path: PathBuf,
    raw: RawCache,
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
        Ok(Self { path, raw })
    }

    /// Returns unqualified actions for `service`, fetching from the network when missing.
    ///
    /// No longer persists on every miss — call [`flush`] once at end of run.
    pub(crate) async fn get_or_fetch(&mut self, service: &str) -> Result<&[String], ExpanderError> {
        if !self.raw.actions.contains_key(service) {
            let actions = client::fetch_actions(service).await?;
            self.raw.actions.insert(service.to_string(), actions);
        }
        // safe: we just inserted it above if it was missing
        Ok(self
            .raw
            .actions
            .get(service)
            .expect("service was just inserted"))
    }

    /// Atomically persists the cache to disk.
    ///
    /// Writes to a `.tmp` file then renames so a crash during write leaves the
    /// previous cache file intact.  Call once at the end of a collection run.
    pub async fn flush(&self) -> Result<(), ExpanderError> {
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let tmp = self.path.with_extension("tmp");
        let json = serde_json::to_string_pretty(&self.raw)?;
        tokio::fs::write(&tmp, &json).await?;
        tokio::fs::rename(&tmp, &self.path).await?;
        Ok(())
    }

    /// Constructs an `ActionCache` directly from pre-seeded actions (test helper).
    #[cfg(test)]
    pub(crate) fn from_parts(path: PathBuf, actions: HashMap<String, Vec<String>>) -> Self {
        Self {
            path,
            raw: RawCache { actions },
        }
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
