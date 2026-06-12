mod cache;
mod client;
mod trie;

pub use cache::ActionCache;

use serde_json::Value;

/// Errors produced by the IAM expander.
#[derive(Debug, thiserror::Error)]
pub enum ExpanderError {
    #[error("network error querying awsiamactions.io: {0}")]
    Network(#[from] reqwest::Error),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unknown service: {0}")]
    UnknownService(String),
}

/// Expands all IAM actions for `service` that match `prefix`.
///
/// `prefix` filters action names (the part after the colon).
/// `None` returns every action for the service.
///
/// Example: `expand_actions("s3", Some("Get"))` → `["s3:GetObject", …]`
pub async fn expand_actions(
    service: &str,
    prefix: Option<&str>,
) -> Result<Vec<String>, ExpanderError> {
    let mut cache = ActionCache::load().await?;
    expand_actions_with_cache(service, prefix, &mut cache).await
}

/// Expands all wildcards in a JSON policy document.
///
/// Replaces patterns like `"s3:*"` or `"iam:Create*"` with their concrete
/// action names.  Statements without wildcards are left unchanged.
pub async fn expand_policy_document(policy_json: &str) -> Result<String, ExpanderError> {
    let mut policy: Value = serde_json::from_str(policy_json)?;
    let mut cache = ActionCache::load().await?;
    expand_statements(&mut policy, &mut cache).await?;
    Ok(serde_json::to_string_pretty(&policy)?)
}

// ── internal helpers ──────────────────────────────────────────────────────────

async fn expand_actions_with_cache(
    service: &str,
    prefix: Option<&str>,
    cache: &mut ActionCache,
) -> Result<Vec<String>, ExpanderError> {
    let trie = cache.get_or_fetch(service).await?;
    let search = format!("{}:{}", service, prefix.unwrap_or(""));
    Ok(trie.starts_with(&search))
}

async fn expand_statements(
    policy: &mut Value,
    cache: &mut ActionCache,
) -> Result<(), ExpanderError> {
    if let Some(Value::Array(stmts)) = policy.get_mut("Statement") {
        for stmt in stmts.iter_mut() {
            expand_one_statement(stmt, cache).await?;
        }
    }
    Ok(())
}

async fn expand_one_statement(
    stmt: &mut Value,
    cache: &mut ActionCache,
) -> Result<(), ExpanderError> {
    let raw_actions: Vec<String> = match stmt.get("Action") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => return Ok(()),
    };

    let mut expanded: Vec<String> = Vec::new();
    for action in raw_actions {
        expanded.extend(expand_one_action(&action, cache).await?);
    }

    stmt["Action"] = Value::Array(expanded.into_iter().map(Value::String).collect());
    Ok(())
}

async fn expand_one_action(
    action: &str,
    cache: &mut ActionCache,
) -> Result<Vec<String>, ExpanderError> {
    if !action.contains('*') {
        return Ok(vec![action.to_string()]);
    }

    if let Some(colon) = action.find(':') {
        let service = &action[..colon];
        let suffix = &action[colon + 1..];

        // Only expand trailing wildcards: "svc:*" or "svc:Prefix*"
        if suffix == "*" {
            return expand_actions_with_cache(service, None, cache).await;
        }
        if let Some(prefix) = suffix.strip_suffix('*') {
            return expand_actions_with_cache(service, Some(prefix), cache).await;
        }
    }

    // Wildcard in an unsupported position — return unchanged
    Ok(vec![action.to_string()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trie::Trie;

    fn make_cache_with(service: &str, actions: &[&str]) -> ActionCache {
        use std::collections::HashMap;

        let mut tries = HashMap::new();
        let mut trie = Trie::new();
        for a in actions {
            trie.insert(&format!("{service}:{a}"));
        }
        tries.insert(service.to_string(), trie);

        // Use a non-existent path so no disk I/O happens in tests
        ActionCache::from_parts(
            std::path::PathBuf::from("/tmp/test-cache-nonexistent.json"),
            tries,
        )
    }

    #[tokio::test]
    async fn test_expand_wildcard_all() {
        let mut cache = make_cache_with("s3", &["GetObject", "PutObject", "DeleteObject"]);
        let result = expand_actions_with_cache("s3", None, &mut cache)
            .await
            .expect("should expand");
        assert_eq!(result.len(), 3);
    }

    #[tokio::test]
    async fn test_expand_wildcard_prefix() {
        let mut cache = make_cache_with("s3", &["GetObject", "GetBucketAcl", "PutObject"]);
        let result = expand_actions_with_cache("s3", Some("Get"), &mut cache)
            .await
            .expect("should expand");
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|a| a.starts_with("s3:Get")));
    }

    #[tokio::test]
    async fn test_expand_policy_wildcards() {
        let policy = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:Get*", "s3:PutObject"],
                "Resource": "*"
            }]
        }"#;

        let mut cache = make_cache_with("s3", &["GetObject", "GetBucketAcl", "PutObject"]);
        let mut value: serde_json::Value = serde_json::from_str(policy).unwrap();
        expand_statements(&mut value, &mut cache).await.unwrap();

        let actions = value["Statement"][0]["Action"].as_array().unwrap();
        // "s3:Get*" → 2 actions; "s3:PutObject" stays as-is → total 3
        assert_eq!(actions.len(), 3);
    }
}
