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
    let result = expand_actions_with_cache(service, prefix, &mut cache).await?;
    cache.flush().await?;
    Ok(result)
}

/// Expands all wildcards in a JSON policy document.
///
/// Replaces patterns like `"s3:*"` or `"iam:Create*"` with their concrete
/// action names.  Statements without wildcards are left unchanged.
///
/// Loads a fresh [`ActionCache`] on every call.  When expanding many documents
/// in a single run, prefer [`expand_policy_document_with_cache`] to share one
/// cache load across all calls.
pub async fn expand_policy_document(policy_json: &str) -> Result<String, ExpanderError> {
    let mut cache = ActionCache::load().await?;
    let result = expand_policy_document_with_cache(policy_json, &mut cache).await?;
    cache.flush().await?;
    Ok(result)
}

/// Expands all wildcards in a JSON policy document using a caller-provided cache.
///
/// Use this to share a single [`ActionCache`] across many documents in one run:
/// call [`ActionCache::load`] once, pass `&mut cache` to each document, then
/// call [`ActionCache::flush`] once at the end.
pub async fn expand_policy_document_with_cache(
    policy_json: &str,
    cache: &mut ActionCache,
) -> Result<String, ExpanderError> {
    let mut policy: Value = serde_json::from_str(policy_json)?;
    expand_statements(&mut policy, cache).await?;
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
    expand_action_list(stmt, "Action", cache).await?;
    expand_action_list(stmt, "NotAction", cache).await?;
    Ok(())
}

async fn expand_action_list(
    stmt: &mut Value,
    key: &str,
    cache: &mut ActionCache,
) -> Result<(), ExpanderError> {
    let raw_actions: Vec<String> = match stmt.get(key) {
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

    stmt[key] = Value::Array(expanded.into_iter().map(Value::String).collect());
    Ok(())
}

async fn expand_one_action(
    action: &str,
    cache: &mut ActionCache,
) -> Result<Vec<String>, ExpanderError> {
    if !action.contains('*') && !action.contains('?') {
        return Ok(vec![action.to_string()]);
    }

    let Some(colon) = action.find(':') else {
        // No colon — wildcard in service position, not expandable
        return Ok(vec![action.to_string()]);
    };

    let service = &action[..colon];

    // Wildcard in service position (e.g. "*:Describe*") — not expandable.
    // Callers should treat these as literal action strings.
    if service.contains('*') || service.contains('?') {
        return Ok(vec![action.to_string()]);
    }

    let suffix = &action[colon + 1..];

    // Fast path: "svc:*" — return all actions for this service
    if suffix == "*" {
        return expand_actions_with_cache(service, None, cache).await;
    }

    // Fast path: "svc:Prefix*" — single trailing wildcard, no other wildcards
    if suffix.ends_with('*') && !suffix[..suffix.len() - 1].contains(['*', '?']) {
        let prefix = &suffix[..suffix.len() - 1];
        return expand_actions_with_cache(service, Some(prefix), cache).await;
    }

    // General case: interior or multi-position wildcards (e.g. "s3:*Object", "iam:*Group*").
    // Fetch all actions for the service and filter with IAM glob semantics.
    let all = expand_actions_with_cache(service, None, cache).await?;
    Ok(all
        .into_iter()
        .filter(|a| {
            let a_suffix = a.split_once(':').map(|(_, s)| s).unwrap_or("");
            glob_match(suffix, a_suffix)
        })
        .collect())
}

/// IAM wildcard match: `*` matches any sequence of characters, `?` matches one character.
/// Matching is case-insensitive, consistent with AWS IAM policy evaluation.
///
/// `pattern` is the (possibly wildcarded) action string, e.g. a Deny statement's action;
/// `text` is the concrete action being tested against it.
///
/// Allocation-free: walks both strings by decoded `char` (not raw byte, so a multi-byte
/// `?` match consumes a whole codepoint, not a partial one) and compares case-insensitively
/// per-char via `char::eq_ignore_ascii_case`, which — like the `str::to_ascii_lowercase` this
/// replaced — only folds ASCII, leaving other codepoints unchanged. Uses the standard
/// iterative two-pointer wildcard algorithm rather than naive recursive backtracking, which
/// is exponential on adversarial patterns like `"a*a*a*...b"`.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let mut pi = 0usize;
    let mut ti = 0usize;
    // Last '*' seen: (pattern position just after it, text position to resume matching from).
    let mut star: Option<(usize, usize)> = None;

    loop {
        let p_char = char_at(pattern, pi);
        let t_char = char_at(text, ti);

        match (p_char, t_char) {
            (Some(('*', p_next)), _) => {
                star = Some((p_next, ti));
                pi = p_next;
            }
            (Some((pc, p_next)), Some((tc, t_next)))
                if pc == '?' || pc.eq_ignore_ascii_case(&tc) =>
            {
                pi = p_next;
                ti = t_next;
            }
            _ => {
                if p_char.is_none() && t_char.is_none() {
                    return true;
                }
                let Some((star_pi, star_ti)) = star else {
                    return false;
                };
                let Some((_, t_next)) = char_at(text, star_ti) else {
                    return false;
                };
                star = Some((star_pi, t_next));
                pi = star_pi;
                ti = t_next;
            }
        }
    }
}

/// Decodes the leading char at byte offset `idx` in `s`, returning it along with the byte
/// offset of the char that follows. `None` when `idx` is at or past the end of `s`.
fn char_at(s: &str, idx: usize) -> Option<(char, usize)> {
    let c = s[idx..].chars().next()?;
    Some((c, idx + c.len_utf8()))
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
    async fn expand_one_action_suffix_wildcard_s3_object() {
        let mut cache = make_cache_with(
            "s3",
            &[
                "GetObject",
                "PutObject",
                "DeleteObject",
                "CopyObject",
                "GetBucketAcl",
            ],
        );
        let result = expand_one_action("s3:*Object", &mut cache)
            .await
            .expect("should expand");
        assert!(result.contains(&"s3:GetObject".to_string()));
        assert!(result.contains(&"s3:PutObject".to_string()));
        assert!(result.contains(&"s3:DeleteObject".to_string()));
        assert!(result.contains(&"s3:CopyObject".to_string()));
        assert!(!result.contains(&"s3:GetBucketAcl".to_string()));
    }

    #[tokio::test]
    async fn expand_one_action_interior_wildcard_iam_group() {
        let mut cache = make_cache_with(
            "iam",
            &["CreateGroup", "DeleteGroup", "ListGroups", "CreateUser"],
        );
        let result = expand_one_action("iam:*Group", &mut cache)
            .await
            .expect("should expand");
        assert!(result.contains(&"iam:CreateGroup".to_string()));
        assert!(result.contains(&"iam:DeleteGroup".to_string()));
        assert!(!result.contains(&"iam:ListGroups".to_string())); // ends with 's'
        assert!(!result.contains(&"iam:CreateUser".to_string()));
    }

    #[tokio::test]
    async fn expand_one_action_literal_unchanged() {
        let mut cache = make_cache_with("s3", &["GetObject"]);
        let result = expand_one_action("s3:GetObject", &mut cache)
            .await
            .expect("should pass through");
        assert_eq!(result, vec!["s3:GetObject".to_string()]);
    }

    #[tokio::test]
    async fn expand_one_action_wildcard_service_position_unchanged() {
        let mut cache = make_cache_with("s3", &["GetObject"]);
        let result = expand_one_action("*:GetObject", &mut cache)
            .await
            .expect("should return unchanged");
        assert_eq!(result, vec!["*:GetObject".to_string()]);
    }

    #[tokio::test]
    async fn expand_one_action_question_mark_wildcard() {
        let mut cache = make_cache_with("s3", &["GetObject", "PutObject", "GetObjects"]);
        let result = expand_one_action("s3:?etObject", &mut cache)
            .await
            .expect("should expand");
        // '?' at position 0 matches 'G', then "etObject" matches — GetObject matches
        assert!(result.contains(&"s3:GetObject".to_string()));
        // 'P' matches '?' but 'u' ≠ 'e' — PutObject does not match
        assert!(!result.contains(&"s3:PutObject".to_string()));
        // GetObjects has one extra char — length mismatch, does not match
        assert!(!result.contains(&"s3:GetObjects".to_string()));
    }

    #[tokio::test]
    async fn expand_one_action_all_star() {
        let mut cache = make_cache_with("ec2", &["DescribeInstances", "DescribeVpcs", "CreateVpc"]);
        let result = expand_one_action("ec2:*", &mut cache)
            .await
            .expect("should expand all");
        assert_eq!(result.len(), 3);
    }

    #[tokio::test]
    async fn expand_one_action_prefix_star() {
        let mut cache = make_cache_with("ec2", &["DescribeInstances", "DescribeVpcs", "CreateVpc"]);
        let result = expand_one_action("ec2:Describe*", &mut cache)
            .await
            .expect("should expand prefix");
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|a| a.starts_with("ec2:Describe")));
    }

    #[tokio::test]
    async fn expand_not_action_wildcard_expands_to_concrete_list() {
        let mut cache = make_cache_with(
            "s3",
            &["GetObject", "PutObject", "DeleteObject", "ListBuckets"],
        );
        let mut stmt: serde_json::Value = serde_json::json!({
            "Effect": "Allow",
            "NotAction": ["s3:*"],
            "Resource": "*"
        });

        // Act
        expand_one_statement(&mut stmt, &mut cache)
            .await
            .expect("should expand");

        // Assert — NotAction is now a concrete wildcard-free list
        let not_actions = stmt["NotAction"].as_array().expect("must be array");
        assert!(
            not_actions.iter().all(|v| {
                let s = v.as_str().unwrap_or("");
                !s.contains('*') && !s.contains('?')
            }),
            "NotAction must be wildcard-free after expansion"
        );
        assert!(not_actions.len() >= 4, "all s3 actions must be present");
        // Action key absent → must remain absent
        assert!(stmt.get("Action").is_none());
    }

    #[tokio::test]
    async fn expand_not_action_absent_statement_unchanged() {
        let mut cache = make_cache_with("s3", &["GetObject"]);
        let mut stmt: serde_json::Value = serde_json::json!({
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "*"
        });

        expand_one_statement(&mut stmt, &mut cache)
            .await
            .expect("should succeed");

        assert!(
            stmt.get("NotAction").is_none(),
            "no NotAction must be added"
        );
        let actions = stmt["Action"].as_array().expect("Action must remain");
        assert_eq!(actions.len(), 1);
    }

    /// Confirms that expanding N documents with a shared cache performs no additional
    /// cache loads.  `expand_policy_document_with_cache` never calls `ActionCache::load`;
    /// the caller supplies the cache, so N documents share a single loaded instance.
    #[tokio::test]
    async fn expand_n_documents_with_shared_cache_no_extra_loads() {
        let mut cache = make_cache_with("s3", &["GetObject", "PutObject", "DeleteObject"]);

        let policy_json = r#"{
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:Get*"], "Resource": "*"}]
        }"#;

        // Expand 10 documents using the same cache; no disk or network I/O occurs
        // because the cache was injected pre-seeded (from_parts uses a nonexistent path).
        for _ in 0..10 {
            let result = expand_policy_document_with_cache(policy_json, &mut cache)
                .await
                .expect("should expand without error");

            let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
            let actions = parsed["Statement"][0]["Action"].as_array().unwrap();
            assert_eq!(
                actions.len(),
                1,
                "s3:Get* should expand to s3:GetObject only"
            );
            assert_eq!(actions[0].as_str().unwrap(), "s3:GetObject");
        }
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

    // ── glob_match: allocation-free rewrite (issue #79) ──────────────────────

    /// The old naive recursive/backtracking matcher, kept here only as a reference
    /// implementation to prove the new iterative matcher is bit-identical to it.
    fn glob_match_reference(pattern: &str, text: &str) -> bool {
        fn inner(p: &[char], t: &[char]) -> bool {
            match (p.first(), t.first()) {
                (None, None) => true,
                (Some('*'), _) => inner(&p[1..], t) || (!t.is_empty() && inner(p, &t[1..])),
                (Some('?'), Some(_)) => inner(&p[1..], &t[1..]),
                (Some(pc), Some(tc)) if pc == tc => inner(&p[1..], &t[1..]),
                _ => false,
            }
        }
        let p: Vec<char> = pattern.to_ascii_lowercase().chars().collect();
        let t: Vec<char> = text.to_ascii_lowercase().chars().collect();
        inner(&p, &t)
    }

    /// Corpus of (pattern, text) pairs covering ASCII, non-ASCII multi-byte chars
    /// (including `?`/`*` adjacent to them), empty strings, `*`-only patterns, and
    /// case folding. The new matcher must agree with the reference on every case.
    fn equivalence_corpus() -> Vec<(&'static str, &'static str)> {
        vec![
            ("s3:*", "s3:GetObject"),
            ("s3:Get*", "s3:GetObject"),
            ("s3:Get*", "s3:PutObject"),
            ("iam:*Group", "iam:CreateGroup"),
            ("iam:*Group", "iam:ListGroups"),
            ("s3:?etObject", "s3:GetObject"),
            ("s3:?etObject", "s3:PutObject"),
            ("*", ""),
            ("*", "anything"),
            ("", ""),
            ("", "x"),
            ("x", ""),
            ("SVC:ACTION", "svc:action"),
            ("s3:Café*", "s3:CaféObject"),
            ("s3:Caf?", "s3:Café"),
            ("s3:???", "s3:日本語"),
            ("s3:?", "s3:日"),
            ("*.txt", "héllo.txt"),
            ("**", "anything"),
            ("a*b*c", "aXbYc"),
            ("a*b*c", "aXbYd"),
        ]
    }

    #[test]
    fn glob_match_matches_reference_implementation_on_corpus() {
        for (pattern, text) in equivalence_corpus() {
            assert_eq!(
                glob_match(pattern, text),
                glob_match_reference(pattern, text),
                "mismatch for pattern={pattern:?} text={text:?}"
            );
        }
    }

    #[test]
    fn glob_match_question_mark_consumes_whole_multibyte_char() {
        // '?' must match one whole Unicode scalar value, not one UTF-8 byte.
        assert!(glob_match("s3:Caf?", "s3:Café"));
        assert!(glob_match("s3:???", "s3:日本語"));
        assert!(!glob_match("s3:??", "s3:日本語")); // wrong char count
    }

    #[test]
    fn glob_match_star_only_matches_everything_including_empty() {
        assert!(glob_match("*", ""));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("**", "anything"));
    }

    #[test]
    fn glob_match_empty_pattern_only_matches_empty_text() {
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
    }

    #[test]
    fn glob_match_pathological_backtracking_pattern_stays_fast() {
        // The old naive recursive matcher was exponential on this shape of pattern
        // (measured ~1.5s at n=15); the iterative two-pointer matcher must stay well
        // under a second even at a much larger n.
        let pattern = "a*".repeat(50) + "b"; // no trailing 'b' in text -> forces backtracking
        let text = "a".repeat(200);

        let start = std::time::Instant::now();
        let result = glob_match(&pattern, &text);
        let elapsed = start.elapsed();

        assert!(
            !result,
            "pattern requires a trailing 'b' the text doesn't have"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(100),
            "glob_match took {elapsed:?} on a pathological pattern; expected microseconds"
        );
    }

    /// Micro-benchmark: matches ~5k candidate actions against one queried action, timing
    /// both the new allocation-free matcher and the old (`glob_match_reference`) matcher
    /// for a before/after comparison. Not run in default CI (see CLAUDE.md test commands);
    /// run manually with:
    /// `cargo test -p iam-expander --release -- --ignored bench_glob_match --nocapture`
    #[test]
    #[ignore = "manual micro-benchmark, not part of default CI"]
    fn bench_glob_match_bulk_workload() {
        let candidates: Vec<String> = (0..5000).map(|i| format!("s3:Action{i}Get")).collect();
        let queried = "s3:Action2500Get";

        let start = std::time::Instant::now();
        let matches = candidates.iter().filter(|c| glob_match(c, queried)).count();
        let new_elapsed = start.elapsed();

        let start = std::time::Instant::now();
        let ref_matches = candidates
            .iter()
            .filter(|c| glob_match_reference(c, queried))
            .count();
        let old_elapsed = start.elapsed();

        assert_eq!(matches, ref_matches);
        println!(
            "bench_glob_match_bulk_workload: {} candidates, {matches} matches — new (allocation-free): {new_elapsed:?}, old (Vec<char> alloc): {old_elapsed:?}",
            candidates.len()
        );
    }
}
