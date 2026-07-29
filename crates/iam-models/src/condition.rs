//! Partial evaluator for IAM policy `Condition` blocks.
//!
//! Full condition evaluation is undecidable without runtime request context, so this
//! evaluates only a fixed, documented subset of deterministic keys against optional
//! query-supplied context. Everything else is surfaced as unevaluated rather than
//! silently treated as unconditional. See `docs/limitations.md`.

use crate::common::Condition;
use std::collections::HashMap;

/// Query-supplied context to evaluate condition keys against.
#[derive(Debug, Clone, Default)]
pub struct ConditionContext {
    pub region: Option<String>,
    pub mfa: Option<bool>,
    pub principal_tags: HashMap<String, String>,
}

/// Result of evaluating a `Condition` block against a [`ConditionContext`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionOutcome {
    /// No condition, or every key was evaluated and held true.
    Unconditional,
    /// At least one evaluable key evaluated false — the statement does not apply.
    Excluded,
    /// Every evaluable key held true, but one or more keys could not be evaluated.
    Conditional { unevaluated_keys: Vec<String> },
}

/// Evaluate `condition` against `ctx` using the supported subset of keys:
/// `aws:MultiFactorAuthPresent` (`Bool`), `aws:RequestedRegion`
/// (`StringEquals`/`StringLike`), and `aws:PrincipalTag/<key>`
/// (`StringEquals`/`StringLike`). Any other key or operator is unevaluated.
pub fn evaluate(condition: &Condition, ctx: &ConditionContext) -> ConditionOutcome {
    if condition.is_empty() {
        return ConditionOutcome::Unconditional;
    }

    let mut unevaluated_keys = Vec::new();

    for (operator, keys) in condition {
        for (key, values) in keys {
            match evaluate_key(operator, key, &values.0, ctx) {
                Some(true) => {}
                Some(false) => return ConditionOutcome::Excluded,
                None => unevaluated_keys.push(key.clone()),
            }
        }
    }

    if unevaluated_keys.is_empty() {
        ConditionOutcome::Unconditional
    } else {
        unevaluated_keys.sort();
        unevaluated_keys.dedup();
        ConditionOutcome::Conditional { unevaluated_keys }
    }
}

/// Evaluate a single condition key. `Some(bool)` = deterministic result;
/// `None` = unsupported key/operator or missing context value.
fn evaluate_key(
    operator: &str,
    key: &str,
    values: &[String],
    ctx: &ConditionContext,
) -> Option<bool> {
    let op = operator.to_lowercase();
    let key_lower = key.to_lowercase();

    if key_lower == "aws:multifactorauthpresent" {
        if op != "bool" {
            return None;
        }
        let mfa = ctx.mfa?;
        return Some(
            values
                .iter()
                .any(|v| v.eq_ignore_ascii_case(&mfa.to_string())),
        );
    }

    if key_lower == "aws:requestedregion" {
        if op != "stringequals" && op != "stringlike" {
            return None;
        }
        let region = ctx.region.as_deref()?;
        return Some(values.iter().any(|v| string_matches(&op, v, region)));
    }

    if let Some(tag_key) = key_lower.strip_prefix("aws:principaltag/") {
        if op != "stringequals" && op != "stringlike" {
            return None;
        }
        let tag_value = ctx
            .principal_tags
            .iter()
            .find(|(k, _)| k.to_lowercase() == tag_key)
            .map(|(_, v)| v.as_str())?;
        return Some(values.iter().any(|v| string_matches(&op, v, tag_value)));
    }

    None
}

/// Match `actual` against `pattern` per `op` (`stringequals` = exact, `stringlike` = glob).
fn string_matches(op: &str, pattern: &str, actual: &str) -> bool {
    if op == "stringlike" {
        glob_match(pattern, actual)
    } else {
        pattern == actual
    }
}

// Minimal `*`/`?` glob matcher. Structurally mirrors `iam_expander::glob_match`'s iterative
// two-pointer algorithm — not shared across the crate boundary because iam-models has zero
// dependencies by design (iam-expander and iam-models are dependency-graph siblings). Unlike
// the expander's version, this is deliberately case-sensitive: condition values matched here
// are region names, ARN segments, and tag values, which are case-sensitive in real AWS.
//
// Iterative rather than recursive: naive recursive backtracking on patterns like `"a*a*a*...b"`
// is exponential, and these patterns come directly from collected IAM policy documents (a
// `StringLike` condition value), so an adversarial or accidental pattern here would stall a
// `who_can` query. See the equivalent fix and its rationale in `iam_expander::glob_match`.
fn glob_match(pattern: &str, text: &str) -> bool {
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
            (Some((pc, p_next)), Some((tc, t_next))) if pc == '?' || pc == tc => {
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
    debug_assert!(
        s.is_char_boundary(idx),
        "char_at called at non-char-boundary index {idx} in {s:?}"
    );
    let c = s[idx..].chars().next()?;
    Some((c, idx + c.len_utf8()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::ConditionValues;

    fn condition_of(operator: &str, key: &str, values: &[&str]) -> Condition {
        let mut inner = HashMap::new();
        inner.insert(
            key.to_string(),
            ConditionValues(values.iter().map(|v| v.to_string()).collect()),
        );
        let mut outer = HashMap::new();
        outer.insert(operator.to_string(), inner);
        outer
    }

    #[test]
    fn evaluate_empty_condition_is_unconditional() {
        // Arrange
        let condition: Condition = HashMap::new();
        let ctx = ConditionContext::default();

        // Act
        let outcome = evaluate(&condition, &ctx);

        // Assert
        assert_eq!(outcome, ConditionOutcome::Unconditional);
    }

    #[test]
    fn evaluate_mfa_present_true_context_matches_is_unconditional() {
        // Arrange
        let condition = condition_of("Bool", "aws:MultiFactorAuthPresent", &["true"]);
        let ctx = ConditionContext {
            mfa: Some(true),
            ..Default::default()
        };

        // Act
        let outcome = evaluate(&condition, &ctx);

        // Assert
        assert_eq!(outcome, ConditionOutcome::Unconditional);
    }

    #[test]
    fn evaluate_mfa_present_true_context_mismatch_is_excluded() {
        // Arrange
        let condition = condition_of("Bool", "aws:MultiFactorAuthPresent", &["true"]);
        let ctx = ConditionContext {
            mfa: Some(false),
            ..Default::default()
        };

        // Act
        let outcome = evaluate(&condition, &ctx);

        // Assert
        assert_eq!(outcome, ConditionOutcome::Excluded);
    }

    #[test]
    fn evaluate_mfa_present_no_context_is_conditional() {
        // Arrange
        let condition = condition_of("Bool", "aws:MultiFactorAuthPresent", &["true"]);
        let ctx = ConditionContext::default();

        // Act
        let outcome = evaluate(&condition, &ctx);

        // Assert
        assert_eq!(
            outcome,
            ConditionOutcome::Conditional {
                unevaluated_keys: vec!["aws:MultiFactorAuthPresent".to_string()]
            }
        );
    }

    #[test]
    fn evaluate_requested_region_string_equals_match_is_unconditional() {
        // Arrange
        let condition = condition_of("StringEquals", "aws:RequestedRegion", &["us-east-1"]);
        let ctx = ConditionContext {
            region: Some("us-east-1".to_string()),
            ..Default::default()
        };

        // Act
        let outcome = evaluate(&condition, &ctx);

        // Assert
        assert_eq!(outcome, ConditionOutcome::Unconditional);
    }

    #[test]
    fn evaluate_requested_region_mismatch_is_excluded() {
        // Arrange
        let condition = condition_of("StringEquals", "aws:RequestedRegion", &["us-east-1"]);
        let ctx = ConditionContext {
            region: Some("eu-west-1".to_string()),
            ..Default::default()
        };

        // Act
        let outcome = evaluate(&condition, &ctx);

        // Assert
        assert_eq!(outcome, ConditionOutcome::Excluded);
    }

    #[test]
    fn evaluate_requested_region_string_like_glob_matches() {
        // Arrange
        let condition = condition_of("StringLike", "aws:RequestedRegion", &["us-*"]);
        let ctx = ConditionContext {
            region: Some("us-west-2".to_string()),
            ..Default::default()
        };

        // Act
        let outcome = evaluate(&condition, &ctx);

        // Assert
        assert_eq!(outcome, ConditionOutcome::Unconditional);
    }

    #[test]
    fn evaluate_requested_region_no_context_is_conditional() {
        // Arrange
        let condition = condition_of("StringEquals", "aws:RequestedRegion", &["us-east-1"]);
        let ctx = ConditionContext::default();

        // Act
        let outcome = evaluate(&condition, &ctx);

        // Assert
        assert_eq!(
            outcome,
            ConditionOutcome::Conditional {
                unevaluated_keys: vec!["aws:RequestedRegion".to_string()]
            }
        );
    }

    #[test]
    fn evaluate_principal_tag_match_is_unconditional() {
        // Arrange
        let condition = condition_of("StringEquals", "aws:PrincipalTag/team", &["platform"]);
        let mut principal_tags = HashMap::new();
        principal_tags.insert("team".to_string(), "platform".to_string());
        let ctx = ConditionContext {
            principal_tags,
            ..Default::default()
        };

        // Act
        let outcome = evaluate(&condition, &ctx);

        // Assert
        assert_eq!(outcome, ConditionOutcome::Unconditional);
    }

    #[test]
    fn evaluate_principal_tag_mismatch_is_excluded() {
        // Arrange
        let condition = condition_of("StringEquals", "aws:PrincipalTag/team", &["platform"]);
        let mut principal_tags = HashMap::new();
        principal_tags.insert("team".to_string(), "security".to_string());
        let ctx = ConditionContext {
            principal_tags,
            ..Default::default()
        };

        // Act
        let outcome = evaluate(&condition, &ctx);

        // Assert
        assert_eq!(outcome, ConditionOutcome::Excluded);
    }

    #[test]
    fn evaluate_principal_tag_no_context_is_conditional() {
        // Arrange
        let condition = condition_of("StringEquals", "aws:PrincipalTag/team", &["platform"]);
        let ctx = ConditionContext::default();

        // Act
        let outcome = evaluate(&condition, &ctx);

        // Assert
        assert_eq!(
            outcome,
            ConditionOutcome::Conditional {
                unevaluated_keys: vec!["aws:PrincipalTag/team".to_string()]
            }
        );
    }

    #[test]
    fn evaluate_unsupported_key_is_conditional() {
        // Arrange
        let condition = condition_of("StringEquals", "s3:prefix", &["reports/"]);
        let ctx = ConditionContext::default();

        // Act
        let outcome = evaluate(&condition, &ctx);

        // Assert
        assert_eq!(
            outcome,
            ConditionOutcome::Conditional {
                unevaluated_keys: vec!["s3:prefix".to_string()]
            }
        );
    }

    #[test]
    fn evaluate_unsupported_operator_on_supported_key_is_conditional() {
        // Arrange
        let condition = condition_of("NumericLessThan", "aws:MultiFactorAuthPresent", &["1"]);
        let ctx = ConditionContext {
            mfa: Some(true),
            ..Default::default()
        };

        // Act
        let outcome = evaluate(&condition, &ctx);

        // Assert
        assert_eq!(
            outcome,
            ConditionOutcome::Conditional {
                unevaluated_keys: vec!["aws:MultiFactorAuthPresent".to_string()]
            }
        );
    }

    #[test]
    fn evaluate_mixed_evaluable_true_and_unevaluated_is_conditional() {
        // Arrange
        let mut inner = HashMap::new();
        inner.insert(
            "aws:MultiFactorAuthPresent".to_string(),
            ConditionValues(vec!["true".to_string()]),
        );
        let mut outer: Condition = HashMap::new();
        outer.insert("Bool".to_string(), inner);
        let mut inner2 = HashMap::new();
        inner2.insert(
            "s3:prefix".to_string(),
            ConditionValues(vec!["reports/".to_string()]),
        );
        outer.insert("StringEquals".to_string(), inner2);
        let ctx = ConditionContext {
            mfa: Some(true),
            ..Default::default()
        };

        // Act
        let outcome = evaluate(&outer, &ctx);

        // Assert
        assert_eq!(
            outcome,
            ConditionOutcome::Conditional {
                unevaluated_keys: vec!["s3:prefix".to_string()]
            }
        );
    }

    // ── glob_match: iterative rewrite (issue #79 follow-up) ──────────────────

    /// The old naive recursive/backtracking matcher, kept only as a reference implementation
    /// to prove the new iterative matcher is bit-identical to it. Case-sensitive, matching
    /// the original (this module never lowercased).
    fn glob_match_reference(pattern: &str, text: &str) -> bool {
        fn inner(p: &[char], t: &[char]) -> bool {
            match (p.first(), t.first()) {
                (None, None) => true,
                (None, Some(_)) => false,
                (Some('*'), _) => inner(&p[1..], t) || (!t.is_empty() && inner(p, &t[1..])),
                (Some('?'), Some(_)) => inner(&p[1..], &t[1..]),
                (Some(pc), Some(tc)) if pc == tc => inner(&p[1..], &t[1..]),
                _ => false,
            }
        }
        let p: Vec<char> = pattern.chars().collect();
        let t: Vec<char> = text.chars().collect();
        inner(&p, &t)
    }

    /// Generates every string of length `0..=max_len` over `alphabet`.
    fn generate_corpus(alphabet: &[char], max_len: usize) -> Vec<String> {
        let mut all = vec![String::new()];
        let mut cur = vec![String::new()];
        for _ in 0..max_len {
            cur = cur
                .iter()
                .flat_map(|s| alphabet.iter().map(move |c| format!("{s}{c}")))
                .collect();
            all.extend(cur.iter().cloned());
        }
        all
    }

    #[test]
    fn glob_match_matches_reference_exhaustively() {
        let patterns = generate_corpus(&['a', 'B', '*', '?'], 4);
        let texts = generate_corpus(&['a', 'A', 'é'], 3);
        let mut checked = 0usize;
        for pattern in &patterns {
            for text in &texts {
                assert_eq!(
                    glob_match(pattern, text),
                    glob_match_reference(pattern, text),
                    "mismatch for pattern={pattern:?} text={text:?}"
                );
                checked += 1;
            }
        }
        assert!(checked > 10_000, "sanity check on corpus size: {checked}");
    }

    #[test]
    fn glob_match_is_case_sensitive() {
        // Unlike iam-expander's action matcher, this one must NOT fold case.
        assert!(glob_match("us-*", "us-west-2"));
        assert!(!glob_match("US-*", "us-west-2"));
        assert!(!glob_match("us-*", "US-WEST-2"));
    }

    #[test]
    fn glob_match_pathological_backtracking_pattern_stays_fast() {
        // This exact pattern shape reaches glob_match through a collected policy's
        // `"StringLike": {"aws:RequestedRegion": "a*a*a*...b"}` condition value — the naive
        // recursive matcher this replaces took ~5s at n=14 on this shape (see PR #126 review).
        let pattern = "a*".repeat(50) + "b";
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
}
