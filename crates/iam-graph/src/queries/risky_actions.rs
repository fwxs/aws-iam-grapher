//! User-configurable privilege-escalation technique groups, loaded from a YAML config
//! at runtime (issue #190). Replaces the previously hardcoded 9-action list.
//!
//! Match semantics: **AND within a group, OR across groups** — an entity is reported
//! only if it holds every action in at least one group.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// One named privilege-escalation technique: an entity must hold every action in
/// `actions` (AND) for this group to match. Across groups, OR applies — see
/// [`RiskyActionGroups::finalize_actions`].
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RiskyActionGroup {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub actions: Vec<String>,
}

/// A validated, non-empty set of [`RiskyActionGroup`]s. Construction (`from_yaml`,
/// `load`, `resolve`) is the only way to get one — by the time a caller holds a
/// `RiskyActionGroups`, all validation checks have already passed.
#[derive(Debug, Clone)]
pub struct RiskyActionGroups {
    groups: Vec<RiskyActionGroup>,
}

/// Errors from parsing/validating a risky-actions YAML config, or resolving its path.
/// Deliberately not a [`crate::GraphError`] variant — this is a config-loading concern,
/// not a graph/query-execution one.
#[derive(Debug, thiserror::Error)]
pub enum RiskyActionsError {
    #[error("failed to read risky-actions config at {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse risky-actions config at {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_norway::Error,
    },

    #[error("no risky-action groups defined (empty config)")]
    NoGroups,

    #[error("duplicate group name `{0}`")]
    DuplicateGroupName(String),

    #[error(
        "group `{0}`: actions list is empty (an empty group would vacuously match every entity)"
    )]
    EmptyActions(String),

    #[error(
        "group `{group}`: invalid action `{action}` \
         (wildcards are not supported; use an exact `service:Action`)"
    )]
    InvalidAction { group: String, action: String },

    #[error(
        "no risky-actions config found at\n         {path}\n       \
         Install it with scripts/install.sh, or pass --risky-actions <path>."
    )]
    NotFound { path: String },

    #[error("cannot resolve default risky-actions config path: $HOME is not set")]
    NoHome,
}

impl RiskyActionGroups {
    /// Parse and fully validate YAML text, returning every problem found (not just the
    /// first) — used by `config check`.
    pub fn from_yaml(text: &str) -> Result<Self, Vec<RiskyActionsError>> {
        let groups: Vec<RiskyActionGroup> = serde_norway::from_str(text).map_err(|source| {
            vec![RiskyActionsError::Parse {
                path: "<input>".to_string(),
                source,
            }]
        })?;

        let errors = Self::validate(&groups);
        if errors.is_empty() {
            Ok(Self { groups })
        } else {
            Err(errors)
        }
    }

    /// Load from a file path, surfacing only the first validation problem — used by the
    /// actual query path. `config check` uses [`Self::from_yaml`] directly to report
    /// every problem instead.
    pub fn load(path: &Path) -> Result<Self, RiskyActionsError> {
        let text = std::fs::read_to_string(path).map_err(|source| RiskyActionsError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_yaml(&text).map_err(|mut errors| {
            // load() surfaces one error; from_yaml's Parse variant is the only error that
            // can precede a successful validate() call, and Parse never omits `path` — but
            // Parse builds with a placeholder path, so fill in the real one here.
            let mut first = errors.remove(0);
            if let RiskyActionsError::Parse { path: p, .. } = &mut first {
                *p = path.display().to_string();
            }
            first
        })
    }

    /// Resolve and load per the two-step path-resolution rule: `explicit` (fatal if
    /// missing) else `~/.aws-iam-grapher/config/risky-actions.yaml` (fatal if missing,
    /// fatal if `home` is `None`). `home` is injected rather than read from
    /// `std::env::var` internally, so tests never mutate process-global `$HOME` and stay
    /// parallel-safe. Deliberately no repo-checkout fallback — see issue #190.
    pub fn resolve(
        explicit: Option<&Path>,
        home: Option<&Path>,
    ) -> Result<Self, RiskyActionsError> {
        let path: PathBuf = match explicit {
            Some(p) => p.to_path_buf(),
            None => {
                let home = home.ok_or(RiskyActionsError::NoHome)?;
                home.join(".aws-iam-grapher/config/risky-actions.yaml")
            }
        };
        if !path.is_file() {
            return Err(RiskyActionsError::NotFound {
                path: path.display().to_string(),
            });
        }
        Self::load(&path)
    }

    fn validate(groups: &[RiskyActionGroup]) -> Vec<RiskyActionsError> {
        let mut errors = Vec::new();
        if groups.is_empty() {
            errors.push(RiskyActionsError::NoGroups);
        }

        let mut seen_names = HashSet::new();
        for group in groups {
            if !seen_names.insert(group.name.as_str()) {
                errors.push(RiskyActionsError::DuplicateGroupName(group.name.clone()));
            }
            if group.actions.is_empty() {
                errors.push(RiskyActionsError::EmptyActions(group.name.clone()));
            }
            for action in &group.actions {
                if action.is_empty() || !action.contains(':') || action.contains('*') {
                    errors.push(RiskyActionsError::InvalidAction {
                        group: group.name.clone(),
                        action: action.clone(),
                    });
                }
            }
        }
        errors
    }

    /// Flat, deduplicated union of every action across every group — the value bound to
    /// Cypher's `$risky_actions` parameter, used only to filter which `Permission` nodes
    /// are pulled back as `allowed_actions`. AND/OR group semantics are not expressible
    /// in Cypher; they're evaluated in Rust by [`Self::finalize_actions`].
    pub fn all_actions(&self) -> Vec<String> {
        self.groups
            .iter()
            .flat_map(|g| g.actions.iter().cloned())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn groups(&self) -> &[RiskyActionGroup] {
        &self.groups
    }

    /// Evaluate AND-within-group/OR-across-group escalation semantics against one
    /// entity's actions.
    ///
    /// `allowed_post_deny` MUST already have had Deny actions subtracted (via
    /// `iam_expander::glob_match` against the entity's `deny_actions` — the existing
    /// per-entity suppression step in `escalation.rs`/`org_escalation.rs`) — never call
    /// this with the raw `Permission` Allow set. Evaluating group AND-matching before
    /// Deny subtraction would let a group falsely "match" on an action actually
    /// suppressed by an explicit Deny — a false positive on a security query.
    ///
    /// Returns `None` if no group's action set is fully satisfied (drop the entity from
    /// results). Returns `Some((risky_actions, matched_paths))` where `risky_actions` is
    /// the deduplicated, sorted union of actions belonging to every matched group, and
    /// `matched_paths` is the sorted list of matched group names.
    pub fn finalize_actions(
        &self,
        allowed_post_deny: &[String],
    ) -> Option<(Vec<String>, Vec<String>)> {
        let allowed: HashSet<&str> = allowed_post_deny.iter().map(String::as_str).collect();

        let mut matched_names = Vec::new();
        let mut matched_actions = HashSet::new();
        for group in &self.groups {
            if group.actions.iter().all(|a| allowed.contains(a.as_str())) {
                matched_names.push(group.name.clone());
                matched_actions.extend(group.actions.iter().cloned());
            }
        }

        if matched_names.is_empty() {
            return None;
        }

        matched_names.sort();
        let mut risky_actions: Vec<String> = matched_actions.into_iter().collect();
        risky_actions.sort();
        Some((risky_actions, matched_names))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn group(name: &str, actions: &[&str]) -> String {
        let actions_yaml = actions
            .iter()
            .map(|a| format!("    - {a}"))
            .collect::<Vec<_>>()
            .join("\n");
        format!("- name: {name}\n  description: test\n  actions:\n{actions_yaml}\n")
    }

    #[test]
    fn from_yaml_shipped_config_all_actions_equals_the_nine_legacy_actions() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let path = Path::new(manifest_dir)
            .join("../..")
            .join("config/risky-actions.yaml");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));

        let groups = RiskyActionGroups::from_yaml(&text).expect("shipped config must be valid");

        let mut actions = groups.all_actions();
        actions.sort();
        let mut expected = vec![
            "iam:CreatePolicyVersion".to_string(),
            "iam:SetDefaultPolicyVersion".to_string(),
            "iam:AttachRolePolicy".to_string(),
            "iam:AttachUserPolicy".to_string(),
            "iam:PassRole".to_string(),
            "iam:PutRolePolicy".to_string(),
            "iam:PutUserPolicy".to_string(),
            "iam:CreateAccessKey".to_string(),
            "iam:CreateLoginProfile".to_string(),
        ];
        expected.sort();

        assert_eq!(actions, expected);
        assert_eq!(groups.groups().len(), 9);
    }

    #[test]
    fn from_yaml_duplicate_group_name_returns_duplicate_group_error() {
        let yaml = format!(
            "{}{}",
            group("dup", &["iam:PassRole"]),
            group("dup", &["iam:CreateAccessKey"])
        );

        let result = RiskyActionGroups::from_yaml(&yaml);

        let errors = result.expect_err("duplicate names must be rejected");
        assert!(errors
            .iter()
            .any(|e| matches!(e, RiskyActionsError::DuplicateGroupName(n) if n == "dup")));
    }

    #[test]
    fn from_yaml_empty_actions_list_returns_empty_group_error() {
        let yaml = "- name: empty\n  description: test\n  actions: []\n";

        let result = RiskyActionGroups::from_yaml(yaml);

        let errors = result.expect_err("empty actions must be rejected");
        assert!(errors
            .iter()
            .any(|e| matches!(e, RiskyActionsError::EmptyActions(n) if n == "empty")));
    }

    #[test]
    fn from_yaml_empty_document_returns_no_groups_error() {
        let result = RiskyActionGroups::from_yaml("[]");

        let errors = result.expect_err("empty document must be rejected");
        assert!(errors
            .iter()
            .any(|e| matches!(e, RiskyActionsError::NoGroups)));
    }

    #[test]
    fn from_yaml_wildcard_action_returns_invalid_action_error() {
        let yaml = group("wild", &["iam:Put*"]);

        let result = RiskyActionGroups::from_yaml(&yaml);

        let errors = result.expect_err("wildcard actions must be rejected");
        assert!(errors.iter().any(|e| matches!(
            e,
            RiskyActionsError::InvalidAction { group, action }
            if group == "wild" && action == "iam:Put*"
        )));
    }

    #[test]
    fn from_yaml_collects_all_problems_not_just_the_first() {
        let yaml = format!(
            "{}{}",
            group("dup", &["iam:Put*"]),
            group("dup", &["iam:PassRole"])
        );

        let errors = RiskyActionGroups::from_yaml(&yaml).expect_err("must fail");

        assert!(errors
            .iter()
            .any(|e| matches!(e, RiskyActionsError::DuplicateGroupName(_))));
        assert!(errors
            .iter()
            .any(|e| matches!(e, RiskyActionsError::InvalidAction { .. })));
        assert_eq!(errors.len(), 2);
    }

    #[test]
    fn all_actions_dedupes_actions_shared_across_groups() {
        let yaml = format!(
            "{}{}",
            group("a", &["iam:PassRole", "iam:PutRolePolicy"]),
            group("b", &["iam:PassRole"])
        );
        let groups = RiskyActionGroups::from_yaml(&yaml).expect("must parse");

        let mut actions = groups.all_actions();
        actions.sort();

        assert_eq!(actions, vec!["iam:PassRole", "iam:PutRolePolicy"]);
    }

    #[test]
    fn load_missing_path_returns_read_err() {
        let path = Path::new("/nonexistent/path/risky-actions.yaml");

        let result = RiskyActionGroups::load(path);

        assert!(matches!(result, Err(RiskyActionsError::Read { .. })));
    }

    #[test]
    fn resolve_risky_actions_explicit_path_is_used_verbatim() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("custom.yaml");
        std::fs::write(&path, group("g", &["iam:PassRole"])).expect("write fixture");

        let groups = RiskyActionGroups::resolve(Some(&path), None).expect("must resolve");

        assert_eq!(groups.all_actions(), vec!["iam:PassRole".to_string()]);
    }

    #[test]
    fn resolve_risky_actions_missing_installed_config_returns_not_found_naming_the_path() {
        let dir = tempfile::tempdir().expect("tempdir");

        let result = RiskyActionGroups::resolve(None, Some(dir.path()));

        let expected_path = dir
            .path()
            .join(".aws-iam-grapher/config/risky-actions.yaml");
        match result {
            Err(RiskyActionsError::NotFound { path }) => {
                assert_eq!(path, expected_path.display().to_string());
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn resolve_risky_actions_never_falls_back_to_repo_checkout() {
        // Run from a directory that genuinely contains config/risky-actions.yaml (the
        // repo checkout) but pass it as `home`, not `explicit` — resolution must still
        // look for `<home>/.aws-iam-grapher/config/risky-actions.yaml`, not
        // `<home>/config/risky-actions.yaml`, so it must fail here even though a
        // same-shaped file exists one path segment away.
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let repo_root = Path::new(manifest_dir).join("../..");

        let result = RiskyActionGroups::resolve(None, Some(&repo_root));

        assert!(matches!(result, Err(RiskyActionsError::NotFound { .. })));
    }

    #[test]
    fn resolve_risky_actions_home_unset_returns_no_home_error() {
        let result = RiskyActionGroups::resolve(None, None);

        assert!(matches!(result, Err(RiskyActionsError::NoHome)));
    }

    #[test]
    fn finalize_actions_two_of_three_group_actions_is_not_reported() {
        let yaml = group(
            "combo",
            &["iam:PassRole", "iam:PutRolePolicy", "iam:AttachRolePolicy"],
        );
        let groups = RiskyActionGroups::from_yaml(&yaml).expect("must parse");
        let allowed = vec!["iam:PassRole".to_string(), "iam:PutRolePolicy".to_string()];

        let result = groups.finalize_actions(&allowed);

        assert_eq!(result, None);
    }

    #[test]
    fn finalize_actions_all_three_group_actions_is_reported_with_matched_group_name() {
        let yaml = group(
            "combo",
            &["iam:PassRole", "iam:PutRolePolicy", "iam:AttachRolePolicy"],
        );
        let groups = RiskyActionGroups::from_yaml(&yaml).expect("must parse");
        let allowed = vec![
            "iam:PassRole".to_string(),
            "iam:PutRolePolicy".to_string(),
            "iam:AttachRolePolicy".to_string(),
        ];

        let (risky_actions, matched_paths) = groups.finalize_actions(&allowed).expect("must match");

        assert_eq!(matched_paths, vec!["combo".to_string()]);
        assert_eq!(risky_actions.len(), 3);
    }

    #[test]
    fn finalize_actions_entity_satisfies_two_groups_reports_both_names_and_deduped_actions() {
        let yaml = format!(
            "{}{}",
            group("a", &["iam:PassRole"]),
            group("b", &["iam:PassRole", "iam:PutRolePolicy"])
        );
        let groups = RiskyActionGroups::from_yaml(&yaml).expect("must parse");
        let allowed = vec!["iam:PassRole".to_string(), "iam:PutRolePolicy".to_string()];

        let (risky_actions, matched_paths) = groups.finalize_actions(&allowed).expect("must match");

        assert_eq!(matched_paths, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(
            risky_actions,
            vec!["iam:PassRole".to_string(), "iam:PutRolePolicy".to_string()]
        );
    }

    #[test]
    fn finalize_actions_single_action_group_matches_like_legacy_or_semantics() {
        let yaml = format!(
            "{}{}",
            group("a", &["iam:PassRole"]),
            group("b", &["iam:CreateAccessKey"])
        );
        let groups = RiskyActionGroups::from_yaml(&yaml).expect("must parse");
        let allowed = vec!["iam:PassRole".to_string()];

        let (_, matched_paths) = groups.finalize_actions(&allowed).expect("must match");

        assert_eq!(matched_paths, vec!["a".to_string()]);
    }

    /// The single most important test in this change: proves group AND-matching, if
    /// ever fed input where a Deny already suppressed one of a group's actions, does
    /// NOT match — i.e. correctness depends on the caller applying Deny subtraction
    /// before calling `finalize_actions`, exactly as `escalation.rs`/`org_escalation.rs`
    /// are required to do.
    #[test]
    fn finalize_actions_deny_on_one_group_member_prevents_match() {
        let yaml = group(
            "combo",
            &["iam:PutRolePolicy", "iam:PutUserPolicy", "iam:PassRole"],
        );
        let groups = RiskyActionGroups::from_yaml(&yaml).expect("must parse");
        // Simulates the post-Deny-subtraction input after a `Deny iam:Put*` suppressed
        // both iam:PutRolePolicy and iam:PutUserPolicy — only iam:PassRole survives.
        let allowed_post_deny = vec!["iam:PassRole".to_string()];

        let result = groups.finalize_actions(&allowed_post_deny);

        assert_eq!(result, None);
    }
}
