use iam_models::Condition;

/// UID for entities with an ARN.
pub fn entity_uid(snapshot_id: &str, arn: &str) -> String {
    format!("{snapshot_id}|{arn}")
}

/// UID for inline policies (no ARN — keyed by owner ARN + name).
pub fn inline_policy_uid(snapshot_id: &str, owner_arn: &str, name: &str) -> String {
    format!("{snapshot_id}|{owner_arn}|{name}")
}

/// UID for Permission nodes.
///
/// `condition` is folded into the UID (via [`canonical_condition`]) so two statements
/// with the same action/resource/effect but *different* `Condition` blocks produce
/// distinct nodes — otherwise a MERGE collision would silently drop one statement's
/// condition, mis-flagging a conditional grant as unconditional.
pub fn permission_uid(
    snapshot_id: &str,
    effect: &str,
    action: &str,
    resource: &str,
    condition: Option<&Condition>,
) -> String {
    let cond = canonical_condition(condition);
    format!("{snapshot_id}|{effect}|{action}|{resource}|{cond}")
}

/// UID for allow-all-except (NotAction) Permission nodes.
///
/// Encodes the sorted excluded-action list so two NotAction grants on the same
/// resource but with different excluded sets get distinct nodes, and so the UID
/// never collides with a true full-admin `action='*'` node.
pub fn excluded_permission_uid(
    snapshot_id: &str,
    effect: &str,
    resource: &str,
    excluded: &[String],
    condition: Option<&Condition>,
) -> String {
    let mut sorted = excluded.to_vec();
    sorted.sort();
    let joined = sorted.join(",");
    let cond = canonical_condition(condition);
    format!("{snapshot_id}|{effect}|*|{resource}|EXCEPT:{joined}|{cond}")
}

/// Deterministic string encoding of a `Condition` block, independent of `HashMap`
/// iteration order, for folding into node UIDs and stored properties.
pub fn canonical_condition(condition: Option<&Condition>) -> String {
    let Some(condition) = condition.filter(|c| !c.is_empty()) else {
        return String::new();
    };
    let mut operators: Vec<_> = condition.iter().collect();
    operators.sort_by(|a, b| a.0.cmp(b.0));
    operators
        .into_iter()
        .map(|(operator, keys)| {
            let mut entries: Vec<_> = keys.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let body = entries
                .into_iter()
                .map(|(key, values)| {
                    let mut sorted_values = values.0.clone();
                    sorted_values.sort();
                    format!("{key}=[{}]", sorted_values.join(","))
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{operator}{{{body}}}")
        })
        .collect::<Vec<_>>()
        .join(";")
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_uid_is_deterministic() {
        assert_eq!(
            entity_uid("snap-001", "arn:aws:iam::123:policy/Test"),
            "snap-001|arn:aws:iam::123:policy/Test"
        );
    }

    #[test]
    fn inline_policy_uid_encodes_owner_and_name() {
        assert_eq!(
            inline_policy_uid("snap-001", "arn:aws:iam::123:role/Foo", "Inline"),
            "snap-001|arn:aws:iam::123:role/Foo|Inline"
        );
    }

    #[test]
    fn permission_uid_encodes_all_parts() {
        assert_eq!(
            permission_uid("snap-001", "Allow", "s3:GetObject", "*", None),
            "snap-001|Allow|s3:GetObject|*|"
        );
    }

    #[test]
    fn excluded_permission_uid_is_deterministic_and_sorts_excluded() {
        let a = excluded_permission_uid(
            "snap-001",
            "Allow",
            "*",
            &["s3:DeleteObject".to_string(), "s3:GetObject".to_string()],
            None,
        );
        let b = excluded_permission_uid(
            "snap-001",
            "Allow",
            "*",
            &["s3:GetObject".to_string(), "s3:DeleteObject".to_string()],
            None,
        );
        assert_eq!(a, b, "order of excluded list must not affect uid");
        assert!(a.contains("EXCEPT:"), "uid must encode exclusion marker");
    }

    #[test]
    fn excluded_permission_uid_differs_from_full_admin_uid() {
        let full_admin = permission_uid("snap-001", "Allow", "*", "*", None);
        let not_action = excluded_permission_uid(
            "snap-001",
            "Allow",
            "*",
            &["s3:GetObject".to_string()],
            None,
        );
        assert_ne!(full_admin, not_action);
    }

    #[test]
    fn permission_uid_differs_by_condition() {
        use iam_models::ConditionValues;
        use std::collections::HashMap;

        let mut inner = HashMap::new();
        inner.insert(
            "aws:MultiFactorAuthPresent".to_string(),
            ConditionValues(vec!["true".to_string()]),
        );
        let mut condition: Condition = HashMap::new();
        condition.insert("Bool".to_string(), inner);

        let unconditional = permission_uid("snap-001", "Allow", "s3:GetObject", "*", None);
        let conditional =
            permission_uid("snap-001", "Allow", "s3:GetObject", "*", Some(&condition));

        assert_ne!(unconditional, conditional);
    }

    #[test]
    fn canonical_condition_is_order_independent() {
        use iam_models::ConditionValues;
        use std::collections::HashMap;

        let mut inner_a = HashMap::new();
        inner_a.insert(
            "aws:RequestedRegion".to_string(),
            ConditionValues(vec!["us-east-1".to_string(), "us-west-2".to_string()]),
        );
        let mut a: Condition = HashMap::new();
        a.insert("StringEquals".to_string(), inner_a);

        let mut inner_b = HashMap::new();
        inner_b.insert(
            "aws:RequestedRegion".to_string(),
            ConditionValues(vec!["us-west-2".to_string(), "us-east-1".to_string()]),
        );
        let mut b: Condition = HashMap::new();
        b.insert("StringEquals".to_string(), inner_b);

        assert_eq!(canonical_condition(Some(&a)), canonical_condition(Some(&b)));
    }
}
