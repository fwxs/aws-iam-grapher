use iam_models::Condition;

/// UID for entities with an ARN.
pub fn entity_uid(snapshot_id: &str, arn: &str) -> String {
    format!("{snapshot_id}|{arn}")
}

/// UID for inline policies (no ARN — keyed by owner ARN + name).
pub fn inline_policy_uid(snapshot_id: &str, owner_arn: &str, name: &str) -> String {
    format!("{snapshot_id}|{owner_arn}|{name}")
}

/// Deterministic, sorted encoding of an excluded-action list (`NotAction`), for folding
/// into `GRANTS` edge merge keys so two NotAction grants on the same policy/resource/effect
/// with different excluded sets don't collide.
pub fn excluded_actions_key(excluded: &[String]) -> String {
    let mut sorted = excluded.to_vec();
    sorted.sort();
    sorted.join(",")
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
    fn excluded_actions_key_is_deterministic_regardless_of_order() {
        let a = excluded_actions_key(&["s3:DeleteObject".to_string(), "s3:GetObject".to_string()]);
        let b = excluded_actions_key(&["s3:GetObject".to_string(), "s3:DeleteObject".to_string()]);
        assert_eq!(a, b, "order of excluded list must not affect the key");
    }

    #[test]
    fn excluded_actions_key_empty_for_empty_list() {
        assert_eq!(excluded_actions_key(&[]), "");
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
