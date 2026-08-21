//! Snapshot tests over the serialized JSON shape of every query result type.
//!
//! These pin the wire format consumed by the `aws-iam-grapher` Claude Code skill (D7, #145)
//! as a reviewable contract: a field rename, added field, or `CaveatCode` variant rename fails
//! `cargo test --workspace` with a snapshot diff instead of silently drifting. A failing
//! snapshot here means a consumer-visible JSON contract change — update the skill in the same
//! PR before accepting the new snapshot. See `CLAUDE.md`.
//!
//! No Docker required: every result type is a plain data holder constructed directly with
//! fixed literal values, never through the graph.

use iam_graph::queries::{
    AccountRecord, AssociatedEntity, Caveat, EntityRef, EscalationPath, Hop, OrgEscalationPath,
    OrgHop, PermissionDiff, PermissionRecord, PermissionRow, SnapshotRecord,
};

#[test]
fn associated_entity_json_shape() {
    let value = AssociatedEntity {
        arn: "arn:aws:iam::123456789012:role/Example".to_string(),
        name: "Example".to_string(),
        entity_type: "Role".to_string(),
        relationship: "CAN_ASSUME".to_string(),
    };

    insta::assert_json_snapshot!(value);
}

#[test]
fn entity_ref_json_shape() {
    let value = EntityRef {
        arn: "arn:aws:iam::123456789012:role/Example".to_string(),
        name: "Example".to_string(),
        entity_type: "Role".to_string(),
        is_full_admin: false,
        resource: "arn:aws:s3:::example-bucket/*".to_string(),
        is_bounded: true,
        conditional: false,
        unevaluated_condition_keys: vec!["aws:SourceIp".to_string()],
    };

    insta::assert_json_snapshot!(value);
}

#[test]
fn permission_row_json_shape() {
    let value = PermissionRow {
        action: "s3:GetObject".to_string(),
        effect: "Allow".to_string(),
        resource: "arn:aws:s3:::example-bucket/*".to_string(),
        effective: true,
    };

    insta::assert_json_snapshot!(value);
}

#[test]
fn escalation_path_json_shape() {
    let value = EscalationPath {
        arn: "arn:aws:iam::123456789012:user/Attacker".to_string(),
        name: "Attacker".to_string(),
        entity_type: "User".to_string(),
        risky_actions: vec!["iam:CreatePolicyVersion".to_string()],
        path: vec![Hop {
            arn: "arn:aws:iam::123456789012:role/Victim".to_string(),
            entity_type: "Role".to_string(),
        }],
        conditional: false,
    };

    insta::assert_json_snapshot!(value);
}

#[test]
fn org_escalation_path_json_shape() {
    let value = OrgEscalationPath {
        arn: "arn:aws:iam::123456789012:user/Attacker".to_string(),
        name: "Attacker".to_string(),
        entity_type: "User".to_string(),
        account_id: "123456789012".to_string(),
        risky_actions: vec!["sts:AssumeRole".to_string()],
        path: vec![OrgHop {
            arn: "arn:aws:iam::210987654321:role/Victim".to_string(),
            entity_type: "Role".to_string(),
            account_id: "210987654321".to_string(),
        }],
        conditional: true,
    };

    insta::assert_json_snapshot!(value);
}

#[test]
fn permission_diff_json_shape() {
    let value = PermissionDiff {
        added: vec![PermissionRecord {
            action: "s3:PutObject".to_string(),
            resource: "arn:aws:s3:::example-bucket/*".to_string(),
            effect: "Allow".to_string(),
        }],
        removed: vec![PermissionRecord {
            action: "s3:DeleteObject".to_string(),
            resource: "arn:aws:s3:::example-bucket/*".to_string(),
            effect: "Allow".to_string(),
        }],
    };

    insta::assert_json_snapshot!(value);
}

#[test]
fn snapshot_record_json_shape() {
    let value = SnapshotRecord {
        id: "20260101T000000Z".to_string(),
        account_id: "123456789012".to_string(),
        collected_at: "2026-01-01T00:00:00Z".to_string(),
        is_partial: true,
        partial_reasons: vec!["some wildcards not expanded".to_string()],
        org_collection_run_id: Some("org-run-001".to_string()),
    };

    insta::assert_json_snapshot!(value);
}

#[test]
fn account_record_json_shape() {
    let value = AccountRecord {
        id: "123456789012".to_string(),
        alias: Some("example-account".to_string()),
        ou_id: Some("ou-abcd-12345678".to_string()),
        ou_name: Some("Production".to_string()),
    };

    insta::assert_json_snapshot!(value);
}

#[test]
fn caveat_approximate_deny_json_shape() {
    insta::assert_json_snapshot!(Caveat::approximate_deny());
}

#[test]
fn caveat_notaction_not_expanded_json_shape() {
    insta::assert_json_snapshot!(Caveat::notaction_not_expanded());
}

#[test]
fn caveat_partial_snapshot_json_shape() {
    let reasons = vec!["instance profiles missing".to_string()];
    insta::assert_json_snapshot!(Caveat::partial_snapshot(&reasons));
}

#[test]
fn caveat_expansion_degraded_json_shape() {
    insta::assert_json_snapshot!(Caveat::expansion_degraded());
}
