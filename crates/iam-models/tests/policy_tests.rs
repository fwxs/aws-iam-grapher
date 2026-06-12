use iam_models::{IamInlinePolicy, IamPolicy, PolicyDocument, PolicyStatement};

#[test]
fn managed_aws_policy_deserializes_correctly() {
    let json = include_str!("fixtures/policy_managed_aws.json");

    let policy = IamPolicy::from_json(json).expect("fixture must deserialize");

    assert_eq!(policy.policy_name, "ReadOnlyAccess");
    assert_eq!(policy.arn, "arn:aws:iam::aws:policy/ReadOnlyAccess");
    assert_eq!(policy.default_version_id, "v16");
    assert_eq!(policy.attachment_count, 3);
    assert!(policy.is_attachable);
    assert!(policy.create_date.timestamp() > 0);
}

#[test]
fn managed_aws_policy_derives_is_aws_managed_true() {
    let json = include_str!("fixtures/policy_managed_aws.json");
    let policy = IamPolicy::from_json(json).unwrap();
    assert!(policy.is_aws_managed);
}

#[test]
fn managed_customer_policy_derives_is_aws_managed_false() {
    let json = include_str!("fixtures/policy_managed_customer.json");
    let policy = IamPolicy::from_json(json).unwrap();
    assert!(!policy.is_aws_managed);
}

#[test]
fn managed_customer_policy_parses_tags() {
    let json = include_str!("fixtures/policy_managed_customer.json");
    let policy = IamPolicy::from_json(json).unwrap();
    assert_eq!(policy.tags.get("Team"), Some(&"Engineering".to_string()));
    assert_eq!(
        policy.tags.get("Environment"),
        Some(&"Production".to_string())
    );
}

#[test]
fn policy_managed_aws_parse_date_from_iso8601() {
    let json = include_str!("fixtures/policy_managed_aws.json");
    let policy = IamPolicy::from_json(json).unwrap();
    assert_eq!(policy.create_date.timestamp(), 1371081122);
}

#[test]
fn inline_policy_deserializes_correctly() {
    let json = include_str!("fixtures/policy_inline.json");
    let inline: IamInlinePolicy =
        serde_json::from_str(json).expect("inline fixture must deserialize");
    assert_eq!(inline.policy_name, "InlineS3Access");
    assert_eq!(inline.policy_document.statement.len(), 1);
    let stmt = &inline.policy_document.statement[0];
    assert_eq!(stmt.action.len(), 2);
    assert_eq!(stmt.resource.len(), 2);
}

#[test]
fn policy_document_wildcards_deserializes() {
    let json = include_str!("fixtures/policy_document_wildcards.json");
    let doc: PolicyDocument =
        serde_json::from_str(json).expect("wildcards fixture must deserialize");
    assert_eq!(doc.statement.len(), 3);
    // First statement: single-string action normalized to vec
    assert_eq!(doc.statement[0].action, vec!["s3:*"]);
    // Second statement: array of actions
    assert_eq!(doc.statement[1].action.len(), 2);
}

#[test]
fn policy_document_notaction_deserializes() {
    let json = include_str!("fixtures/policy_document_notaction.json");
    let doc: PolicyDocument =
        serde_json::from_str(json).expect("notaction fixture must deserialize");
    let stmt = &doc.statement[0];
    assert!(stmt.action.is_empty());
    assert_eq!(stmt.not_action.len(), 2);
    assert!(stmt.not_action.contains(&"sts:AssumeRole".to_string()));
}

#[test]
fn policy_round_trip_serialization() {
    let json = include_str!("fixtures/policy_managed_customer.json");
    let original = IamPolicy::from_json(json).unwrap();

    let serialized = serde_json::to_string(&original).unwrap();
    let restored: IamPolicy = serde_json::from_str(&serialized).unwrap();

    assert_eq!(original.arn, restored.arn);
    assert_eq!(original.policy_name, restored.policy_name);
    assert_eq!(
        original.create_date.timestamp(),
        restored.create_date.timestamp()
    );
}

#[test]
fn policy_statement_normalizes_single_action_to_vec() {
    let json = r#"{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}"#;
    let stmt: PolicyStatement = serde_json::from_str(json).unwrap();
    assert_eq!(stmt.action, vec!["s3:GetObject"]);
}

#[test]
fn policy_statement_accepts_action_array() {
    let json = r#"{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"*"}"#;
    let stmt: PolicyStatement = serde_json::from_str(json).unwrap();
    assert_eq!(stmt.action.len(), 2);
}

#[test]
fn policy_statement_handles_notaction() {
    let json = r#"{"Effect":"Deny","NotAction":"sts:AssumeRole","Resource":"*"}"#;
    let stmt: PolicyStatement = serde_json::from_str(json).unwrap();
    assert!(stmt.action.is_empty());
    assert_eq!(stmt.not_action, vec!["sts:AssumeRole"]);
}
