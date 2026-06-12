use iam_models::IamRole;

#[test]
fn standard_role_deserializes_correctly() {
    let json = include_str!("fixtures/role_standard.json");

    let role = IamRole::from_json(json).expect("fixture must deserialize");

    assert_eq!(role.role_name, "AppServerRole");
    assert_eq!(role.arn, "arn:aws:iam::123456789012:role/AppServerRole");
    assert_eq!(role.attached_managed_policies.len(), 1);
    assert_eq!(
        role.attached_managed_policies[0].policy_name,
        "AmazonS3ReadOnlyAccess"
    );
    assert!(role.create_date.timestamp() > 0);
}

#[test]
fn standard_role_is_aws_managed_false() {
    let json = include_str!("fixtures/role_standard.json");
    let role = IamRole::from_json(json).unwrap();
    assert!(!role.is_aws_managed);
}

#[test]
fn aws_service_role_is_aws_managed_true() {
    let json = include_str!("fixtures/role_aws_service.json");
    let role = IamRole::from_json(json).unwrap();
    assert!(role.is_aws_managed);
    assert!(role.path.starts_with("/aws-service-role/"));
}

#[test]
fn role_with_boundary_deserializes_boundary() {
    let json = include_str!("fixtures/role_with_boundary.json");
    let role = IamRole::from_json(json).unwrap();
    let boundary = role.permissions_boundary.expect("boundary must be present");
    assert_eq!(
        boundary.permissions_boundary_arn,
        "arn:aws:iam::123456789012:policy/BoundaryPolicy"
    );
}

#[test]
fn role_without_boundary_is_none() {
    let json = include_str!("fixtures/role_standard.json");
    let role = IamRole::from_json(json).unwrap();
    assert!(role.permissions_boundary.is_none());
}

#[test]
fn role_assume_policy_document_deserializes() {
    let json = include_str!("fixtures/role_standard.json");
    let role = IamRole::from_json(json).unwrap();
    let doc = role
        .assume_role_policy_document
        .expect("trust policy must be present");
    assert_eq!(doc.statement.len(), 1);
    assert_eq!(doc.statement[0].action, vec!["sts:AssumeRole"]);
}

#[test]
fn role_round_trip_serialization() {
    let json = include_str!("fixtures/role_standard.json");
    let original = IamRole::from_json(json).unwrap();

    let serialized = serde_json::to_string(&original).unwrap();
    let restored: IamRole = serde_json::from_str(&serialized).unwrap();

    assert_eq!(original.arn, restored.arn);
    assert_eq!(original.role_name, restored.role_name);
    assert_eq!(
        original.create_date.timestamp(),
        restored.create_date.timestamp()
    );
}

#[test]
fn role_parse_date_from_iso8601() {
    let json = include_str!("fixtures/role_standard.json");
    let role = IamRole::from_json(json).unwrap();
    assert!(role.create_date.timestamp() > 0);
}
