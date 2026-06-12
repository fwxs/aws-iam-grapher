use iam_models::IamUser;

#[test]
fn standard_user_deserializes_correctly() {
    let json = include_str!("fixtures/user_standard.json");

    let user = IamUser::from_json(json).expect("fixture must deserialize");

    assert_eq!(user.user_name, "alice");
    assert_eq!(user.arn, "arn:aws:iam::123456789012:user/alice");
    assert_eq!(user.group_list, vec!["Developers"]);
    assert_eq!(user.attached_managed_policies.len(), 1);
    assert!(user.create_date.timestamp() > 0);
}

#[test]
fn iam_user_is_aws_managed_always_false() {
    let json = include_str!("fixtures/user_standard.json");
    let user = IamUser::from_json(json).unwrap();
    assert!(!user.is_aws_managed);
}

#[test]
fn user_with_boundary_deserializes_boundary() {
    let json = include_str!("fixtures/user_with_boundary.json");
    let user = IamUser::from_json(json).unwrap();
    let boundary = user.permissions_boundary.expect("boundary must be present");
    assert_eq!(
        boundary.permissions_boundary_arn,
        "arn:aws:iam::123456789012:policy/UserBoundary"
    );
}

#[test]
fn user_optional_password_last_used() {
    let json = include_str!("fixtures/user_with_boundary.json");
    let user = IamUser::from_json(json).unwrap();
    assert!(user.password_last_used.is_none());
}

#[test]
fn user_password_last_used_parses_when_present() {
    let json = include_str!("fixtures/user_standard.json");
    let user = IamUser::from_json(json).unwrap();
    let last_used = user
        .password_last_used
        .expect("password_last_used must be present");
    assert!(last_used.timestamp() > 0);
}

#[test]
fn user_round_trip_serialization() {
    let json = include_str!("fixtures/user_standard.json");
    let original = IamUser::from_json(json).unwrap();

    let serialized = serde_json::to_string(&original).unwrap();
    let restored: IamUser = serde_json::from_str(&serialized).unwrap();

    assert_eq!(original.arn, restored.arn);
    assert_eq!(original.user_name, restored.user_name);
    assert_eq!(
        original.create_date.timestamp(),
        restored.create_date.timestamp()
    );
}

#[test]
fn user_parse_date_from_iso8601() {
    let json = include_str!("fixtures/user_standard.json");
    let user = IamUser::from_json(json).unwrap();
    assert!(user.create_date.timestamp() > 0);
}
