use iam_models::IamInstanceProfile;

#[test]
fn standard_instance_profile_deserializes_correctly() {
    let json = include_str!("fixtures/instance_profile_standard.json");

    let profile = IamInstanceProfile::from_json(json).expect("fixture must deserialize");

    assert_eq!(profile.instance_profile_name, "WebServerProfile");
    assert_eq!(
        profile.arn,
        "arn:aws:iam::123456789012:instance-profile/WebServerProfile"
    );
    assert_eq!(profile.roles.len(), 1);
    assert_eq!(profile.roles[0].role_name, "AppServerRole");
    assert!(profile.create_date.timestamp() > 0);
}

#[test]
fn instance_profile_is_aws_managed_false_for_standard_path() {
    let json = include_str!("fixtures/instance_profile_standard.json");
    let profile = IamInstanceProfile::from_json(json).unwrap();
    assert!(!profile.is_aws_managed);
}

#[test]
fn instance_profile_embedded_role_is_aws_managed_false() {
    let json = include_str!("fixtures/instance_profile_standard.json");
    let profile = IamInstanceProfile::from_json(json).unwrap();
    assert!(!profile.roles[0].is_aws_managed);
}

#[test]
fn instance_profile_round_trip_serialization() {
    let json = include_str!("fixtures/instance_profile_standard.json");
    let original = IamInstanceProfile::from_json(json).unwrap();

    let serialized = serde_json::to_string(&original).unwrap();
    let restored: IamInstanceProfile = serde_json::from_str(&serialized).unwrap();

    assert_eq!(original.arn, restored.arn);
    assert_eq!(
        original.instance_profile_name,
        restored.instance_profile_name
    );
    assert_eq!(
        original.create_date.timestamp(),
        restored.create_date.timestamp()
    );
}

#[test]
fn instance_profile_parse_date_from_iso8601() {
    let json = include_str!("fixtures/instance_profile_standard.json");
    let profile = IamInstanceProfile::from_json(json).unwrap();
    assert!(profile.create_date.timestamp() > 0);
}
