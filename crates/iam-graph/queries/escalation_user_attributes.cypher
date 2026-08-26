// name: escalation_user_attributes
// description: For each escalating-entity ARN in $arns that is a User, return its security
//   posture (MFA, console login, activity, access keys). Batched via UNWIND so all User
//   entities from one privilege_escalation_paths call are resolved in a single round trip.
//   ARNs that don't resolve to a User in this scope (already filtered by the caller to only
//   User-typed entities, but scoped again here for tenant isolation) simply produce no row.
// param $arns: escalating-entity ARNs to resolve user attributes for
// param $account_id: account scope for tenant isolation
// param $snapshot_id: snapshot scope

UNWIND $arns AS entity_arn
MATCH (u:User {arn: entity_arn, account_id: $account_id, snapshot_id: $snapshot_id})
RETURN entity_arn, u.user_id AS user_id, u.has_mfa AS has_mfa, u.mfa_method AS mfa_method,
       u.console_login_enabled AS console_login_enabled,
       u.password_last_used AS password_last_used,
       u.last_activity_date AS last_activity_date, u.create_date AS create_date,
       u.access_key_count AS access_key_count,
       u.active_access_key_count AS active_access_key_count,
       u.oldest_active_key_date AS oldest_active_key_date,
       u.access_key_ids AS access_key_ids
