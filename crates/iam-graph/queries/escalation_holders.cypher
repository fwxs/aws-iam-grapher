// name: escalation_holders
// description: For each terminal Group ARN in $arns, return its member Users via an inbound
//   MEMBER_OF edge (User)-[:MEMBER_OF]->(Group). Batched via UNWIND so all terminals from one
//   privilege_escalation_paths call are resolved in a single round trip.
// param $arns: terminal Group ARNs to resolve holders for
// param $account_id: account scope for tenant isolation
// param $snapshot_id: snapshot scope

UNWIND $arns AS terminal_arn
MATCH (g:Group {arn: terminal_arn, account_id: $account_id, snapshot_id: $snapshot_id})
MATCH (u:User)-[:MEMBER_OF]->(g)
RETURN terminal_arn, u.arn AS arn, u.name AS name, labels(u)[0] AS entity_type,
       u.user_id AS user_id, u.has_mfa AS has_mfa, u.mfa_method AS mfa_method,
       u.console_login_enabled AS console_login_enabled,
       u.password_last_used AS password_last_used,
       u.last_activity_date AS last_activity_date, u.create_date AS create_date,
       u.access_key_count AS access_key_count,
       u.active_access_key_count AS active_access_key_count,
       u.oldest_active_key_date AS oldest_active_key_date,
       u.access_key_ids AS access_key_ids
