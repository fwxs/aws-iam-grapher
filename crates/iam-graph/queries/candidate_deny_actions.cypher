// name: candidate_deny_actions
// description: Returns every distinct Deny action string present in this snapshot/account
//   scope, excluding Deny-NotAction sentinel nodes (action='*' with excluded_actions set —
//   those are not evaluated, see limitations.md). The caller matches the queried action
//   against this list with IAM glob semantics (iam_expander::glob_match) to compute the
//   concrete set of Deny actions that cover it, then passes that set back into who_can.cypher
//   / privilege_escalation_paths.cypher as $deny_actions.
// param $snapshot_id: snapshot scope
// param $account_id: account scope for tenant isolation

MATCH (deny:Permission {
    effect: 'Deny',
    snapshot_id: $snapshot_id,
    account_id: $account_id
})
WHERE deny.excluded_actions IS NULL
RETURN DISTINCT deny.action AS action
