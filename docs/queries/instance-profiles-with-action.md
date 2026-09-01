# instance_profiles_with_action

## Purpose

Instance profiles whose associated roles have an Allow permission for `$action`.

## Parameters

- `$account_id` — account scope for tenant isolation
- `$snapshot_id` — snapshot scope
- `$action` — IAM action to test (e.g. `"ec2:DescribeInstances"`)

## Cypher

```cypher
MATCH (ip:InstanceProfile {account_id: $account_id, snapshot_id: $snapshot_id})
      -[:CONTAINS_ROLE]->(r:Role)
      -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS {
          effect: 'Allow',
          snapshot_id: $snapshot_id
      }]->(perm:Permission {action: $action})
RETURN DISTINCT ip.arn AS arn, ip.name AS name
```

## Rust binding

`crates/iam-graph/src/queries/analysis.rs` — `INSTANCE_PROFILES_WITH_ACTION_QUERY`, used in
`instance_profiles_with_action(graph: &Graph, ctx: &QueryContext, action: &str) -> Result<Vec<EntityRef>, GraphError>`.

## Returns

Rows of `{ arn, name }`, converted to `EntityRef { entity_type: "InstanceProfile", ... }`
with the remaining `EntityRef` fields defaulted (`is_full_admin: false`, `resource: ""`,
`is_bounded: false`, `conditional: false`).
