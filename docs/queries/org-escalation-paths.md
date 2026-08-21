# org_escalation_paths

## Purpose

Cross-account privilege-escalation paths across one org collection run. Traverses
`CAN_ASSUME_ROLE` edges (including cross-account edges materialized by the stitch pass) to
find entities that can reach any of the 9 risky IAM actions by assuming roles across account
boundaries. Only transitive paths (1..N hops) are returned; run
[`privilege_escalation_paths`](privilege-escalation-paths.md) per-account for the zero-hop
(direct) case.

## Parameters

- `$org_run_id` — org collection run id shared across all per-account snapshots
- `{max_hops}` — **not a real Cypher parameter.** A validated literal integer interpolated
  into the query text at build time via `render_hop_bound()`, clamped to `[1, 10]`
  (default `3`).

## Cypher

```cypher
MATCH (start_snap:Snapshot {org_collection_run_id: $org_run_id})-[:INCLUDES]->(start)
WHERE start:Role OR start:User
MATCH p = (start)-[:CAN_ASSUME_ROLE*1..{max_hops}]->(terminal)
WHERE EXISTS {
  MATCH (:Snapshot {org_collection_run_id: $org_run_id})-[:INCLUDES]->(terminal)
}
WITH start, terminal, p
ORDER BY length(p) ASC
WITH start, terminal, collect(p)[0] AS p
MATCH (terminal)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
                -[:GRANTS]->(perm:Permission {effect: 'Allow', snapshot_id: terminal.snapshot_id})
WHERE perm.action IN [
    'iam:CreatePolicyVersion',
    'iam:SetDefaultPolicyVersion',
    'iam:AttachRolePolicy',
    'iam:AttachUserPolicy',
    'iam:PassRole',
    'iam:PutRolePolicy',
    'iam:PutUserPolicy',
    'iam:CreateAccessKey',
    'iam:CreateLoginProfile'
]
WITH start, p, terminal, collect(DISTINCT perm.action) AS direct_allowed_actions
OPTIONAL MATCH (terminal)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(dpol)
               -[:GRANTS]->(deny:Permission {effect: 'Deny', snapshot_id: terminal.snapshot_id})
WHERE deny.excluded_actions IS NULL
WITH start, p, terminal, direct_allowed_actions, collect(DISTINCT deny.action) AS own_deny_actions
OPTIONAL MATCH (terminal)-[:MEMBER_OF]->(:Group)
               -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(gdpol)
               -[:GRANTS]->(gdeny:Permission {effect: 'Deny', snapshot_id: terminal.snapshot_id})
WHERE gdeny.excluded_actions IS NULL
WITH start, p, terminal, direct_allowed_actions, own_deny_actions,
     collect(DISTINCT gdeny.action) AS group_deny_actions
WITH start, p, terminal,
     [a IN direct_allowed_actions WHERE
        NOT EXISTS {
            MATCH (terminal)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(dnpol)
                  -[:GRANTS]->(deny_not:Permission {action: '*', effect: 'Deny',
                               snapshot_id: terminal.snapshot_id})
            WHERE deny_not.excluded_actions IS NOT NULL AND NOT a IN deny_not.excluded_actions
        }
        AND NOT EXISTS {
            MATCH (terminal)-[:MEMBER_OF]->(:Group)
                  -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(gdnpol)
                  -[:GRANTS]->(gdeny_not:Permission {action: '*', effect: 'Deny',
                               snapshot_id: terminal.snapshot_id})
            WHERE gdeny_not.excluded_actions IS NOT NULL
              AND NOT a IN gdeny_not.excluded_actions
        }
     ] AS allowed_actions,
     own_deny_actions, group_deny_actions
RETURN start.arn AS arn, start.name AS name, labels(start)[0] AS entity_type,
       start.account_id AS account_id,
       allowed_actions, own_deny_actions + group_deny_actions AS deny_actions,
       [n IN nodes(p) | {arn: n.arn, entity_type: labels(n)[0], account_id: n.account_id}] AS path,
       any(rel IN relationships(p) WHERE rel.conditional) AS conditional
```

## Rust binding

`crates/iam-graph/src/queries/org_escalation.rs` — `ORG_ESCALATION_QUERY`, used in
`org_escalation_paths(graph: &Graph, ctx: &OrgQueryContext, max_hops: u32) -> Result<Vec<OrgEscalationPath>, GraphError>`.
Uses `render_hop_bound(ORG_ESCALATION_QUERY, max_hops)` to interpolate `{max_hops}`; the only
real bound parameter is `$org_run_id`.

## Returns

`Vec<OrgEscalationPath>` where `OrgEscalationPath { arn, name, entity_type, account_id, risky_actions, path: Vec<OrgHop>, conditional }`
and `OrgHop { arn, entity_type, account_id }` — `OrgHop` carries `account_id` per node so a
caller can render the cross-account path. Rust post-processing dedupes by arn keeping the
shortest path, applies wildcard Deny suppression via `iam_expander::glob_match`, and drops
entities with an empty `risky_actions` set.

## Notes

Terminal risky-action filtering, Deny suppression, and deny-all-except evaluation mirror the
single-account [`privilege_escalation_paths`](privilege-escalation-paths.md) query, but here
`snapshot_id` is taken from `terminal.snapshot_id` rather than a parameter, since a path can
cross snapshots belonging to different accounts within the same org run.
