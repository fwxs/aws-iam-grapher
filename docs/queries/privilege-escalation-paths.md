# privilege_escalation_paths

## Purpose

Entities with at least one of the 9 risky IAM actions, reachable either directly (own
attached/inline policy) or transitively via 1..N `CAN_ASSUME_ROLE` hops
(entity → role-A → role-B → ... → terminal).

## Parameters

- `$account_id` — account scope for tenant isolation
- `$snapshot_id` — snapshot scope
- `{max_hops}` — **not a real Cypher parameter.** A validated literal integer interpolated
  into the query text at build time via `render_hop_bound()`, clamped to `[1, 10]` (default
  `3`), because Cypher cannot parameterize a variable-length relationship pattern's bound.

## Cypher

```cypher
MATCH (e {account_id: $account_id, snapshot_id: $snapshot_id})
      -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS]->(perm:Permission {effect: 'Allow', snapshot_id: $snapshot_id})
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
WITH e, collect(DISTINCT perm.action) AS direct_allowed_actions
OPTIONAL MATCH (e)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(dpol)
               -[:GRANTS]->(deny:Permission {effect: 'Deny', snapshot_id: $snapshot_id})
WHERE deny.excluded_actions IS NULL
WITH e, direct_allowed_actions, collect(DISTINCT deny.action) AS own_deny_actions
OPTIONAL MATCH (e)-[:MEMBER_OF]->(:Group)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(gdpol)
               -[:GRANTS]->(gdeny:Permission {effect: 'Deny', snapshot_id: $snapshot_id})
WHERE gdeny.excluded_actions IS NULL
WITH e, direct_allowed_actions, own_deny_actions, collect(DISTINCT gdeny.action) AS group_deny_actions
WITH e,
     [a IN direct_allowed_actions WHERE
        NOT EXISTS {
            MATCH (e)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(dnpol)
                  -[:GRANTS]->(deny_not:Permission {action: '*', effect: 'Deny', snapshot_id: $snapshot_id})
            WHERE deny_not.excluded_actions IS NOT NULL AND NOT a IN deny_not.excluded_actions
        }
        AND NOT EXISTS {
            MATCH (e)-[:MEMBER_OF]->(:Group)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(gdnpol)
                  -[:GRANTS]->(gdeny_not:Permission {action: '*', effect: 'Deny', snapshot_id: $snapshot_id})
            WHERE gdeny_not.excluded_actions IS NOT NULL AND NOT a IN gdeny_not.excluded_actions
        }
     ] AS allowed_actions,
     own_deny_actions, group_deny_actions
RETURN e.arn AS arn, e.name AS name, labels(e)[0] AS entity_type,
       allowed_actions, own_deny_actions + group_deny_actions AS deny_actions,
       [{arn: e.arn, entity_type: labels(e)[0]}] AS path,
       false AS conditional

UNION

MATCH p = (start {account_id: $account_id, snapshot_id: $snapshot_id})
          -[:CAN_ASSUME_ROLE*1..{max_hops}]->(terminal)
WHERE (start:Role OR start:User) AND terminal.account_id = $account_id
  AND terminal.snapshot_id = $snapshot_id
WITH start, terminal, p
ORDER BY length(p) ASC
WITH start, terminal, collect(p)[0] AS p
MATCH (terminal)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
                -[:GRANTS]->(perm:Permission {effect: 'Allow', snapshot_id: $snapshot_id})
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
               -[:GRANTS]->(deny:Permission {effect: 'Deny', snapshot_id: $snapshot_id})
WHERE deny.excluded_actions IS NULL
WITH start, p, terminal, direct_allowed_actions, collect(DISTINCT deny.action) AS own_deny_actions
OPTIONAL MATCH (terminal)-[:MEMBER_OF]->(:Group)
               -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(gdpol)
               -[:GRANTS]->(gdeny:Permission {effect: 'Deny', snapshot_id: $snapshot_id})
WHERE gdeny.excluded_actions IS NULL
WITH start, p, terminal, direct_allowed_actions, own_deny_actions,
     collect(DISTINCT gdeny.action) AS group_deny_actions
WITH start, p,
     [a IN direct_allowed_actions WHERE
        NOT EXISTS {
            MATCH (terminal)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(dnpol)
                  -[:GRANTS]->(deny_not:Permission {action: '*', effect: 'Deny', snapshot_id: $snapshot_id})
            WHERE deny_not.excluded_actions IS NOT NULL AND NOT a IN deny_not.excluded_actions
        }
        AND NOT EXISTS {
            MATCH (terminal)-[:MEMBER_OF]->(:Group)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(gdnpol)
                  -[:GRANTS]->(gdeny_not:Permission {action: '*', effect: 'Deny', snapshot_id: $snapshot_id})
            WHERE gdeny_not.excluded_actions IS NOT NULL AND NOT a IN gdeny_not.excluded_actions
        }
     ] AS allowed_actions,
     own_deny_actions, group_deny_actions
RETURN start.arn AS arn, start.name AS name, labels(start)[0] AS entity_type,
       allowed_actions, own_deny_actions + group_deny_actions AS deny_actions,
       [n IN nodes(p) | {arn: n.arn, entity_type: labels(n)[0]}] AS path,
       any(rel IN relationships(p) WHERE rel.conditional) AS conditional
```

## Rust binding

`crates/iam-graph/src/queries/escalation.rs` — `ESCALATION_QUERY`, used in
`privilege_escalation_paths(graph: &Graph, ctx: &QueryContext, max_hops: u32) -> Result<Vec<EscalationPath>, GraphError>`.
Uses `render_hop_bound(ESCALATION_QUERY, max_hops)` to interpolate `{max_hops}` before
execution.

## Returns

`Vec<EscalationPath>` where `EscalationPath { arn, name, entity_type, risky_actions, path: Vec<Hop>, conditional }`
and `Hop { arn, entity_type }`. Rust post-processing dedupes by arn (shortest path wins),
applies wildcard-aware Deny suppression via `iam_expander::glob_match`, and drops entities
with an empty `risky_actions` set.

## Notes

Two UNION arms: arm 1 covers the zero-hop case (own risky permissions); arm 2 covers
transitive `CAN_ASSUME_ROLE` chains, deduped to the shortest path per (start, terminal) pair
before computing risky actions. Allow/Deny suppression mirrors the single-entity logic,
evaluated at the terminal entity — own policies plus every group the terminal is `MEMBER_OF`.
Per-action, wildcard-aware Deny suppression (e.g. a Deny on `iam:Put*` covering
`iam:PutRolePolicy`) is applied in Rust against `deny_actions`, since Cypher has no glob
matching. Deny-all-except (Deny NotAction) sentinel nodes are evaluated here via `NOT EXISTS`
subqueries instead, since the rule is plain set membership: an allowed action is dropped if a
reachable deny-all-except node (own policies or a member group's) does *not* list it in
`excluded_actions`.

`conditional` is true when any `CAN_ASSUME_ROLE` hop on the path carries `conditional = true`
(a runtime-evaluated or unresolved trust condition) — it flags the path as uncertain rather
than asserting the chain unconditionally.

See also [`org_escalation_paths`](org-escalation-paths.md) for the cross-account equivalent
(run per org collection run rather than per account, and only covers the transitive case —
run this query per-account for the zero-hop case).
