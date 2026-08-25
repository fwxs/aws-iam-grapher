# privilege_escalation_paths

## Purpose

Entities holding permissions from a configured risky-action group (`config/risky-actions.yaml`),
reachable either directly (own attached/inline policy) or transitively via 1..N
`CAN_ASSUME_ROLE` hops (entity → role-A → role-B → ... → terminal).

## Parameters

- `$account_id` — account scope for tenant isolation
- `$snapshot_id` — snapshot scope
- `$risky_actions` — flat, deduplicated union of every action across every configured
  risky-action group (`RiskyActionGroups::all_actions`). Filters which `Permission` nodes are
  pulled back as `allowed_actions`; it does **not** by itself express the
  AND-within-group/OR-across-group semantics — that evaluation happens in Rust afterward,
  post-Deny-subtraction, via `RiskyActionGroups::finalize_actions`. See
  `crates/iam-graph/src/queries/risky_actions.rs`.
- `{max_hops}` — **not a real Cypher parameter.** A validated literal integer interpolated
  into the query text at build time via `render_hop_bound()`, clamped to `[1, 10]` (default
  `3`), because Cypher cannot parameterize a variable-length relationship pattern's bound.

## Cypher

```cypher
MATCH (e {account_id: $account_id, snapshot_id: $snapshot_id})
      -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS]->(perm:Permission {effect: 'Allow', snapshot_id: $snapshot_id})
WHERE perm.action IN $risky_actions
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
WHERE perm.action IN $risky_actions
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

After the path-finding query above and its Rust-side dedup/risky-action filtering, three
further batched enrichment queries run once per call, keyed on the deduped set of terminal
(permission-holding) ARNs — `path.last()`, not the top-level `arn` — to avoid inlining
`OPTIONAL MATCH` clauses into the UNION above and risking a Cartesian blowup on rows later
discarded by dedup:

```cypher
-- escalation_holders.cypher (Group terminals only) — also returns the holder's own
-- User node properties as `attributes` (see below)
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

-- escalation_instance_profiles.cypher (Role terminals only)
UNWIND $arns AS terminal_arn
MATCH (r:Role {arn: terminal_arn, account_id: $account_id, snapshot_id: $snapshot_id})
MATCH (ip:InstanceProfile)-[:CONTAINS_ROLE]->(r)
RETURN terminal_arn, ip.arn AS arn, ip.name AS name

-- escalation_trust_principals.cypher (Role terminals only)
UNWIND $arns AS terminal_arn
MATCH (r:Role {arn: terminal_arn, account_id: $account_id, snapshot_id: $snapshot_id})
MATCH (pr:Principal)-[rel:CAN_ASSUME]->(r)
RETURN terminal_arn, pr.id AS id, pr.type AS principal_type, rel.conditional AS conditional

-- escalation_user_attributes.cypher (User entities only) — keyed on the escalating
-- entity's own arn, NOT the terminal: for a transitive chain, arn is the assumer who'd
-- actually be attacked, while the terminal is the entity that holds the permission
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
```

Each is skipped entirely (no round trip) when its ARN batch is empty.

## Rust binding

`crates/iam-graph/src/queries/escalation.rs` — `ESCALATION_QUERY`, used in
`privilege_escalation_paths(graph: &Graph, ctx: &QueryContext, max_hops: u32, groups: &RiskyActionGroups) -> Result<Vec<EscalationPath>, GraphError>`.
Uses `render_hop_bound(ESCALATION_QUERY, max_hops)` to interpolate `{max_hops}` before
execution; `$risky_actions` (`groups.all_actions()`) is bound alongside `$account_id`/
`$snapshot_id`. Enrichment queries live in
`crates/iam-graph/src/queries/escalation_enrichment.rs` (`fetch_holders`,
`fetch_instance_profiles`, `fetch_trust_principals`, `fetch_user_attributes`), shared with
`org_escalation.rs`. `iam-grapher`'s `query privilege-escalation`/`org-escalation` subcommands
apply an additional `--entity-type <user|role|group|all>` filter in Rust, after this query
returns — see `crates/iam-grapher/src/cli/query.rs::filter_by_entity_type`.

## Returns

`Vec<EscalationPath>` where
`EscalationPath { arn, name, entity_type, risky_actions, matched_paths, path: Vec<Hop>, conditional, holders: Vec<Holder>, instance_profiles: Vec<InstanceProfileRef>, trust_principals: Vec<TrustPrincipal>, user_attributes: Option<UserAttributes> }`,
`Hop { arn, entity_type }`, `Holder { arn, name, entity_type, attributes: UserAttributes }`,
`InstanceProfileRef { arn, name }`, `TrustPrincipal { id, principal_type, conditional }`, and
`UserAttributes { user_id, has_mfa, mfa_method: Option<String>, console_login_enabled, password_last_used: Option<String>, last_activity_date: Option<String>, create_date, access_key_count, active_access_key_count, oldest_active_key_date: Option<String>, access_key_ids: Vec<String> }`.
Rust post-processing dedupes by arn (shortest path wins), applies wildcard-aware Deny
suppression via `iam_expander::glob_match`, then evaluates AND-within-group/OR-across-group
matching via `RiskyActionGroups::finalize_actions` on the post-Deny action set — group matching
must run after Deny subtraction, never before, or a Deny-suppressed action could make a group
falsely appear satisfied. Entities that satisfy no group are dropped. `risky_actions` is the
deduplicated union of actions belonging to every matched group; `matched_paths` names the
matched groups (from the user-configurable `config/risky-actions.yaml` — see
`crates/iam-graph/src/queries/risky_actions.rs`). The enrichment queries then run against the
surviving terminal set.

`holders` is populated only when the terminal's `entity_type == "Group"` (member Users via
`MEMBER_OF`); `instance_profiles` and `trust_principals` only when the terminal's
`entity_type == "Role"` (via `CONTAINS_ROLE` and `CAN_ASSUME` respectively); `user_attributes`
only when `arn`'s own `entity_type == "User"`. All are empty/absent otherwise. These, and
`matched_paths`, are exact graph traversals/exact-match evaluations, not glob-match
approximations, so no new `CaveatCode` variant applies to them.

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
