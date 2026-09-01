# org_escalation_paths

## Purpose

Cross-account privilege-escalation paths across one org collection run. Traverses
`CAN_ASSUME_ROLE` edges (including cross-account edges materialized by the stitch pass) to
find entities that can reach a configured risky-action group by assuming roles across account
boundaries. Only transitive paths (1..N hops) are returned; run
[`privilege_escalation_paths`](privilege-escalation-paths.md) per-account for the zero-hop
(direct) case.

## Parameters

- `$org_run_id` — org collection run id shared across all per-account snapshots
- `$risky_actions` — flat, deduplicated union of every action across every configured
  risky-action group. Filters which `Permission` actions are pulled back (via the `GRANTS`
  edge); AND/OR group semantics are evaluated in Rust afterward, post-Deny-subtraction. See
  [`privilege_escalation_paths`](privilege-escalation-paths.md) for the full explanation.
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
                -[:GRANTS {effect: 'Allow', snapshot_id: terminal.snapshot_id}]->(perm:Permission)
WHERE perm.action IN $risky_actions
WITH start, p, terminal, collect(DISTINCT perm.action) AS direct_allowed_actions
OPTIONAL MATCH (terminal)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(dpol)
               -[dg:GRANTS {effect: 'Deny', snapshot_id: terminal.snapshot_id}]->(deny:Permission)
WHERE dg.excluded_actions IS NULL
WITH start, p, terminal, direct_allowed_actions, collect(DISTINCT deny.action) AS own_deny_actions
OPTIONAL MATCH (terminal)-[:MEMBER_OF]->(:Group)
               -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(gdpol)
               -[gdg:GRANTS {effect: 'Deny', snapshot_id: terminal.snapshot_id}]->(gdeny:Permission)
WHERE gdg.excluded_actions IS NULL
WITH start, p, terminal, direct_allowed_actions, own_deny_actions,
     collect(DISTINCT gdeny.action) AS group_deny_actions
WITH start, p, terminal,
     [a IN direct_allowed_actions WHERE
        NOT EXISTS {
            MATCH (terminal)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(dnpol)
                  -[dng:GRANTS {effect: 'Deny', snapshot_id: terminal.snapshot_id}]
                    ->(:Permission {action: '*'})
            WHERE dng.excluded_actions IS NOT NULL AND NOT a IN dng.excluded_actions
        }
        AND NOT EXISTS {
            MATCH (terminal)-[:MEMBER_OF]->(:Group)
                  -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(gdnpol)
                  -[gdng:GRANTS {effect: 'Deny', snapshot_id: terminal.snapshot_id}]
                    ->(:Permission {action: '*'})
            WHERE gdng.excluded_actions IS NOT NULL
              AND NOT a IN gdng.excluded_actions
        }
     ] AS allowed_actions,
     own_deny_actions, group_deny_actions
RETURN start.arn AS arn, start.name AS name, labels(start)[0] AS entity_type,
       start.account_id AS account_id,
       allowed_actions, own_deny_actions + group_deny_actions AS deny_actions,
       [n IN nodes(p) | {arn: n.arn, entity_type: labels(n)[0], account_id: n.account_id,
                          snapshot_id: n.snapshot_id}] AS path,
       any(rel IN relationships(p) WHERE rel.conditional) AS conditional
```

After the path-finding query above and its Rust-side dedup/risky-action filtering, three
further batched enrichment queries run once per call, keyed on `(arn, snapshot_id)` pairs for
the deduped set of terminal (permission-holding) hops — `path.last()`, not the top-level
`arn`. Org terminals may belong to different account snapshots within the same org run, so
each pair carries its own `snapshot_id` rather than one bound parameter:

```cypher
-- org_escalation_holders.cypher (Group terminals only) — also returns the holder's own
-- User node properties as `attributes` (see below)
UNWIND $pairs AS pair
MATCH (g:Group {arn: pair.arn, snapshot_id: pair.snapshot_id})
MATCH (u:User)-[:MEMBER_OF]->(g)
RETURN pair.arn AS terminal_arn, u.arn AS arn, u.name AS name, labels(u)[0] AS entity_type,
       u.user_id AS user_id, u.has_mfa AS has_mfa, u.mfa_method AS mfa_method,
       u.console_login_enabled AS console_login_enabled,
       u.password_last_used AS password_last_used,
       u.last_activity_date AS last_activity_date, u.create_date AS create_date,
       u.access_key_count AS access_key_count,
       u.active_access_key_count AS active_access_key_count,
       u.oldest_active_key_date AS oldest_active_key_date,
       u.access_key_ids AS access_key_ids

-- org_escalation_instance_profiles.cypher (Role terminals only)
UNWIND $pairs AS pair
MATCH (r:Role {arn: pair.arn, snapshot_id: pair.snapshot_id})
MATCH (ip:InstanceProfile)-[:CONTAINS_ROLE]->(r)
RETURN pair.arn AS terminal_arn, ip.arn AS arn, ip.name AS name

-- org_escalation_trust_principals.cypher (Role terminals only)
UNWIND $pairs AS pair
MATCH (r:Role {arn: pair.arn, snapshot_id: pair.snapshot_id})
MATCH (pr:Principal)-[rel:CAN_ASSUME]->(r)
RETURN pair.arn AS terminal_arn, pr.id AS id, pr.type AS principal_type, rel.conditional AS conditional

-- org_escalation_user_attributes.cypher (User entities only) — keyed on the escalating
-- entity's own (arn, snapshot_id), NOT the terminal
UNWIND $pairs AS pair
MATCH (u:User {arn: pair.arn, snapshot_id: pair.snapshot_id})
RETURN pair.arn AS entity_arn, u.user_id AS user_id, u.has_mfa AS has_mfa,
       u.mfa_method AS mfa_method, u.console_login_enabled AS console_login_enabled,
       u.password_last_used AS password_last_used,
       u.last_activity_date AS last_activity_date, u.create_date AS create_date,
       u.access_key_count AS access_key_count,
       u.active_access_key_count AS active_access_key_count,
       u.oldest_active_key_date AS oldest_active_key_date,
       u.access_key_ids AS access_key_ids

-- org_escalation_user_associations.cypher (User entities only) — keyed on the escalating
-- entity's own (arn, snapshot_id), NOT the terminal. Same three UNION arms and
-- permission-verified CAN_ASSUME_ROLE predicate as escalation_user_associations.cypher — see
-- privilege-escalation-paths.md — with snapshot_id taken from pair.snapshot_id and no
-- account_id filter, since org terminals can belong to a different account snapshot.
UNWIND $pairs AS pair
MATCH (u:User {arn: pair.arn, snapshot_id: pair.snapshot_id})
MATCH (u)-[car:CAN_ASSUME_ROLE]->(role:Role)
WHERE (
    EXISTS { ... sts:AssumeRole grant on own policies, resource = role.arn OR '*' ... }
    OR EXISTS { ... same, via MEMBER_OF group policies ... }
  )
RETURN pair.arn AS entity_arn, role.arn AS arn, role.name AS name, labels(role)[0] AS entity_type,
       'CAN_ASSUME_ROLE' AS relationship, /* conditional, see stitch_cross_account.cypher */ ...

UNION
-- ...HAS_ATTACHED_POLICY_OR_INLINE arm (own attached/inline policies, conditional=false)
UNION
-- ...MEMBER_OF arm (own group memberships, conditional=false)
```

Each is skipped entirely (no round trip) when its terminal batch is empty.

## Rust binding

`crates/iam-graph/src/queries/org_escalation.rs` — `ORG_ESCALATION_QUERY`, used in
`org_escalation_paths(graph: &Graph, ctx: &OrgQueryContext, max_hops: u32, groups: &RiskyActionGroups) -> Result<Vec<OrgEscalationPath>, GraphError>`.
Uses `render_hop_bound(ORG_ESCALATION_QUERY, max_hops)` to interpolate `{max_hops}`; bound
parameters are `$org_run_id` and `$risky_actions` (`groups.all_actions()`). Enrichment queries
live in `crates/iam-graph/src/queries/escalation_enrichment.rs` (`fetch_org_holders`,
`fetch_org_instance_profiles`, `fetch_org_trust_principals`, `fetch_org_user_attributes`,
`fetch_org_user_associations`), shared with `escalation.rs`. `iam-grapher`'s
`query org-escalation` subcommand applies an
additional `--entity-type <user|role|group|all>` filter in Rust, after this query returns —
see `crates/iam-grapher/src/cli/query.rs::filter_by_entity_type`.

## Returns

`Vec<OrgEscalationPath>` where
`OrgEscalationPath { arn, name, entity_type, account_id, risky_actions, matched_paths, path: Vec<OrgHop>, conditional, holders: Vec<Holder>, instance_profiles: Vec<InstanceProfileRef>, trust_principals: Vec<TrustPrincipal>, user_attributes: Option<UserAttributes>, associations: Vec<UserAssociation> }`
and `OrgHop { arn, entity_type, account_id, snapshot_id }` — `OrgHop` carries `account_id` and
`snapshot_id` per node so a caller can render the cross-account path and enrichment queries
can resolve each hop against its own snapshot. `Holder`/`UserAttributes`/`UserAssociation` are
the same shapes used by `escalation.rs` — see `privilege-escalation-paths.md`. Rust
post-processing dedupes by
arn keeping the shortest path, applies wildcard Deny suppression via
`iam_expander::glob_match`, then evaluates AND-within-group/OR-across-group matching via
`RiskyActionGroups::finalize_actions` on the post-Deny action set — this must happen after
Deny subtraction, never before (see `RiskyActionGroups::finalize_actions`'s doc comment) — and
drops entities that satisfy no group. `risky_actions` is the deduplicated union of actions
belonging to every matched group; `matched_paths` names the matched groups. The enrichment
queries then run against the surviving terminal set.

`holders` is populated only when the terminal's `entity_type == "Group"`;
`instance_profiles`/`trust_principals` only when `entity_type == "Role"`; `user_attributes`
and `associations` only when `arn`'s own `entity_type == "User"`. All are empty/absent
otherwise. These, and `matched_paths`, are exact graph traversals/exact-match evaluations, not
glob-match approximations, so no new `CaveatCode` variant applies to them. See
[`privilege_escalation_paths`](privilege-escalation-paths.md) for the `associations`
permission-verified `CAN_ASSUME_ROLE` semantics — identical here, scoped by
`pair.snapshot_id` instead of a single bound snapshot.

## Notes

Terminal risky-action filtering, Deny suppression, and deny-all-except evaluation mirror the
single-account [`privilege_escalation_paths`](privilege-escalation-paths.md) query, but here
`snapshot_id` is taken from `terminal.snapshot_id` rather than a parameter, since a path can
cross snapshots belonging to different accounts within the same org run. `Permission` is a
global, action-keyed node — every `effect`/`excluded_actions`/`snapshot_id` filter above binds
to the `GRANTS` relationship, not the node.
