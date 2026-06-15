# V1 Limitations

This document describes known analysis limitations of the V1 release. Understanding these boundaries prevents misinterpreting query results.

---

## Neo4j Community Edition Constraints

### Single database

Neo4j Community supports exactly one database per instance. All accounts, all collection runs, and all snapshots coexist in this database. There is no physical isolation between tenants.

**Consequence:** Queries that omit `account_id` and `snapshot_id` filters silently operate across all collected data. The CLI always injects these filters automatically; manual Cypher written in Neo4j Browser must include them explicitly. See [QUERIES.md § 1](../QUERIES.md#1-mandatory-filter-context).

### No role-based access control (RBAC)

Neo4j Community has no database-level user permissions. Any client with the bolt password can read or delete all data. Do not store multi-tenant data from untrusted sources in a shared instance.

### No online backup

Neo4j Community does not include hot backup. To back up the graph, stop the container, copy the data directory, and restart.

### No causal clustering

Neo4j Community is single-node only. For high availability or read replicas, Neo4j Enterprise is required. V1 does not support or test multi-node deployments.

---

## V1 Analysis Limitations

The following IAM constructs are **recorded** in the graph but **not evaluated** when determining effective permissions. Queries may return entities that appear to have access but whose effective access is blocked by one of these mechanisms — or miss entities whose access is granted through them.

### Permission Boundaries not evaluated

AWS IAM Permission Boundaries are attached to roles and users and act as a maximum permission ceiling. An entity can only exercise permissions that appear in both its policies and its permission boundary.

**V1 behavior:** The graph records that a boundary is attached (`has_permission_boundary` property on the node). Queries do NOT intersect policies with the boundary. `who-can` and `entity-perms` results may include actions that are actually denied by the boundary.

**Workaround:** After running a query, check if the returned entity has `has_permission_boundary = true`. Inspect the boundary policy separately.

### Service Control Policies (SCPs) not supported

AWS Organizations SCPs restrict what IAM entities in member accounts can do, even if the entity's own policies allow the action. An SCP can deny `s3:DeleteBucket` organization-wide regardless of what the IAM policy says.

**V1 behavior:** SCPs are not collected, stored, or evaluated. Queries report permissions from IAM policies only. In accounts governed by Organizations with restrictive SCPs, query results are optimistic — they overstate effective access.

**Workaround:** Retrieve the effective SCP stack via `aws organizations list-policies-for-target` and manually intersect with query output.

### Policy conditions not evaluated

IAM policy statements may include `Condition` keys (e.g., `aws:RequestedRegion`, `aws:MultiFactorAuthPresent`, `s3:prefix`). Conditions restrict when a permission applies.

**V1 behavior:** The `Condition` block is stored as a raw JSON string property on the `Permission` node but is never evaluated. A permission guarded by `"aws:MultiFactorAuthPresent": "true"` is treated as unconditional in all queries.

**Workaround:** After identifying high-risk entities via `who-can` or `privilege-escalation`, check the `Permission.condition` property in Neo4j Browser to determine whether conditions gate access.

### Transitive `sts:AssumeRole` limited to 2 levels

Privilege escalation analysis traverses `CAN_ASSUME` relationships. V1 follows at most 2 hops: entity → role-A → role-B. Chains longer than 2 levels are not detected.

**V1 behavior:** If entity X can assume role A, which can assume role B, which can assume role C (which holds admin access), V1 detects X → A → B but does not report X → C.

**Workaround:** Run the `privilege-escalation` query iteratively on the entities it returns to extend the chain manually.

### `NotAction` — implemented as allow-all-except (query-time exclusion)

IAM `NotAction` statements (e.g. `Allow NotAction: ["s3:*"]` — allow everything *except* the
listed actions) are fully supported using a sentinel + query-time exclusion model:

1. **Wildcard expansion:** wildcards *inside* the `NotAction` list (e.g. `s3:*`) are expanded
   to a concrete, wildcard-free list of excluded actions at collection time, exactly like `Action`
   wildcards. The excluded list is bounded (service-scoped); the allowed complement is not
   materialized.

2. **Graph representation:** one `Permission` node is created per resource with `action = '*'` and
   an `excluded_actions` list property carrying the concrete excluded actions. This node is distinct
   from a true full-admin `*` node (its UID encodes the excluded set, preventing collisions).

3. **Query evaluation:** `who_can(action)` matches allow-all-except grants and applies
   `WHERE NOT $action IN excluded_actions` — so an entity with `Allow NotAction: ["s3:*"]` appears
   in `who_can("ec2:DescribeInstances")` (not excluded) and is absent from `who_can("s3:DeleteObject")`
   (excluded). True full-admin nodes (no `excluded_actions`) are unchanged — `coalesce([], [])` makes
   them match every action.

**Remaining approximations:**
- `Deny NotAction` (deny-all-except) is stored but not evaluated in `who_can`; it is treated
  generically like other Deny nodes. This may under-subtract access in rare deny-all-except policies.
- The resource scope of an allow-all-except grant is not intersected with the queried resource
  (same approximation as for full-admin `*` grants — see below).
- Condition evaluation on `NotAction` statements is not implemented (same limitation as all
  permission nodes — see "Policy conditions not evaluated").

### Deny scope is approximate

Explicit Deny subtraction uses action-exact matching. A Deny with a wildcard action
(e.g. `Deny: s3:Delete*`) that covers the queried action does **not** suppress the Allow result
unless the Deny is `action: '*'` (full-admin deny) or exactly matches the queried action string.

Additionally, group-inherited Deny for a user is not evaluated: if a group policy Denies an
action, that Deny does not suppress Allow grants on the user's own policies and vice-versa. The
approximation is conservative — we prefer over-reporting access (false positives for Deny
misses) over under-reporting.

### `Action: "*"` resource scope not intersected

Entities holding `Action: "*"` (full-admin) are returned by `who_can` with `is_full_admin: true`.
The resource scope of the `*` grant is not intersected with the queried resource, so a principal
with `"Action": "*", "Resource": "arn:aws:s3:::my-bucket"` appears in `who_can("s3:DeleteObject")`
even though the grant is bucket-scoped, not object-scoped.

---

## V2 Roadmap

These limitations are targeted for resolution in a future major version:

| Limitation | Planned approach |
|---|---|
| Permission Boundaries | Intersect entity policies with boundary at query time using graph traversal |
| SCPs | Add `iam-collector` mode that collects SCPs via Organizations API; add `SCP` nodes and `RESTRICTED_BY` relationships |
| Condition evaluation | Parse and partially evaluate common condition keys (`aws:RequestedRegion`, `aws:MultiFactorAuthPresent`, `aws:PrincipalTag`) using a condition evaluator library |
| Deep transitive assume-role | Switch `privilege-escalation` to variable-length path queries (`[:CAN_ASSUME*1..]`) with cycle detection |
| Multi-account | Support cross-account role chaining via `sts:AssumeRole` relationships between accounts in the same collection run |
| `Deny NotAction` evaluation | Evaluate deny-all-except statements in `who_can` (currently stored but not subtracted) |
| Wildcard-action Deny | Match Deny actions with IAM glob semantics against queried action to correctly suppress wildcard Deny statements |
