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

### Trust policy evaluation is approximate

`CAN_ASSUME` edges represent that a principal *may* be able to assume a role based on the trust policy structure. Three approximations apply at the single-hop level:

1. **Conditions are recorded but not evaluated.** When a trust policy statement carries a `Condition` block (e.g. `sts:ExternalId`, `aws:MultiFactorAuthPresent`), the `CAN_ASSUME` relationship is stored with `conditional = true`. The condition is *not* evaluated — the edge is asserted even if the condition would block assumption at runtime. Downstream queries can filter on `conditional` to flag these edges.

2. **`NotPrincipal` is recorded but not evaluated.** A trust policy statement using `NotPrincipal` (allow all principals *except* the listed ones) is parsed; the resulting `CAN_ASSUME` edge is marked `conditional = true`. The exclusion logic is not applied — entities listed under `NotPrincipal` may appear as able to assume the role when in fact they are blocked.

3. **Principal kind is read from block key, not inferred from id string.** `{"Service": "ec2.amazonaws.com"}` produces a `Service`-typed `Principal` node; `{"AWS": "arn:...:root"}` produces an `IamEntity`-typed node. The kind accurately reflects the trust policy intent.

**Implication for privilege escalation:** `CAN_ASSUME` edges with `conditional = true` may over-report assume-role access. An entity returned by `privilege_escalation_paths` should be checked for conditional edges before treating the path as exploitable.

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
- `Deny NotAction` (deny-all-except): the node is stored in the graph but the deny-all-except
  semantic is not evaluated. `who_can` and `privilege_escalation_paths` only subtract Deny nodes
  where `action` is an exact match or a true full-admin `*` (i.e. `excluded_actions IS NULL`).
  A `Deny NotAction: ["s3:GetObject"]` would not suppress any action — the denied complement
  is not computed. This may over-report access in the rare deny-all-except pattern.
- The resource scope of an allow-all-except grant is not intersected with the queried resource
  (same approximation as for full-admin `*` grants — see below).
- Condition evaluation on `NotAction` statements is not implemented (same limitation as all
  permission nodes — see "Policy conditions not evaluated").

### Deny scope is approximate

Explicit Deny subtraction matches Deny actions against the queried/risky action using IAM glob
semantics (`iam_expander::glob_match`, reusing the same matcher as wildcard `Action` expansion).
A Deny with a wildcard action (e.g. `Deny: s3:Delete*`) now correctly suppresses an Allow for
`s3:DeleteObject`, as does an exact match or a true full-admin Deny (`action: '*'`).

Group-inherited Deny is evaluated: a user's effective Deny set is the union of Deny permissions
on its own policies and on every group it is `MEMBER_OF`. A Deny from either side suppresses the
user's Allow, in `who_can` and `privilege_escalation_paths` alike.

**Remaining approximations:**
- `Deny NotAction` (deny-all-except) is still not evaluated — see "`NotAction` — implemented as
  allow-all-except" above. Deny-NotAction sentinel nodes (`action = '*'` with `excluded_actions`
  set) are excluded from Deny matching entirely.
- Group results themselves (a `Group` returned directly as `who_can`'s `e`) are not suppressed by
  a Deny on one of their member users — groups are not IAM principals that take action, so this
  is out of scope.

### `Action: "*"` resource scope intersection (`--resource`)

`who_can` accepts an optional `--resource <arn>`. When supplied, it intersects the queried
resource against the `Resource` of wildcard (`Action: "*"`) grants — both true full-admin and
`NotAction` allow-all-except nodes — using IAM resource-glob semantics (`iam_expander::glob_match`,
reused from action-glob matching). A grant whose resource doesn't cover the queried resource is
excluded: a principal with `"Action": "*", "Resource": "arn:aws:s3:::my-bucket"` is excluded from
`who_can("s3:DeleteObject", resource="arn:aws:s3:::my-bucket/object")` (bucket-scoped, not
object-scoped) but included for `who_can("s3:ListBucket", resource="arn:aws:s3:::my-bucket")`.

Exact-action grants (arms 1/2 — direct policy grant and group-derived grant) are **not** filtered
by `--resource`; their `resource` is only surfaced in the output for callers to post-filter
themselves. When `--resource` is omitted, behavior is unchanged from before and every result now
also carries the matched grant's `resource`.

Caveat: `iam_expander::glob_match` lowercases both sides before comparing (it was written for
case-insensitive IAM action matching). ARN resource segments (bucket names, object keys) are
case-sensitive in real AWS, so a queried resource that differs from the grant only by case will
incorrectly be treated as a match. This is a known limitation of reusing the action-glob matcher
for resources.

When an entity has multiple wildcard grants across different resources, only one resulting
`resource` value is surfaced per entity (the first one Rust-side dedup encounters) — `who_can`
already deduplicates by ARN, collapsing multiple matching grants into a single row.

### Validated scale ceiling

The ingestion pipeline has been load-tested against a synthetic account of:

- **200 managed policies** × 10 statements × 8 concrete actions × 2 resources
- **50 roles** each with one inline policy of the same shape
- **~16 unique permission nodes** after uid-based deduplication (all policies share the same 8 actions × 2 resources)

The UNWIND bulk-merge strategy (500-row batches, Phase 4) processes this load in **under 30 seconds** on a local Neo4j container (single-core colima VM, 2 GB RAM).

**Practical ceiling for a single snapshot:** ~10,000 unique permission nodes ingested comfortably in under 2 minutes. Beyond this, Neo4j Community write latency dominates; consider sharding by account or increasing `batch_size` in `IngestConfig`.

To reproduce: run the Docker-gated benchmark test:
```bash
DOCKER_HOST="unix://${HOME}/.colima/default/docker.sock" \
  TESTCONTAINERS_RYUK_DISABLED=true \
  cargo test -p iam-graph -- --ignored ingest_large_synthetic_account_records_scale_ceiling --nocapture
```

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
