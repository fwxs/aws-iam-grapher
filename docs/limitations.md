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

### Permission Boundaries evaluated as an Allow-intersection ceiling

AWS IAM Permission Boundaries are attached to roles and users and act as a maximum permission ceiling. An entity can only exercise permissions that appear in both its policies and its permission boundary.

**Current behavior:** `who-can` and `entity-perms` intersect each entity's Allow grants against its `BOUNDED_BY` boundary policy's Allow actions (exact, wildcard via `iam_expander::glob_match`, full-admin `*`, and allow-all-except `NotAction`). An entity whose boundary does not also Allow the queried action is excluded from `who-can` and marked `effective: false` in `entity-perms`. Entities without a boundary are unaffected. Results carry `is_bounded` to signal where the ceiling applies.

**Residual approximation:** Boundary-side wildcard matching uses literal glob comparison, not semantic set containment — a grant that is itself a wildcard (e.g. `s3:*`) intersected against a narrower boundary wildcard (e.g. `s3:Get*`) is evaluated as a literal pattern match between the two strings, not as "does the grant's action set fall entirely within the boundary's action set". This mirrors the existing Deny-wildcard approximation (see below) and only affects wildcard-vs-wildcard comparisons; wildcard-vs-concrete-action comparisons (the common case) are exact.

**Not evaluated:** Deny statements *inside* the boundary policy itself (AWS also evaluates these) and `Condition` keys on boundary statements.

### Service Control Policies (SCPs) not supported

AWS Organizations SCPs restrict what IAM entities in member accounts can do, even if the entity's own policies allow the action. An SCP can deny `s3:DeleteBucket` organization-wide regardless of what the IAM policy says.

**V1 behavior:** SCPs are not collected, stored, or evaluated. Queries report permissions from IAM policies only. In accounts governed by Organizations with restrictive SCPs, query results are optimistic — they overstate effective access.

**Workaround:** Retrieve the effective SCP stack via `aws organizations list-policies-for-target` and manually intersect with query output.

### Policy conditions not evaluated

IAM policy statements may include `Condition` keys (e.g., `aws:RequestedRegion`, `aws:MultiFactorAuthPresent`, `s3:prefix`). Conditions restrict when a permission applies.

**V1 behavior:** The `Condition` block is stored as a raw JSON string property on the `Permission` node but is never evaluated. A permission guarded by `"aws:MultiFactorAuthPresent": "true"` is treated as unconditional in all queries.

**Workaround:** After identifying high-risk entities via `who-can` or `privilege-escalation`, check the `Permission.condition` property in Neo4j Browser to determine whether conditions gate access.

### Trust policy evaluation is approximate

`CAN_ASSUME` edges represent that a principal *may* be able to assume a role based on the trust policy structure. A small set of deterministic cases is now evaluated at ingestion time; everything else remains an approximation flagged via `conditional`.

1. **Conditions: a small deterministic subset is evaluated, the rest stays `conditional = true`.** `StringEquals`/`StringEqualsIgnoreCase` on `aws:PrincipalAccount`, checked against a principal that resolves to a single concrete in-account or cross-account ARN, is evaluated: a value consistent with the principal's own account folds the edge to `conditional = false`; a contradictory value suppresses the edge entirely (the statement could never grant assumption). An empty `Condition` block is also treated as unconditional. Every other condition — `sts:ExternalId`, `aws:MultiFactorAuthPresent`, `aws:SourceIp`, date/time checks, tag-based conditions, multi-key/multi-operator blocks, or any condition whose principal account can't be statically resolved (e.g. `Service`/`Federated`/`Wildcard` principals, or multiple principals spanning different accounts) — is left unevaluated and the edge is stored with `conditional = true`. Downstream queries can filter on `conditional` to flag these edges.

2. **`NotPrincipal` exclusions are applied for concrete, resolvable principals.** A trust statement using `Allow NotPrincipal: [...]` no longer produces a `CAN_ASSUME`/`CAN_ASSUME_ROLE` edge *from* any of the listed entities — the over-assertion this section used to describe. Since the exclusion set isn't otherwise resolved to "every other principal in existence," the statement is instead represented as a single `Wildcard`-kind `CAN_ASSUME` edge onto the role, always marked `conditional = true` (the exclusion is structurally honored, but the precise allowed set is still approximate). The `Wildcard` kind never extends a `CAN_ASSUME_ROLE` chain, so it cannot widen transitive privilege-escalation traversal.

3. **Principal kind is read from block key, not inferred from id string.** `{"Service": "ec2.amazonaws.com"}` produces a `Service`-typed `Principal` node; `{"AWS": "arn:...:root"}` produces an `IamEntity`-typed node. The kind accurately reflects the trust policy intent. Unchanged by this work.

**Implication for privilege escalation:** `CAN_ASSUME`/`CAN_ASSUME_ROLE` edges with `conditional = true` may over-report assume-role access for the still-unevaluated condition keys. `privilege_escalation_paths` surfaces a `conditional` flag on each returned path — `true` if any hop in the chain carries an unevaluated runtime condition — so callers can deprioritize uncertain paths without losing them from the results.

### Transitive `sts:AssumeRole` is bounded by `--max-hops`

`privilege-escalation` traverses a `CAN_ASSUME_ROLE` entity-to-entity edge (materialized at ingestion time from the `CAN_ASSUME` trust-policy relationship, for principals that resolve to an in-account Role/User ARN) as a variable-length path of `1..max_hops` hops. If entity X can assume role A, which can assume role B, which can assume role C (which holds `iam:PassRole` or another risky action), the query reports the full chain `X → A → B → C` with the risky action attributed to the terminal entity C.

**`--max-hops` default is 3**, capped at 10. The cap exists because variable-length path matching on a dense `CAN_ASSUME_ROLE` graph grows combinatorially with depth; an unbounded traversal risks a runaway query on large accounts. Chains longer than `--max-hops` are not detected — increase the flag if you suspect deeper chains, at the cost of query time.

Cycles (e.g. A → B → A) are handled by Cypher's default acyclic-relationship semantics for variable-length patterns (a path may not reuse the same relationship instance twice) plus shortest-path deduplication per entity, so a cyclic `CAN_ASSUME_ROLE` graph terminates and each reachable entity is reported once.

**Caveat:** the entity-to-entity bridge is only created when the trust-policy principal is an `AWS` ARN that resolves to a Role or User node already present in the same snapshot (kind `IamEntity`). `Service`, `Federated`, `CanonicalUser`, `Wildcard`, and cross-account `AssumedRole` principals are recorded on the original `CAN_ASSUME` edge (see above) but do not extend the transitive chain — see "Multi-account" in the V2 roadmap.

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

`Deny NotAction` (deny-all-except) is now evaluated: a Deny-NotAction sentinel node
(`action = '*'` Deny with `excluded_actions` set) denies every action except the ones listed.
`who_can` matches it when `$action NOT IN excluded_actions`; `privilege_escalation_paths` drops
a risky action from `allowed_actions` unless it appears in every deny-all-except node's
`excluded_actions` reachable from the terminal entity (own policies and member groups). Both
queries honor Deny-over-Allow precedence: a deny-all-except node suppresses access even when an
`Allow *` (full-admin) or allow-all-except (`NotAction`) grant is also present.

**Remaining approximations:**
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
| Permission Boundaries — Deny statements inside the boundary, and boundary wildcard-vs-wildcard set containment | Extend boundary intersection to evaluate Deny statements and expand wildcards before comparison |
| SCPs | Add `iam-collector` mode that collects SCPs via Organizations API; add `SCP` nodes and `RESTRICTED_BY` relationships |
| Condition evaluation | Parse and partially evaluate common condition keys (`aws:RequestedRegion`, `aws:MultiFactorAuthPresent`, `aws:PrincipalTag`) using a condition evaluator library |
| Multi-account cross-account role chaining | Support cross-account role chaining via `sts:AssumeRole` relationships between accounts in the same collection run |

## Multi-account (AWS Organizations) collection

`collect org` enumerates the OU tree and member accounts from a management-account AWS profile,
assumes a jump role into each member account, runs the same per-account collection as `collect`,
and files each account into its own `Snapshot`. Every snapshot produced by one run shares an
`org_collection_run_id` property, so a single org-wide collection can be queried as a group via
`MATCH (s:Snapshot {org_collection_run_id: $run_id})`.

```bash
aws-iam-grapher collect org \
  --management-profile org-management \
  --assume-role-name OrganizationAccountAccessRole \
  --exclude-ou ou-sandbox-1111 \
  --neo4j-pass "$NEO4J_PASSWORD"
```

**Current behavior:** a single member account's collection failure (e.g. the jump role doesn't
exist, or is denied) is recorded as a warning and does not abort the rest of the run. Each
account is still queried independently — `org_collection_run_id` is metadata for grouping
snapshots, not a cross-account graph; cross-account `sts:AssumeRole` chaining between accounts
in the same org is still future work (see Multi-account cross-account role chaining above).
