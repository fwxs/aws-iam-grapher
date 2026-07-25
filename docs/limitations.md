# V1 Limitations

This document describes known analysis limitations of the V1 release. Understanding these boundaries prevents misinterpreting query results.

---

## Neo4j Community Edition Constraints

### Single database

**Status:** accepted (won't-fix in V-series). Neo4j Community supports exactly one database per instance; Enterprise's multi-database feature is not in scope.

Neo4j Community supports exactly one database per instance. All accounts, all collection runs, and all snapshots coexist in this database. There is no physical isolation between tenants.

**Consequence:** Queries that omit `account_id` and `snapshot_id` filters silently operate across all collected data. The CLI always injects these filters automatically; manual Cypher written in Neo4j Browser must include them explicitly. See [QUERIES.md § 1](../QUERIES.md#1-mandatory-filter-context).

**Mitigation (logical isolation):** every entity node carries `uid`, `snapshot_id`, and `account_id` (constraints defined in `crates/iam-graph/src/schema.rs`), and every analysis query requires a `QueryContext` (`crates/iam-graph/src/queries/`) that scopes on both. See CLAUDE.md "Key Constraints" for the full guarantee. This is logical isolation only — it does not substitute for physical multi-database separation, so untrusted or adversarial tenants still should not share an instance.

### No role-based access control (RBAC)

**Status:** accepted (won't-fix in V-series). Neo4j Community has no database-level user permissions. Any client with the bolt password can read or delete all data. Do not store multi-tenant data from untrusted sources in a shared instance.

**Mitigation:** this is a deployment-hygiene concern, not an application-code one — network isolation (no public bolt exposure) and secret management for the bolt password are the compensating controls. RBAC itself requires Neo4j Enterprise and will not be added to Community deployments.

### No online backup

Neo4j Community does not include hot backup. To back up the graph, stop the container, copy the data directory, and restart. `scripts/neo4j-backup.sh` and `scripts/neo4j-restore.sh` automate this: they stop the `neo4j` compose service, tar the `aws-iam-grapher_neo4j_data` volume to (or from) a timestamped archive, and restart. Downtime equals the tar copy time — a few seconds for typical dev-sized snapshots. Neither script offers a hot/online path; both require the container to be stopped for the duration of the copy.

### No causal clustering

**Status:** accepted (won't-fix in V-series). Neo4j Community is single-node only. For high availability or read replicas, Neo4j Enterprise is required. V1 does not support or test multi-node deployments. HA/read-replicas remain out of scope for the V-series; there is no planned migration path off Community for this reason alone.

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

### Policy conditions: a small deterministic subset is evaluated, the rest is flagged

IAM policy statements may include `Condition` keys (e.g., `aws:RequestedRegion`, `aws:MultiFactorAuthPresent`, `s3:prefix`, `aws:PrincipalTag/*`). Conditions restrict when a permission applies. Full evaluation is undecidable without runtime request context, so only a fixed, documented subset is evaluated.

**V1 behavior:** The `Condition` block is stored as a JSON string on `Permission.condition` (`iam-graph/src/nodes/permission.rs`). `who-can` evaluates it via `iam_models::condition::evaluate` (`crates/iam-models/src/condition.rs`) against an optional `ConditionContext` built from CLI flags:

| Condition key | Operators evaluated | CLI flag |
|---|---|---|
| `aws:MultiFactorAuthPresent` | `Bool` | `--mfa <true\|false>` |
| `aws:RequestedRegion` | `StringEquals`, `StringLike` | `--region <name>` |
| `aws:PrincipalTag/<key>` | `StringEquals`, `StringLike` | `--principal-tag <key>=<value>` (repeatable) |

For each grant: if a supported key/operator pair has a matching context value and evaluates false, the grant is **excluded** from results (e.g. `--mfa false` drops a grant gated by `aws:MultiFactorAuthPresent: true`). If every supported key evaluates true but the grant carries any other key/operator (or a supported key has no matching context value), the grant is kept but the entity is returned with `conditional: true` and `unevaluated_condition_keys` listing what wasn't evaluated. **Unevaluated conditions are never silently treated as unconditional** — they always surface as `conditional`.

**Not evaluated:** any key/operator outside the table above (e.g. `s3:prefix`, `aws:SourceIp`, `sts:ExternalId`, date/time checks), and conditions on `entity-perms` / `instance-profiles-with` (only `who-can` evaluates and flags conditions in V1).

**Dedup approximation:** when the same entity has multiple grants for a queried action, `conditional` is true only if *every* surviving grant is conditional — an additional unconditional grant makes the entity's access unconditional overall. See `who_can()` in `crates/iam-graph/src/queries/analysis.rs`.

**Relationship to trust-policy conditions:** trust policy (`AssumeRole`) conditions are evaluated separately by `classify_trust_condition` (`crates/iam-graph/src/ingester.rs`), which understands only `StringEquals`/`StringEqualsIgnoreCase` on `aws:PrincipalAccount` — see "Trust policy evaluation is approximate" below. The two evaluators are not yet unified; a follow-up should consolidate trust-condition evaluation onto `iam_models::condition::evaluate`.

**Workaround for unevaluated keys:** check the `unevaluated_condition_keys` field on `who-can` results (or `Permission.condition` directly in Neo4j Browser) to determine whether a flagged grant is actually gated in practice.

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

### User MFA, console login, and last-activity attributes are live-collection-only

`IamUser` carries `has_mfa`, `mfa_method`, `console_login_enabled`, and `last_activity_date`,
populated by a per-user enrichment pass (`ListMFADevices`, `GetLoginProfile`, `GetUser`,
`ListAccessKeys` + `GetAccessKeyLastUsed`) in `LiveCollector`. `HybridCollector` inherits this
since it delegates to `LiveCollector` for the live path.

**`OfflineCollector` does not populate these fields** — `GetAccountAuthorizationDetails` and
`ListInstanceProfiles` (its only inputs) carry none of this data. Offline snapshots always default
them (`has_mfa: false`, `mfa_method: None`, `console_login_enabled: false`,
`last_activity_date: None`) and are marked partial via
`CollectorWarning::UserSecurityAttributesNotCollected`. Do not treat `has_mfa: false` on a snapshot
ingested from an offline collection as evidence a user actually lacks MFA — check
`Snapshot.partial_reasons` first.

**Per-user call failures are non-fatal** — a 403 on `ListMFADevices`, `GetLoginProfile`, or the
access-key calls for one user does not fail the whole collection; it is folded into an
account-wide `CollectorWarning` (`MfaDevicesMissing`, `LoginProfileMissing`,
`AccessKeyActivityMissing`) and the affected fields default for that user. A `GetLoginProfile`
`NoSuchEntity` response is not an error — it means the user has no console login profile
(`console_login_enabled: false`) and is not reported as a warning.

### Validated scale ceiling

The ingestion pipeline has been load-tested against a synthetic account of:

- **200 managed policies** × 10 statements × 8 concrete actions × 2 resources
- **50 roles** each with one inline policy of the same shape
- **~16 unique permission nodes** after uid-based deduplication (all policies share the same 8 actions × 2 resources)

The UNWIND bulk-merge strategy (500-row batches, Phase 4) processes this load in **under 30 seconds** on a local Neo4j container (single-core colima VM, 2 GB RAM).

**Practical ceiling for a single snapshot:** ~10,000 unique permission nodes ingested comfortably in under 2 minutes. Beyond this, Neo4j Community write latency dominates; consider sharding by account or increasing `batch_size` in `IngestConfig`.

**Tuning `--batch-size`:** every `collect` subcommand exposes `--batch-size` (default 500), which sets `IngestConfig.batch_size` and controls how many Cypher rows are UNWOUND per transaction in `GraphIngester::execute_batch`. Larger batches reduce transaction overhead but hold more of the write in memory and in a single commit; smaller batches trade throughput for finer-grained failure recovery. Start from the default and increase in steps (e.g. 1000, 2000) while watching ingest wall-clock time — gains flatten once Neo4j's write path, not batching, is the bottleneck.

**Sharding by account:** since every node and query is already scoped by `account_id` + `snapshot_id`, an account whose permission-node count approaches the ceiling can be collected into a **separate Neo4j instance** (its own `docker compose` project / data volume) rather than sharing one instance with other accounts. This keeps any single instance under the validated ceiling without code changes — `iam-grapher` already takes `--neo4j-uri` per invocation, so pointing different accounts at different instances is a deployment choice, not a schema change.

To reproduce the benchmark: run the Docker-gated benchmark test:
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

`--management-profile` is used only for Organizations discovery (enumerating OUs and accounts).
The `sts:AssumeRole` call into each member account's jump role always originates from
`--jump-from-profile` instead (or, if omitted, the standard AWS credential chain —
`AWS_PROFILE` / the `default` profile). These are kept separate on purpose: if
`--management-profile` itself resolves to an assumed role (an SSO profile, or one with
`role_arn`/`source_profile` chaining), reusing its credentials to call `AssumeRole` again would
be a double-hop assumption that most jump-role trust policies reject with `AccessDenied`.

`--jump-from-profile` is commonly just a set of static/base credentials with no `region` of its
own — its only purpose is calling `sts:AssumeRole`. If it (or the default profile/env, when the
flag is omitted) has no region configured, its region falls back to `--management-profile`'s
region, then to `us-east-1`, so the jump-role assumption never fails with a
`ResolveEndpointError("Missing Region")` dispatch error.

`--region` (repeatable, both on `collect` and `collect org`) overrides that resolution
explicitly: its first value is used for every AWS SDK call the running command makes,
regardless of what the profile(s) configure. Omit it to use the profile-resolved region (falling
back to `us-east-1` as above).

```bash
aws-iam-grapher collect org \
  --management-profile org-management \
  --jump-from-profile default \
  --region us-east-1 \
  --assume-role-name OrganizationAccountAccessRole \
  --exclude-ou-id ou-sandbox-1111 \
  --exclude-ou-name Legacy \
  --neo4j-pass "$NEO4J_PASSWORD"
```

`--exclude-ou-id` and `--exclude-ou-name` (both repeatable) prune matching OU subtrees before
account enumeration — `--exclude-ou-id` matches the OU's id exactly, `--exclude-ou-name` matches
its display name exactly. Either one excludes the OU and all its descendants (nested OUs and
accounts).

**Current behavior:** a single member account's collection failure (e.g. the jump role doesn't
exist, or is denied) is recorded as a warning and does not abort the rest of the run. Each
account is still queried independently — `org_collection_run_id` is metadata for grouping
snapshots, not a cross-account graph; cross-account `sts:AssumeRole` chaining between accounts
in the same org is still future work (see Multi-account cross-account role chaining above).

`--exclude-ou-id` matches only against OU ids, `--exclude-ou-name` only against OU display names —
each only against values actually encountered while walking the tree from the enumerated roots.
If a value passed to either flag never matches — a typo, an id/name swap, or a value from the
wrong organization — it is reported as a warning (`--exclude-ou-id <id> did not match any
organizational unit ...` / `--exclude-ou-name <name> did not match any organizational unit's
display name ...`) instead of being silently ignored, so a misconfigured exclusion doesn't look
identical to "nothing needed excluding."

### Scoping collection to named OUs (`--include-ou-name`)

`--exclude-ou-*` is opt-**out**: everything is collected except pruned subtrees. `--include-ou-name
<name>` (repeatable) is the opt-**in** counterpart — when given at least once, only accounts under
an OU whose display name matches one of the given values (or any of its descendant OUs) are
collected; every other account is skipped:

```bash
aws-iam-grapher collect org \
  --management-profile org-management \
  --jump-from-profile default \
  --assume-role-name OrganizationAccountAccessRole \
  --include-ou-name Prod \
  --neo4j-pass "$NEO4J_PASSWORD"
```

Omitting `--include-ou-name` collects the full org tree as usual. Repeating it ORs the filter
across multiple named OUs. It combines with `--exclude-ou-id`/`--exclude-ou-name`: an OU excluded
by id or name is still pruned even if it also matches an `--include-ou-name` value — exclude wins.

**OU names are not guaranteed unique across an organization** — two sibling OUs under different
parents can share a name. `--include-ou-name` matches **any** OU in the tree with that name, not a
single unambiguous path. Prefer `--exclude-ou-id` (id-based, unambiguous) when precision matters.
Like the other OU flags, an `--include-ou-name` value that never matches any OU encountered while
walking the tree is reported as a warning, not silently ignored.

### Mixed-authentication orgs (`--ou-profile-override`)

Some organizations are not authentication-homogeneous: most accounts assume the jump role from
`--jump-from-profile`, but a subset — often quarantined into their own OU for exactly this reason
— must assume it from a *different* source identity (e.g. a separate set of long-lived static
credentials, or its own SSO profile) instead. `--ou-profile-override <ou_id_or_name>=<aws_profile>`
(repeatable) makes accounts under a matching OU, and all its descendant OUs, assume
`--assume-role-name` from the named local profile instead of `--jump-from-profile` — every account,
from both paths, still calls `sts:AssumeRole` into the same role name and is filed into the same
`org_collection_run_id`:

```bash
aws-iam-grapher collect org \
  --management-profile org-management \
  --jump-from-profile default \
  --assume-role-name OrganizationAccountAccessRole \
  --ou-profile-override Quarantine=legacy-static-creds \
  --ou-profile-override ThirdParty=vendor-keys \
  --neo4j-pass "$NEO4J_PASSWORD"
```

This is not a way to bypass assume-role entirely — the named profile is only ever used to call
`sts:AssumeRole`, exactly like `--jump-from-profile` is, just scoped to that OU subtree instead of
the whole run. It does **not** collect the profile's own account directly, and the profile itself
does not need `iam:GetAccountAuthorizationDetails` — only permission to assume
`--assume-role-name` in each account under the matching OU.

Matching mirrors `--exclude-ou-id`/`--exclude-ou-name`: the key is checked against both the OU's
id and its display name. When nested overridden OUs disagree, the innermost (nearest ancestor)
override wins for a given account. Unlike `--exclude-ou-*`, an override key that never matches
any OU encountered while walking the tree is a **fatal** validation error — collection is aborted
before any account is touched, rather than proceeding as if the override had no effect. Likewise,
an override's local profile must resolve real credentials before collection starts; an unresolvable
profile also fails fast with a validation error.

### Role-heterogeneous orgs (`--ou-role-override`)

Some orgs don't use the same cross-account role name everywhere — a legacy or acquired subtree
exposes it under a different name than `--assume-role-name`. `--ou-role-override
<ou_id_or_name>=<role_name>` (repeatable) assumes `<role_name>` instead of `--assume-role-name` in
every account under a matching OU and its descendants; everything else (source identity, region,
run id) is unchanged. It is independent of `--ou-profile-override` — one changes the target role
name, the other the source identity — and both may apply to the same OU and compose.

```bash
aws-iam-grapher collect org \
  --management-profile org-management \
  --jump-from-profile default \
  --assume-role-name OrganizationAccountAccessRole \
  --ou-role-override LegacyAcquisition=CrossAccountAuditRole \
  --neo4j-pass "$NEO4J_PASSWORD"
```

Matching, inheritance, and the fatal-unmatched-key behavior are the same as
`--ou-profile-override` above, with three deviations:

- **`--exclude-ou-*` short-circuits before role-override resolution.** A key that matches only an
  OU that was itself excluded is reported as a *shadowed-by-exclude* warning, not the fatal
  unmatched-key error — the exclusion is assumed deliberate.
- **When one OU is matched by both an id-keyed and a name-keyed entry** with different role
  names, the id-keyed value wins.
- **Duplicate identical keys use last-value-wins** (the more common CLI convention), not the
  first-value-wins used by `--ou-profile-override` — a deliberate divergence, noted here since the
  two flags otherwise behave symmetrically.

The role name is validated at parse time (non-empty, no ARN/path fragments or whitespace) so a
malformed value is rejected before any AWS call rather than surfacing as an opaque per-account
`AssumeRole` failure deep in the walk.

### Bounded-concurrency account collection (`--concurrency`)

Member accounts are collected with bounded concurrency (`--concurrency`, default 4, clamped to
`[1, 16]`) instead of strictly one at a time — wall clock for an N-account org is `≈ N/concurrency`
rather than `Σ(per-account time)`. The default is conservative deliberately: the limiting factor
is AWS-side per-account IAM throttling (mitigated by the SDK's built-in adaptive retry) and the
jump-role STS trust setup, not local CPU. A single account's collection failure is still recorded
as a `CollectorWarning::PartialData` and does not abort the run, identical to the pre-concurrency
behavior. Because accounts complete out of order under concurrency, `OrgCollectionResult.accounts`
is explicitly sorted by account id before being returned, so downstream output and ingestion order
stay deterministic regardless of `--concurrency` or network timing.
