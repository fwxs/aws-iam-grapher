# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Format (must pass before commit)
cargo fmt --all

# Lint (all warnings are errors)
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Unit tests (no Docker required)
cargo test --workspace

# Run a single test by name
cargo test -p iam-graph test_name

# Docker-gated integration tests (Neo4j via testcontainers)
DOCKER_HOST="unix://${HOME}/.colima/default/docker.sock" \
  TESTCONTAINERS_RYUK_DISABLED=true \
  cargo test --workspace -- --ignored
```

All four commands must pass before any task is considered complete.

## Release Process

Every `release/<version>` branch must add a new entry to `CHANGELOG.md` for that version before merging.

## Architecture

Five crates in a Cargo workspace with a strict dependency direction:

```
iam-models  ←  iam-expander
    ↓               ↓
iam-collector  (uses both)
    ↓
iam-graph  (uses iam-collector + iam-models)
    ↓
iam-grapher  (binary, uses all four)
```

**iam-models** — Core IAM entity types (`IamRole`, `IamUser`, `IamPolicy`, `IamGroup`, `IamInstanceProfile`, `PolicyDocument`). No async, no network.

**iam-expander** — Expands wildcard IAM action strings (`s3:*`, `iam:*Group`) to concrete action lists via awsiamactions.io. Results are cached in `~/.cache/iam-expander/`. Falls back gracefully on network errors. Supports trailing wildcards via a trie and interior/suffix wildcards via glob matching (`glob_match`).

**iam-collector** — Three single-account collection modes:
- `LiveCollector` — calls AWS SDK `GetAccountAuthorizationDetails` and `ListInstanceProfiles`
- `OfflineCollector` / `OfflineCollectorBuilder` — parses JSON exports from those same CLI commands
- `HybridCollector` — tries live, prompts for a file on 403

All three call `expand_collected_data(&mut data)` (in `src/expand.rs`) before returning so wildcard expansion is mode-symmetric. Returns `CollectedData` which carries `account_id: Option<String>` derived from entity ARNs (skipping ARNs where the account segment is the literal `"aws"`, which are AWS-managed policies).

`src/org.rs` drives org-wide collection (`collect org`): walks the AWS Organizations OU tree from a management-account profile, assumes `--assume-role-name` into each member account (from `--jump-from-profile` by default, or a per-OU `--ou-profile-override`/`--ou-role-override`), and runs a `LiveCollector` per account. All accounts in a run share one `org_collection_run_id` and carry their OU ancestry. Two identities are kept deliberately separate: the management profile only calls Organizations APIs, never assumes roles; the jump-from profile (or override) only calls `sts:AssumeRole`, never IAM APIs directly — reusing an already-assumed management identity for a second hop is rejected by most jump-role trust policies. Override matching (OU id or display name, innermost-wins on nested overrides, fatal on an unmatched override key) is detailed in `docs/limitations.md`.

**iam-graph** — Two concerns:

*Ingestion* (`src/ingester.rs`): `GraphIngester::ingest()` runs 6 sequential phases:
1. `AwsAccount` + `AwsService` nodes
2. `Snapshot` node (carries `is_partial`, `partial_reasons` derived from `data.warnings`)
3. Entity nodes (Policy, Role, User, Group, InstanceProfile + their inline policies)
4. Permission nodes + `ON_SERVICE` relationships
5. `Snapshot -[:INCLUDES]→` entity relationships
6. Entity relationships: `HAS_ATTACHED_POLICY`, `HAS_INLINE_POLICY`, `GRANTS`, `MEMBER_OF`, `CONTAINS_ROLE`, `CAN_ASSUME`, `BOUNDED_BY`

*Queries* (`src/queries/`): All queries require `QueryContext` (snapshot_id + account_id) for tenant isolation. Key queries:
- `who_can(action, resource)` — returns entities with Allow for the action, excluding those with an explicit Deny; also matches entities holding `Action: "*"` (flagged `is_full_admin: true`). Optional `resource` intersects wildcard (`Action: "*"`) grants against the queried resource via IAM resource-glob semantics
- `privilege_escalation_paths()` — entities with any of 9 risky IAM actions
- `diff_permissions(snap_a, snap_b)` — permission delta between snapshots
- `list_snapshots(account_id)` — returns `SnapshotRecord` including `is_partial` and `partial_reasons`

**iam-grapher** — CLI binary. Subcommands: `collect` (single account), `collect org` (org-wide, see `iam-collector::org` above), `query`, and `docs` (bundled Markdown reference docs — `docs [name]` for `caveats`/`limitations`, `docs queries [name]` for one reference doc per Cypher query in `crates/iam-graph/queries/`, source in `docs/queries/`). Account ID resolution order for `collect`: explicit `--account-id` flag → derived from entity ARNs → fatal error (never silently uses a fallback). `collect`'s `--profile` flag (`live`/`hybrid` only, ignored offline) selects credentials with precedence `--profile` → `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` env vars → the standard AWS credential chain; credentials are resolved once, eagerly, before any IAM call (`iam-collector::credentials`). Both `collect` and `collect org` accept `--output-file <path>` to also write their summary as JSON. AWS API calls are logged via `tracing` at info/debug (`RUST_LOG=iam_collector=debug` for per-page pagination detail).

`query` resolves `--account-id` automatically when omitted: if the graph has exactly one account it's used, otherwise the query runs once per distinct account found (each scoped to its own `(account_id, snapshot_id)`, results never merged). `--snapshot-id` cannot be combined with this multi-account fan-out — pass `--account-id` to target one account when disambiguation is needed. `list-accounts` is the cross-account discovery command and never takes `--account-id`.

## Neo4j Graph Model

Every entity node carries `uid` (`"snapshot_id|arn"`), `snapshot_id`, and `account_id` — all three are required for queries to be correctly scoped. `Permission` nodes carry `action`, `effect` (`"Allow"` or `"Deny"`), `resource`, `snapshot_id`, and `account_id`. The schema (constraints + indexes) is defined in `src/schema.rs` and must be initialized via `GraphClient::initialize_schema()` before ingestion.

## Integration Test Pattern

Tests in `crates/iam-graph/tests/` share one Neo4j container per test binary (four binaries → four containers). The container is started once via `OnceLock<ContainerInfo>` in `helpers.rs`, leaked so it is never dropped, and all tests in the binary connect to it via `shared_client()`. Test isolation is via unique `snapshot_id` per test, not separate containers. All Docker-gated tests require `#[tokio::test(flavor = "multi_thread")]` because `block_in_place` is used inside `init_container()`. Add `#[ignore = "requires Docker"]` to every Docker-gated test.

## Key Constraints

- `account_id` scope: every analysis query filters on both `account_id` and `snapshot_id`. Omitting either causes cross-tenant data leaks. Neo4j Community has one database; isolation is logical only.
- `Action: "*"` (unqualified full-admin) is stored as a literal `Permission` node with `action = "*"`. The `who_can` query has an explicit UNION arm to match it.
- Explicit Deny evaluation subtracts exact-action, wildcard-action (via `iam_expander::glob_match`), and `action = "*"` Denies, including group-inherited Denies and `Deny NotAction` (deny-all-except). The remaining approximation is wildcard-vs-wildcard literal glob comparison (not semantic set containment), and Denies on a group's member users don't suppress a `Group` returned directly. See `docs/limitations.md`.
- `NotAction` statements are fully evaluated via a sentinel + query-time exclusion model (not merely parsed) — an entity with `Allow NotAction: [...]` correctly appears/is absent from `who_can` results. Remaining approximations: the grant's resource scope isn't intersected with `--resource`, and conditions on `NotAction` statements aren't evaluated. See `docs/limitations.md`.
- `query ... --output json` attaches a `caveats` array (closed `CaveatCode` enum: `approximate-deny`, `notaction-not-expanded`, `partial-snapshot`, `expansion-degraded`) to every response, describing which of the above approximations apply to that query and snapshot. Always present, empty when none apply. See `docs/caveats.md`.

## Claude Code Skill

A repo-local, read-only skill lives at `.claude/skills/aws-iam-grapher/` (`SKILL.md` +
`reference.md`), wrapping `query`'s read subcommands only (`who-can`, `entity-perms`,
`instance-profiles-with`, `privilege-escalation`, `org-escalation`, `diff`, `list-snapshots`,
`list-accounts`). It never exposes `delete-snapshot` (no confirmation/dry-run gate in the CLI) or
`collect`/`collect org` (mutates the graph, makes live AWS calls). Keep it in sync with `query.rs`
and the `CaveatCode` enum when either changes — every flag it documents must match the CLI's
actual `--help` output exactly.

The wire shape the skill parses (every query result type, the `caveats` array, and the JSON
error envelope) is snapshot-tested with `insta` in `crates/iam-graph/tests/json_schema_tests.rs`
and the `#[cfg(test)]` modules of `crates/iam-grapher/src/cli/query.rs` and
`crates/iam-grapher/src/output/json.rs`. A failing snapshot means a consumer-visible JSON
contract change — update the skill in the same PR before accepting the new snapshot with
`cargo insta review`.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
