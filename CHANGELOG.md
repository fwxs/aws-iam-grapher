# Changelog

All notable changes to this project are documented here.

## [0.6.0] - 2026-08-24

Configurable privilege-escalation detection.

- **User-configurable risky-action groups**: the privilege-escalation risky-action list moves from a hardcoded 9-action Cypher array to `config/risky-actions.yaml`, resolved via `--risky-actions <path>` or the installed `~/.aws-iam-grapher/config/risky-actions.yaml` (fatal if neither is found; no repo-checkout fallback). Detection upgrades from "holds any of 9 actions" to named techniques with **AND-within-group, OR-across-group** matching, letting operators express multi-action escalation combos (e.g. `iam:CreatePolicyVersion` + `iam:SetDefaultPolicyVersion` together) instead of reporting each action independently. New `config check [path]` subcommand validates a config and reports every problem found. `scripts/install.sh` installs the default config and never overwrites an existing one. `privilege-escalation`/`org-escalation` results gain a `matched_paths` field naming the satisfied groups.
  - **Behavior-preserving by default**: the shipped `config/risky-actions.yaml` reproduces the previous 9-action list as 9 single-action groups, so results with the installed default are unchanged. This is a breaking change only for operators who edit the config to add multi-action groups — until then, result sets are identical to 0.5.0.

## [0.5.0] - 2026-08-15

Output, performance, and refactor-focused release.

- **Graphviz output**: new DOT-format output option for `who-can`, `privilege-escalation`, and `org-escalation` query results.
- **`--profile` flag**: `collect` gains a `--profile` flag for selecting AWS credentials, threaded through the collector and org path, with profile-binding fixes and parser tests.
- **Performance**: `glob_match` rewritten to be allocation-free and non-exponential (applied identically in both `iam-expander` and `iam-models`); expander skips a full wildcard-catalog refetch when the on-disk cache is still fresh; query snapshot-scope resolution now happens once instead of via duplicate `list_snapshots` calls.
- **Cache-sharing tier refactor**: CLI binary migrated to a shared cache tier; cache gained a dirty flag to skip unnecessary flushes; per-call wrapper functions dropped from the expander in favor of the shared tier; cache flushed before error-exit paths.
- **Query code cleanup**: shared `col`/`col_or_default` row-helper functions introduced and applied across snapshots, accounts, escalation, org-escalation, and analysis queries, with tests asserting column names on malformed rows; `col_or_default` later dropped in favor of hard errors; scoped query commands deduplicated; single-account mode now keyed off `--account-id` directly.
- **Misc**: new `RenderSpec` table output type; fixed how risky actions are merged for the privilege-escalation check; added local `graphify` knowledge-graph config; routine dependency bumps (serde_json, async-trait, serde, futures, aws-sdk-organizations, tokio, anyhow, thiserror, quinn-proto, aws-smithy-runtime-api, clap).

## [0.4.0] - 2026-07-18

Org-collection filtering and user-attribute additions.

- New `--include-ou-name` flag (with underlying collector support) to filter org-wide collection to specific OUs by name, including review-driven fixes and limitations docs.
- New per-OU AWS profile override (`--ou-profile-override`) for org collection, also with review fixes and docs.
- `IamUser` model gains MFA, console-login, and last-activity attributes.
- Routine dependency bumps (aws-sdk-iam, tokio, clap, uuid, aws-sdk-organizations, aws-config, aws-smithy-runtime-api, aws-smithy-mocks); CI path-filter fix to match nested `Cargo.toml` files.

## [0.3.0] - 2026-07-10

Large feature release.

- **Condition evaluation**: new condition evaluator for IAM policy statements, CLI flags to filter by condition, MFA-specific condition test cases, and docs covering condition evaluation semantics.
- **Permission boundaries**: `query` now evaluates permission boundaries when resolving effective permissions.
- **Deny evaluation hardening**: evaluates `Deny NotAction` (deny-all-except) in `who_can` and privilege-escalation queries, plus deterministic trust-policy condition and `NotPrincipal` exclusion in trust evaluation; fixed a Cypher type error surfaced by the new deny-all-except logic.
- **Org-wide collection**: new `collect org` subcommand — walks the AWS Organizations OU tree, assumes roles per member account, tags all accounts from one run with a shared `org_collection_run_id`; new cross-account stitch pass and org-scoped privilege-escalation query (`org-escalation` CLI subcommand) with cross-account escalation tests; `--exclude-ou`/`--exclude-ou-name` id/name split, with a warning when an `--exclude-ou` matches no OU.
- **Cross-account query UX**: new `list-accounts` subcommand; `query` now runs across all accounts automatically when `--account-id` is omitted.
- **Deep escalation paths**: privilege-escalation detection now follows transitive `sts:AssumeRole` chains, and intersects `Action: "*"` resource scope against the queried resource in `who-can`.
- **Ops/infra**: `--output-file` flag for `collect`/`query` JSON output; `--region` flag plus AWS API call logging during collection; Neo4j-only Docker Compose stack with usage docs; Neo4j offline backup/restore scripts with batch-tuning docs; iam-expander cache-flush fixes and a switch to the bulk awsiamactions.io endpoint; CI fix pinning checkout to the PR head SHA on `pull_request_target`; routine dependency bumps (anyhow, uuid).

## [0.2.1] - 2026-06-18

Patch release. Fixes and additions in `iam-models::common` (expanded shared type/helper logic), plus corresponding test updates in `iam-graph`. Cargo.toml versions bumped across affected crates.

## [0.2.0] - 2026-06-18

Reworked and expanded `docs/limitations.md` (moved from repo root into `docs/`), documenting known approximations in the permission-evaluation model. Fixes to the `Policy` model in `iam-models`. Added `rust-toolchain.toml` to pin the toolchain version.

## [0.1.0] - 2026-06-11

Initial release. Five-crate workspace (`iam-models`, `iam-expander`, `iam-collector`, `iam-graph`, `iam-grapher`). Core IAM entity types; wildcard action expansion via awsiamactions.io with local caching; live/offline/hybrid collectors calling `GetAccountAuthorizationDetails`; Neo4j-backed graph ingestion and schema; initial `collect`/`query` CLI subcommands.
