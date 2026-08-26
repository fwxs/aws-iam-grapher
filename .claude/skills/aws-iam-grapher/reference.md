# aws-iam-grapher — limitations & caveats reference

Condensed from `docs/limitations.md` and `docs/caveats.md`. Kept in sync with the `CaveatCode`
enum (`crates/iam-graph/src/queries/caveats.rs`). Read this before interpreting any query result.

## The `caveats` array

Every `query ... --output json` response is `{"results": ..., "caveats": [...]}`. `caveats` is
always present, empty when nothing applies. Each entry is `{"code": ..., "message": ..., "doc_anchor": ...}`.

| Code | Applies to | Meaning |
|---|---|---|
| `approximate-deny` | `who-can`, `privilege-escalation`, `org-escalation` | Deny subtraction compares wildcard Deny actions against wildcard Allow grants as literal glob patterns, not true set containment — a wildcard grant narrowed by a wildcard Deny may be reported as permitted. Group results are not suppressed by Denies on member users. |
| `notaction-not-expanded` | `who-can` only | `NotAction` grants are evaluated by exclusion, but their resource scope isn't intersected with `--resource` and conditions on `NotAction` statements aren't evaluated — may overstate access. |
| `partial-snapshot` | any query, when the queried snapshot(s) are marked partial | Collection was incomplete for at least one queried snapshot; entities/permissions that couldn't be collected are simply absent, not flagged — may understate access. Message includes the recorded reasons. |
| `expansion-degraded` | any query, when the partial reason is specifically wildcard-expansion fallback | `awsiamactions.io` was unreachable during collection; some wildcard actions were stored unexpanded. A concrete-action query may miss an entity holding only an unexpanded wildcard that covers it. |

`entity-perms`, `associated-entities`, and `instance-profiles-with` never carry
`approximate-deny`/`notaction-not-expanded` (their Cypher does no Deny subtraction or NotAction
exclusion) but can still carry `partial-snapshot`/`expansion-degraded` from the snapshot.
`associated-entities` is purely structural (attached/inline policy holders, role assumers,
containing instance profiles, group members) — it doesn't evaluate permissions at all. `diff` is
a raw structural diff — same restriction. `list-snapshots`/`list-accounts` never carry any caveat
(not access queries).

**Always restate every caveat's `message` to the user next to the results it applies to.** A
`who-can` answer delivered without its Deny/NotAction caveats is a wrong answer on a security tool.

## Other V1 limitations not surfaced via `caveats` (still relevant)

- **Permission Boundaries**: evaluated as an Allow-intersection ceiling for `who-can`/`entity-perms`
  (`is_bounded`/`effective` fields signal this). Deny statements *inside* the boundary itself, and
  boundary `Condition` keys, are not evaluated. Wildcard-vs-wildcard boundary comparisons use
  literal glob matching, not semantic set containment.
- **SCPs (Service Control Policies) are not supported at all** — not collected, stored, or
  evaluated. In an Organizations-governed account with restrictive SCPs, results are optimistic
  (overstate access). No caveat code for this yet; mention it whenever the account is known to be
  org-managed.
- **Policy conditions**: only `who-can` evaluates conditions, and only three key/operator pairs —
  `aws:MultiFactorAuthPresent` (`Bool`, via `--mfa`), `aws:RequestedRegion` (`StringEquals`/
  `StringLike`, via `--region`), `aws:PrincipalTag/<key>` (`StringEquals`/`StringLike`, via
  `--principal-tag key=value`, repeatable). Anything else leaves the grant marked
  `conditional: true` with `unevaluated_condition_keys` listing what wasn't checked — never
  silently treated as unconditional. `entity-perms`/`instance-profiles-with` don't evaluate
  conditions at all.
- **Trust policy (`sts:AssumeRole`) evaluation is approximate**: only `StringEquals`/
  `StringEqualsIgnoreCase` on `aws:PrincipalAccount` against a single resolvable ARN is evaluated.
  Everything else (`sts:ExternalId`, MFA, SourceIp, date/time, tags, unresolvable principals) stays
  `conditional: true` on the edge/path. `privilege-escalation`/`org-escalation` surface `conditional`
  per path.
- **`privilege-escalation`/`org-escalation` are bounded by `--max-hops`** (default 3, cap 10) —
  longer assume-role chains are not detected unless the flag is raised.
- **`privilege-escalation`/`org-escalation` risky actions are user-configurable** via a YAML config
  (`--risky-actions <path>`, else `~/.aws-iam-grapher/config/risky-actions.yaml`, fatal if neither
  resolves — no repo-checkout fallback). Match semantics: AND within a named group's `actions`, OR
  across groups — an entity is reported only if it fully satisfies at least one group. The installed
  default reproduces the tool's original 9-action list as 9 single-action groups.
- **`privilege-escalation`/`org-escalation` results carry `holders`/`instance_profiles`/
  `trust_principals`/`matched_paths`** for the terminal (permission-holding) entity of each path:
  `holders` (member Users, `Group` terminals only), `instance_profiles` (wrapping InstanceProfiles,
  `Role` terminals only), `trust_principals` (trust-policy principals that can assume it, `Role`
  terminals only), `matched_paths` (names of the risky-action groups the entity's actions satisfy,
  evaluated after Deny subtraction). `--output json` carries full detail for each field.
  These are exact graph traversals/exact-match evaluations, not glob-match approximations — no
  `caveats` entry applies to them.
- **Every User in a `privilege-escalation`/`org-escalation` result carries its security posture**:
  each `holders` entry has an `attributes` object, and a result whose own `entity_type` is `"User"`
  carries top-level `user_attributes` (`null`/absent otherwise). Fields: `user_id`, `has_mfa`,
  `mfa_method` (`virtual`/`hardware`/`sms`, absent if no MFA), `console_login_enabled`,
  `password_last_used`, `last_activity_date`, `create_date`, `access_key_count`,
  `active_access_key_count`, `oldest_active_key_date` (oldest *active* key's create date, absent
  if none active), `access_key_ids` (both active and inactive). Use `--entity-type user`
  (below) to surface only these.
- **`--entity-type <user|role|group|all>`** filters `privilege-escalation`/`org-escalation` results
  after the query runs (default `all`). `user` keeps every result whose `entity_type` is `"User"`
  **and** every Group result that has a non-empty `holders` list — a user reachable only through
  group membership is exactly the "which users" case, so it stays even though the path's own
  `entity_type` is `"Group"`. `role`/`group` keep only that exact `entity_type`.
- **Offline-collected snapshots never populate user security attributes** (`has_mfa`, `mfa_method`,
  `console_login_enabled`, `last_activity_date`, access keys) — these default to `false`/`None`/empty
  and the snapshot is marked partial (`UserSecurityAttributesNotCollected`). Never state "this user
  lacks MFA" or "this user has no active keys" from an offline snapshot without checking
  `partial_reasons` first.

Full detail: `docs/limitations.md`, `docs/caveats.md` in the repository.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success — **includes empty result sets**. A `"results": []` response is not a failure. |
| `1` | Unexpected/internal error |
| `2` | Usage/validation error (bad flags, e.g. `--snapshot-id` combined with multi-account fan-out) |
| `3` | Credential or connection failure (Neo4j unreachable, missing/empty password) |
| `4` | Requested scope not found (unknown snapshot id, no snapshots for the account) |

Under `--output json`, a non-zero exit also writes `{"error": {"code": "...", "message": "..."}}`
to **stderr**; stdout stays empty on error. Branch on the exit code, never on parsing stdout text.
