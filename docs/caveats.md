# Caveats

`query ... --output json` attaches a machine-readable `caveats` array to every response,
populated with only the codes below that actually apply to that query and that snapshot. The
array is always present, empty when no caveat applies. This document explains each approximation
those codes reference — a human reading table output can hold them in mind; a model consuming
bare JSON cannot, so the closed `CaveatCode` enum (`crates/iam-graph/src/queries/caveats.rs`)
carries the applicable subset alongside query results.

## Caveat codes

| Code | Meaning | Heading |
|---|---|---|
| `approximate-deny` | Deny subtraction uses literal glob comparison for wildcard-vs-wildcard cases; may overstate access. | [Deny scope is approximate](#deny-scope-is-approximate) |
| `notaction-not-expanded` | `NotAction` grants aren't resource- or condition-scoped; may overstate access. | [`NotAction` — implemented as allow-all-except (query-time exclusion)](#notaction-implemented-as-allow-all-except-query-time-exclusion) |
| `partial-snapshot` | The queried snapshot's collection was incomplete; may understate access. | [Partial snapshots](#partial-snapshots) |
| `expansion-degraded` | Wildcard action expansion fell back during collection; concrete-action queries may miss matches. | [Wildcard expansion degradation](#wildcard-expansion-degradation) |

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
  permission nodes — see `docs/limitations.md` "Policy conditions").

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

### Partial snapshots

Collection can be incomplete for a variety of reasons (an AWS API call was throttled or denied,
inline policies couldn't be resolved, MFA/login/access-key metadata couldn't be listed, or
wildcard action expansion degraded — see "Wildcard expansion degradation" below). When any of
these occur during `collect`, the resulting `Snapshot` node is marked `is_partial: true` and
carries a `partial_reasons` list enumerating the causes.

**A partial snapshot understates access**: entities or permissions that could not be collected
are simply absent from the graph, not flagged as missing on a per-entity basis. `query
list-snapshots` reports `is_partial`/`partial_reasons` per snapshot. `query ... --output json`
against a partial snapshot surfaces this as the `partial-snapshot` caveat, with the recorded
reasons included in the caveat message.

### Wildcard expansion degradation

`iam-expander` expands wildcard IAM action strings (e.g. `s3:*`) to concrete action lists by
querying awsiamactions.io, with results cached locally. If that service is unreachable during
collection — network failure, or the local action cache fails to load — wildcard expansion falls
back and the affected wildcard actions are stored unexpanded rather than as their concrete
action list.

**Effect on queries:** a concrete-action query (e.g. `who-can s3:DeleteObject`) may miss an
entity that holds only an unexpanded wildcard covering that action, since the query matches
concrete actions and exact/known wildcard forms, not arbitrary unexpanded patterns. This is a
collection-time degradation, recorded as the `"some wildcards not expanded"` reason in the
snapshot's `partial_reasons` (see "Partial snapshots" above) and surfaced separately at query
time as the `expansion-degraded` caveat, since it specifically means action *matching* may miss
results, not merely that collection was incomplete in general.

See [`docs/limitations.md`](limitations.md) for all other V1 analysis limitations not surfaced
via the `caveats` array.
