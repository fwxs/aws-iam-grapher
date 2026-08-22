# associated_entities

## Purpose

Entities linked to a Policy/Role/Group ARN via the structural (non-permission) relationships
the ingester materializes. Which UNION arms produce rows depends on the target's own label:

- **Policy** → entities with `HAS_ATTACHED_POLICY`/`HAS_INLINE_POLICY` into it
- **Role** → entities with `CAN_ASSUME_ROLE` into it, `InstanceProfile`s via `CONTAINS_ROLE`,
  its own attached/inline policies (shared UNION arm with Group, below), and `BOUNDED_BY`
  boundary
- **Group** → member `User`s via `MEMBER_OF`, plus its own attached/inline policies (same
  shared arm as Role)

No permission-level (`GRANTS`) traversal — this is a structural "what's linked to this entity"
query, not a "what can this entity do" query (see [`entity_permissions`](entity-permissions.md)
for that).

## Parameters

- `$uid` — target entity uid (`"snapshot_id|arn"`)
- `$snapshot_id` — snapshot scope

## Cypher

```cypher
MATCH (e {uid: $uid})
WHERE e:Policy
MATCH (other)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY]->(e)
RETURN other.arn AS arn, other.name AS name, labels(other)[0] AS entity_type,
       'HAS_ATTACHED_POLICY_OR_INLINE' AS relationship

UNION

MATCH (e {uid: $uid})
WHERE e:Role
MATCH (assumer)-[:CAN_ASSUME_ROLE]->(e)
RETURN assumer.arn AS arn, assumer.name AS name, labels(assumer)[0] AS entity_type,
       'CAN_ASSUME' AS relationship

UNION

MATCH (e {uid: $uid})
WHERE e:Role
MATCH (profile:InstanceProfile)-[:CONTAINS_ROLE]->(e)
RETURN profile.arn AS arn, profile.name AS name, labels(profile)[0] AS entity_type,
       'CONTAINS_ROLE' AS relationship

UNION

MATCH (e {uid: $uid})
WHERE e:Role OR e:Group
MATCH (e)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY]->(pol)
RETURN pol.arn AS arn, pol.name AS name, labels(pol)[0] AS entity_type,
       'HAS_ATTACHED_POLICY_OR_INLINE_OWN' AS relationship

UNION

MATCH (e {uid: $uid})
WHERE e:Role
MATCH (e)-[:BOUNDED_BY]->(boundary:Policy)
RETURN boundary.arn AS arn, boundary.name AS name, labels(boundary)[0] AS entity_type,
       'BOUNDED_BY' AS relationship

UNION

MATCH (e {uid: $uid})
WHERE e:Group
MATCH (member:User)-[:MEMBER_OF]->(e)
RETURN member.arn AS arn, member.name AS name, labels(member)[0] AS entity_type,
       'MEMBER_OF' AS relationship
```

## Rust binding

`crates/iam-graph/src/queries/analysis.rs` — `ASSOCIATED_ENTITIES_QUERY`, used in
`associated_entities(graph: &Graph, ctx: &QueryContext, entity_arn: &str) -> Result<Vec<AssociatedEntity>, GraphError>`.

## Returns

`Vec<AssociatedEntity>` where `AssociatedEntity { arn, name, entity_type, relationship }`.
`relationship` is one of `HAS_ATTACHED_POLICY_OR_INLINE`, `CAN_ASSUME`, `CONTAINS_ROLE`,
`HAS_ATTACHED_POLICY_OR_INLINE_OWN`, `BOUNDED_BY`, `MEMBER_OF` — naming which arm produced the
row, not a graph relationship type queried verbatim.

## Notes

`associated_entities()` checks entity existence first, returning `GraphError::EntityNotFound`
if the uid doesn't resolve — same pattern as `entity_permissions()`. Only ARNs typed as
`Policy`, `Role`, or `Group` produce non-empty UNION arms; a `User`/`InstanceProfile` ARN
resolves (no error) but returns an empty result, since none of the arms match its label. Pure
structural traversal: no Deny/NotAction evaluation, no permission-level `GRANTS` walk, so the
CLI attaches no `approximate-deny`/`notaction-not-expanded` caveat for this query. See
`docs/limitations.md`.
