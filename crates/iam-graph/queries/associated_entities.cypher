// name: associated_entities
// description: Entities linked to a Policy/Role/Group ARN via the structural (non-permission)
//   relationships the ingester materializes. Which UNION arms produce rows depends on the
//   target's own label, tested inline with `e:Policy`/`e:Role`/`e:Group` guards rather than
//   dispatched in Rust, since a node's label set is already available in Cypher:
//     Policy  -> entities with HAS_ATTACHED_POLICY/HAS_INLINE_POLICY into it
//     Role    -> entities with CAN_ASSUME_ROLE into it, InstanceProfiles via CONTAINS_ROLE,
//                plus the role's own attached/inline policies and BOUNDED_BY boundary
//     Group   -> member Users via MEMBER_OF, plus the group's own attached/inline policies
//   No permission-level (GRANTS) traversal — this is a structural "what's linked to this
//   entity" query, not a "what can this entity do" query (see entity_permissions.cypher for
//   that). See limitations.md.
// param $uid: target entity uid ("snapshot_id|arn")
// param $snapshot_id: snapshot scope

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
WHERE e:Role
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

UNION

MATCH (e {uid: $uid})
WHERE e:Group
MATCH (e)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY]->(pol)
RETURN pol.arn AS arn, pol.name AS name, labels(pol)[0] AS entity_type,
       'HAS_ATTACHED_POLICY_OR_INLINE_OWN' AS relationship
