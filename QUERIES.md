# IAM Graph — Cypher Query Reference

This document lists all Cypher queries available for the IAM graph, both those exposed through the CLI and additional queries for manual analysis in Neo4j Browser.

---

## 1. Mandatory Filter Context

**Every query must filter by `account_id` and `snapshot_id`.**

Because Neo4j Community supports only a single database, all data from all accounts and all collection runs lives in the same graph. A query without these filters operates over every account and every snapshot simultaneously — producing meaningless combined results.

```cypher
// Always include in WHERE or as a property on the root node:
WHERE n.account_id = '123456789012'
  AND n.snapshot_id = 'a3f2c1d0-4e5b-6c7d-8e9f-0a1b2c3d4e5f'
```

To find valid values for these parameters, run `list-snapshots` from the CLI or use the snapshot management queries below.

---

## 2. Snapshot Management

### List all snapshots (newest first)

```cypher
MATCH (s:Snapshot)-[:OF_ACCOUNT]->(a:AwsAccount)
RETURN s.id, s.collected_at, s.collector_mode, a.alias
ORDER BY s.collected_at DESC;
```

### List snapshots for a specific account

```cypher
MATCH (s:Snapshot {account_id: '123456789012'})
RETURN s.id, s.collected_at, s.is_partial
ORDER BY s.collected_at DESC;
```

### Delete a snapshot (all associated nodes and relationships)

```cypher
// Step 1: delete entity nodes (those with snapshot_id property)
MATCH (n {snapshot_id: 'a3f2c1d0-...'})
DETACH DELETE n;

// Step 2: delete the Snapshot node itself
MATCH (s:Snapshot {id: 'a3f2c1d0-...'})
DETACH DELETE s;
```

> The CLI `delete-snapshot` subcommand performs both steps automatically.

---

## 3. Inventory Queries

### Count entities by type in a snapshot

```cypher
MATCH (n {snapshot_id: $sid, account_id: $aid})
RETURN labels(n)[0] AS type, count(n) AS total
ORDER BY total DESC;
```

### All AWS-managed policies (not customer-created)

```cypher
MATCH (p:Policy {is_aws_managed: true, snapshot_id: $sid, account_id: $aid})
RETURN p.name, p.arn
ORDER BY p.name;
```

### Roles unused in the last 90 days

```cypher
MATCH (r:Role {snapshot_id: $sid, account_id: $aid})
WHERE r.last_used_date IS NULL
   OR r.last_used_date < datetime() - duration('P90D')
RETURN r.name, r.arn, r.last_used_date
ORDER BY r.last_used_date ASC;
```

### Users with no attached policies or group memberships

```cypher
MATCH (u:User {snapshot_id: $sid, account_id: $aid})
WHERE NOT (u)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY]->()
  AND NOT (u)-[:MEMBER_OF]->()
RETURN u.name, u.arn;
```

### Instance profiles and their associated roles

```cypher
MATCH (ip:InstanceProfile {snapshot_id: $sid, account_id: $aid})
      -[:CONTAINS_ROLE]->(r:Role)
RETURN ip.name, ip.arn, collect(r.name) AS roles;
```

---

## 4. Permission Analysis Queries

### What entities can perform a specific action? (`who-can`)

```cypher
MATCH (e)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS]->(perm:Permission {
          action: 's3:DeleteObject',
          effect: 'Allow',
          snapshot_id: $sid
      })
WHERE e.account_id = $aid
RETURN labels(e)[0] AS type, e.name, e.arn;
```

### All permissions for a specific entity (`entity-perms`)

```cypher
// Replace $entity_uid with: '<snapshot_id>|<entity_arn>'
MATCH (e {uid: $entity_uid})
      -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS]->(perm:Permission {snapshot_id: $sid})
RETURN perm.action, perm.effect, perm.resource
ORDER BY perm.action;
```

### Instance profiles that grant a given action (`instance-profiles-with`)

```cypher
MATCH (ip:InstanceProfile {account_id: $aid, snapshot_id: $sid})
      -[:CONTAINS_ROLE]->(r:Role)
      -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS]->(perm:Permission {
          action: $action,
          effect: 'Allow',
          snapshot_id: $sid
      })
RETURN DISTINCT ip.name, ip.arn;
```

### Instance profiles with any high-risk action

```cypher
MATCH (ip:InstanceProfile {snapshot_id: $sid, account_id: $aid})
      -[:CONTAINS_ROLE]->(r:Role)
      -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS]->(perm:Permission {effect: 'Allow', snapshot_id: $sid})
WHERE perm.action IN [
    'iam:PassRole',
    'iam:CreatePolicyVersion',
    'iam:AttachRolePolicy',
    'ec2:*',
    's3:*'
]
RETURN ip.name, r.name, collect(perm.action) AS risky_actions;
```

---

## 5. Privilege Escalation Queries

### All entities with any escalation permission (`privilege-escalation`)

```cypher
MATCH (e {account_id: $aid, snapshot_id: $sid})
      -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS]->(perm:Permission {effect: 'Allow', snapshot_id: $sid})
WHERE perm.action IN [
    'iam:CreatePolicyVersion',
    'iam:SetDefaultPolicyVersion',
    'iam:AttachRolePolicy',
    'iam:AttachUserPolicy',
    'iam:PassRole',
    'iam:PutRolePolicy',
    'iam:PutUserPolicy',
    'iam:CreateAccessKey',
    'iam:CreateLoginProfile'
]
RETURN e.arn, e.name, labels(e)[0] AS type,
       collect(perm.action) AS risky_actions;
```

#### Technique: `iam:CreatePolicyVersion`

Create a new policy version with elevated permissions on any managed policy attached to a privileged entity.

```cypher
MATCH (e {account_id: $aid, snapshot_id: $sid})
      -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS]->(perm:Permission {
          action: 'iam:CreatePolicyVersion',
          effect: 'Allow',
          snapshot_id: $sid
      })
RETURN e.arn, e.name, labels(e)[0] AS type;
```

#### Technique: `iam:SetDefaultPolicyVersion`

Activate a previously uploaded policy version that may have broader permissions.

```cypher
MATCH (e {account_id: $aid, snapshot_id: $sid})
      -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS]->(perm:Permission {
          action: 'iam:SetDefaultPolicyVersion',
          effect: 'Allow',
          snapshot_id: $sid
      })
RETURN e.arn, e.name, labels(e)[0] AS type;
```

#### Technique: `iam:AttachRolePolicy`

Attach any managed policy (including `AdministratorAccess`) to a role the attacker can assume.

```cypher
MATCH (e {account_id: $aid, snapshot_id: $sid})
      -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS]->(perm:Permission {
          action: 'iam:AttachRolePolicy',
          effect: 'Allow',
          snapshot_id: $sid
      })
RETURN e.arn, e.name, labels(e)[0] AS type;
```

#### Technique: `iam:AttachUserPolicy`

Attach any managed policy directly to another IAM user.

```cypher
MATCH (e {account_id: $aid, snapshot_id: $sid})
      -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS]->(perm:Permission {
          action: 'iam:AttachUserPolicy',
          effect: 'Allow',
          snapshot_id: $sid
      })
RETURN e.arn, e.name, labels(e)[0] AS type;
```

#### Technique: `iam:PutRolePolicy`

Write an inline policy to any role, granting it arbitrary permissions.

```cypher
MATCH (e {account_id: $aid, snapshot_id: $sid})
      -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS]->(perm:Permission {
          action: 'iam:PutRolePolicy',
          effect: 'Allow',
          snapshot_id: $sid
      })
RETURN e.arn, e.name, labels(e)[0] AS type;
```

#### Technique: `iam:PassRole`

Pass a privileged role to an AWS service (EC2, Lambda, etc.), gaining its permissions indirectly.

```cypher
MATCH (e {account_id: $aid, snapshot_id: $sid})
      -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS]->(perm:Permission {
          action: 'iam:PassRole',
          effect: 'Allow',
          snapshot_id: $sid
      })
RETURN e.arn, e.name, labels(e)[0] AS type;
```

#### Technique: `iam:CreateAccessKey`

Create a new access key for any other IAM user, gaining that user's permissions.

```cypher
MATCH (e {account_id: $aid, snapshot_id: $sid})
      -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS]->(perm:Permission {
          action: 'iam:CreateAccessKey',
          effect: 'Allow',
          snapshot_id: $sid
      })
RETURN e.arn, e.name, labels(e)[0] AS type;
```

---

## 6. Snapshot Comparison (Diff)

### Permissions added in a newer snapshot

```cypher
MATCH (perm:Permission {snapshot_id: $snapshot_new, account_id: $aid})
WHERE NOT EXISTS {
    MATCH (:Permission {
        action: perm.action,
        resource: perm.resource,
        effect: perm.effect,
        snapshot_id: $snapshot_old,
        account_id: $aid
    })
}
RETURN perm.effect, perm.action, perm.resource
ORDER BY perm.action;
```

### Permissions removed in the newer snapshot

```cypher
MATCH (perm:Permission {snapshot_id: $snapshot_old, account_id: $aid})
WHERE NOT EXISTS {
    MATCH (:Permission {
        action: perm.action,
        resource: perm.resource,
        effect: perm.effect,
        snapshot_id: $snapshot_new,
        account_id: $aid
    })
}
RETURN perm.effect, perm.action, perm.resource
ORDER BY perm.action;
```

### Entities that gained new permissions between snapshots

```cypher
MATCH (e)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS]->(perm_new:Permission {
          snapshot_id: $snapshot_new,
          account_id: $aid,
          effect: 'Allow'
      })
WHERE e.account_id = $aid
  AND NOT EXISTS {
    MATCH (e)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol2)
          -[:GRANTS]->(perm_old:Permission {
              action: perm_new.action,
              snapshot_id: $snapshot_old,
              account_id: $aid
          })
  }
RETURN e.arn, e.name, labels(e)[0] AS type,
       collect(perm_new.action) AS new_actions
ORDER BY e.arn;
```
