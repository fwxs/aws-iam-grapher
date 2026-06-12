# aws-iam-grapher

Collect AWS IAM permissions into a Neo4j graph and run security analysis queries against them. Designed for security engineers who need to audit effective permissions, detect privilege escalation paths, and diff permission snapshots over time.

---

## Prerequisites

- **Rust 1.82.0 or higher** — install via [rustup](https://rustup.rs)
- **Docker** — to run Neo4j Community Edition
- **AWS credentials configured** — required for live and hybrid modes (`~/.aws/credentials`, environment variables, or IAM role)
- **Neo4j Community Edition** running locally or accessible via Bolt

---

## Installation

```bash
git clone https://github.com/<usuario>/aws-iam-grapher
cd aws-iam-grapher
cargo build --release
```

The binary is at `target/release/aws-iam-grapher`.

---

## Quick Start

### Scenario A — Direct live access to the account

```bash
export NEO4J_PASSWORD=your-password
aws-iam-grapher collect \
    --mode live \
    --account-alias production
```

### Scenario B — Avoid CloudTrail noise (offline)

```bash
# Step 1: generate the file using your credentials (one API call)
aws iam get-account-authorization-details \
    --output json > account-auth-details.json

# Step 2 (optional): instance profiles
aws iam list-instance-profiles \
    --output json > instance-profiles.json

# Step 3: ingest without further API calls
export NEO4J_PASSWORD=your-password
aws-iam-grapher collect \
    --mode offline \
    --input-file account-auth-details.json \
    --profiles-file instance-profiles.json \
    --account-alias production
```

### Scenario C — Automatic (tries live, prompts for file if 403)

```bash
export NEO4J_PASSWORD=your-password
aws-iam-grapher collect --mode hybrid --account-alias production
```

---

## Data Coverage by Collection Mode

This table describes what data is available in each mode. Missing data silently skews analysis results — read this before interpreting the graph.

| Field / Entity | Live Mode | Offline Mode |
|---|---|---|
| Users | ✓ complete | ✓ if in `get-account-authorization-details` |
| Roles | ✓ complete | ✓ if in `get-account-authorization-details` |
| Managed policies | ✓ complete | ✓ if in `get-account-authorization-details` |
| Inline policies | ✓ complete | ✓ if in `get-account-authorization-details` |
| Instance Profiles | ✓ via `list-instance-profiles` | ⚠ requires `--profiles-file` |
| Wildcard expansion | ✓ via awsiamactions.io | ✓ via awsiamactions.io |
| `create_date` of entities | ✓ | ✓ |
| `is_aws_managed` | ✓ derived from ARN/path | ✓ derived from ARN/path |
| Effective permissions with boundary | ⚠ boundary recorded, not evaluated | ⚠ boundary recorded, not evaluated |

See [`docs/limitations.md`](docs/limitations.md) for V1 analysis limitations.

---

## Query Commands

All query commands require `--neo4j-pass` (or `NEO4J_PASSWORD` env var) and `--account-id`. If `--snapshot-id` is omitted, the most recent snapshot for the account is used.

### Who can perform an action?

```bash
aws-iam-grapher query \
    --account-id 123456789012 \
    who-can s3:DeleteObject
```

```
Entities with permission s3:DeleteObject (snapshot: a3f2c1d0)

TYPE   ARN
────── ──────────────────────────────────────────────────────
Role   arn:aws:iam::123456789012:role/DataEngineer
Role   arn:aws:iam::123456789012:role/S3AdminRole
User   arn:aws:iam::123456789012:user/alice
```

### All permissions for an entity

```bash
aws-iam-grapher query \
    --account-id 123456789012 \
    entity-perms arn:aws:iam::123456789012:role/DataEngineer
```

```
Permissions for arn:aws:iam::123456789012:role/DataEngineer

EFFECT  ACTION          RESOURCE
─────── ─────────────── ────────
Allow   s3:GetObject    *
Allow   s3:PutObject    *
Allow   s3:DeleteObject arn:aws:s3:::my-bucket/*
```

### Instance profiles granting an action

```bash
aws-iam-grapher query \
    --account-id 123456789012 \
    instance-profiles-with iam:PassRole
```

```
Instance profiles granting iam:PassRole (snapshot: a3f2c1d0)

NAME          ARN
───────────── ──────────────────────────────────────────────────────────────
EC2DevProfile arn:aws:iam::123456789012:instance-profile/EC2DevProfile
```

### Privilege escalation paths

```bash
aws-iam-grapher query \
    --account-id 123456789012 \
    privilege-escalation
```

```
Privilege escalation paths (snapshot: a3f2c1d0)

ENTITY                                           RISKY ACTIONS
──────────────────────────────────────────────── ──────────────────────────────────
arn:aws:iam::123456789012:role/DevRole           iam:PassRole, iam:AttachRolePolicy
arn:aws:iam::123456789012:user/developer         iam:CreatePolicyVersion
```

### List snapshots

```bash
aws-iam-grapher query \
    --account-id 123456789012 \
    list-snapshots
```

```
SNAPSHOT ID                           ACCOUNT        COLLECTED AT          STATUS
───────────────────────────────────── ────────────── ───────────────────── ──────
a3f2c1d0-4e5b-6c7d-8e9f-0a1b2c3d4e5f 123456789012   2024-01-15T14:32:00Z  full
b4e3d2c1-5f6a-7b8c-9d0e-1f2a3b4c5d6e 123456789012   2024-01-08T09:15:00Z  full
```

### Diff between two snapshots

```bash
aws-iam-grapher query \
    --account-id 123456789012 \
    diff a3f2c1d0-... b4e3d2c1-...
```

```
Permission diff between a3f2c1d0-... and b4e3d2c1-...

NEW PERMISSIONS (in b4e3d2c1-..., not in a3f2c1d0-...):
  [+] Allow  s3:DeleteBucket                          *
  [+] Allow  iam:CreateUser                           *

REMOVED PERMISSIONS (in a3f2c1d0-..., not in b4e3d2c1-...):
  [-] Allow  ec2:TerminateInstances                   *
```

### Delete a snapshot

```bash
aws-iam-grapher query \
    --account-id 123456789012 \
    delete-snapshot a3f2c1d0-4e5b-6c7d-8e9f-0a1b2c3d4e5f
```

---

## Neo4j Community Setup

Neo4j Community Edition is free and does not require a license.

```bash
docker run \
  --name neo4j-iam \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/your-password \
  neo4j:community
```

The Neo4j Browser is then available at `http://localhost:7474`. The Bolt endpoint used by this tool is `bolt://localhost:7687`.

**Note:** Neo4j Community allows only a single database. Account isolation is logical (by `account_id` property), not physical. See [`docs/limitations.md`](docs/limitations.md) for implications.

---

## Workspace Architecture

```
aws-iam-grapher/
├── crates/
│   ├── iam-models      (lib) ──────────────────────────────┐
│   │                                                        │
│   ├── iam-expander    (lib) ──────────────────────────────┤
│   │                                                        │
│   ├── iam-collector   (lib) ── uses iam-models            │
│   │                        ── uses iam-expander            │
│   │                                                        │
│   ├── iam-graph       (lib) ── uses iam-models            │
│   │                        ── uses iam-collector           │
│   │                                                        │
│   └── iam-grapher     (bin) ── uses iam-collector ────────┘
│                            ── uses iam-graph
│                            ── uses iam-models
└── 
```

---

## Crate Reference

| Crate | Type | Responsibility |
|---|---|---|
| `iam-models` | lib | Core IAM entity types: `IamRole`, `IamUser`, `IamPolicy`, `IamGroup`, `IamInstanceProfile`, `PolicyDocument` |
| `iam-expander` | lib | Expands wildcard IAM actions (`s3:*`) to their full list via awsiamactions.io |
| `iam-collector` | lib | Collects IAM data from live AWS API, offline JSON files, or hybrid mode |
| `iam-graph` | lib | Ingests collected data into Neo4j and runs Cypher analysis queries |
| `iam-grapher` | bin | CLI binary: `collect` and `query` subcommands |
