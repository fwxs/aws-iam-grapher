# aws-iam-grapher

Collect AWS IAM permissions into a Neo4j graph and run security analysis queries against them. Designed for security engineers who need to audit effective permissions, detect privilege escalation paths, and diff permission snapshots over time.

---

## Prerequisites

- **Rust 1.82.0 or higher** — install via [rustup](https://rustup.rs)
- **Docker** — required to run Neo4j Community Edition and the integration test suite
- **AWS credentials** — required for live and hybrid collection modes (`~/.aws/credentials`, environment variables, or an IAM role)
- **Neo4j Community Edition** — running locally or accessible via the Bolt protocol

---

## Installation

```bash
git clone https://github.com/<user>/aws-iam-grapher
cd aws-iam-grapher
cargo build --release
```

The compiled binary is located at `target/release/aws-iam-grapher`.

---

## Run Neo4j with Docker

A `docker-compose.yml` runs Neo4j only; the `aws-iam-grapher` binary is built
and run locally with `cargo`. Neo4j's `/data` directory is backed by the
named volume `neo4j_data`, so snapshots survive container restarts.

```bash
export NEO4J_PASSWORD=changeme   # required, no default password

# Start Neo4j and wait for it to become healthy
docker compose up -d neo4j

# Run the binary against it
cargo run --release -- collect \
  --mode offline \
  --input-file ./data/auth-details.json \
  --neo4j-uri bolt://localhost:7687 \
  --neo4j-user neo4j
```

**Persistence and reset:**

```bash
docker compose down      # stops containers, keeps the neo4j_data volume
docker compose up -d neo4j   # data from prior collect runs is still there

docker volume inspect aws-iam-grapher_neo4j_data   # see where Docker stores it

docker compose down -v   # drops the volume — full reset, all snapshots lost
```

**Backup and restore:**

Neo4j Community has no online (hot) backup — only offline. `scripts/neo4j-backup.sh`
and `scripts/neo4j-restore.sh` automate the offline procedure: stop the `neo4j`
container, copy the `aws-iam-grapher_neo4j_data` volume to/from a timestamped
tarball, restart. The container is down for the duration of the copy.

```bash
scripts/neo4j-backup.sh                          # writes ./backups/neo4j-backup-<timestamp>.tar.gz
scripts/neo4j-restore.sh -f ./backups/neo4j-backup-<timestamp>.tar.gz
```

**Batch size and scale:**

`--batch-size` (default 500, every `collect` subcommand) controls how many
writes Neo4j commits per transaction during ingestion. See
[`docs/limitations.md` § Validated scale ceiling](docs/limitations.md#validated-scale-ceiling)
for tuning guidance and the account-sharding strategy for accounts that
approach the ~10,000-permission-node practical ceiling.

---

## Running Tests

### Unit tests

Unit tests have no external dependencies and run entirely in-process:

```bash
cargo test --workspace
```

### Integration tests (requires Docker)

Integration tests in `crates/iam-graph/tests/` start a real Neo4j container using [testcontainers-rs](https://github.com/testcontainers/testcontainers-rs). They are annotated with `#[ignore = "requires Docker"]` so they don't run by default — you need to opt in explicitly.

#### Running on macOS with Colima

Colima exposes the Docker socket at a non-standard path, and its default profile restricts container privileges. You need to set two environment variables before running the tests:

```bash
# Point testcontainers at the Colima socket
export DOCKER_HOST="unix://${HOME}/.colima/default/docker.sock"

# Disable ryuk — it requires privileged mode that Colima does not allow
export TESTCONTAINERS_RYUK_DISABLED=true
```

If you are using a named Colima profile instead of `default`, adjust the socket path accordingly:

```bash
export DOCKER_HOST="unix://${HOME}/.colima/<profile-name>/docker.sock"
```

Once the variables are set, run the integration tests:

```bash
# All Docker-gated tests across the workspace
cargo test --workspace -- --ignored

# Only the iam-graph integration tests
cargo test -p iam-graph -- --ignored
```

#### How containers are managed

Each test binary (one per file in `tests/`) starts a single shared Neo4j container. The container is initialized once, the schema is set up exactly once, and then all tests in that binary reuse the same running instance. Tests remain isolated from each other because each test creates its own `snapshot_id` inside `IngestConfig` — data written by one test is never visible to another.

In total, four containers are started (one per test binary), rather than one per test function.

#### Verifying containers are running

While the tests are executing, you can check which containers are active:

```bash
DOCKER_HOST="unix://${HOME}/.colima/default/docker.sock" \
  docker ps --filter ancestor=neo4j
```

#### Cleaning up after the test run

Because ryuk is disabled, containers are not removed automatically when the tests finish. Remove them manually when you are done:

```bash
DOCKER_HOST="unix://${HOME}/.colima/default/docker.sock" \
  docker container prune -f
```

---

## Quick Start

### Scenario A — Direct live access to the account

```bash
export NEO4J_PASSWORD=your-password
aws-iam-grapher collect \
    --mode live \
    --profile production \
    --account-alias production
```

`--profile` selects a named local AWS profile for credentials, honored by `live` and `hybrid`
modes (`hybrid` is the default) and ignored in `offline` mode, same as `--region`. Resolution
order: `--profile`, if given, wins outright; otherwise `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`
in the environment are used if both are set; otherwise the standard AWS credential chain
(`AWS_PROFILE` / the `[default]` profile / a container or IMDS role) applies unchanged. An
unresolvable profile or credential set fails fast, before any IAM call, naming the problem.

### Scenario B — Avoid CloudTrail noise (offline)

```bash
# Step 1: export IAM authorization details (single API call, no ongoing access required)
aws iam get-account-authorization-details \
    --output json > account-auth-details.json

# Step 2 (optional): export instance profiles
aws iam list-instance-profiles \
    --output json > instance-profiles.json

# Step 3: ingest the exported data without any further AWS API calls
export NEO4J_PASSWORD=your-password
aws-iam-grapher collect \
    --mode offline \
    --input-file account-auth-details.json \
    --profiles-file instance-profiles.json \
    --account-alias production
```

### Scenario C — Automatic (tries live, prompts for file on access denied)

```bash
export NEO4J_PASSWORD=your-password
aws-iam-grapher collect --mode hybrid --account-alias production
```

### Scenario D — Org-wide collection (`collect org`)

Enumerates every account under an AWS Organization, assumes a jump role into each, and files
them all under one `org_collection_run_id`:

```bash
aws-iam-grapher collect org \
  --management-profile org-management \
  --jump-from-profile default \
  --assume-role-name OrganizationAccountAccessRole \
  --neo4j-pass "$NEO4J_PASSWORD"
```

`--exclude-ou-id`/`--exclude-ou-name` and `--include-ou-name` scope which OUs are collected;
`--ou-profile-override <ou_id_or_name>=<aws_profile>` collects a subtree via a named local
profile instead of assume-role. If a subtree exposes the cross-account role under a *different
name* than `--assume-role-name`, use `--ou-role-override <ou_id_or_name>=<role_name>` (repeatable)
to assume that role instead, for accounts under that OU and its descendants:

```bash
aws-iam-grapher collect org \
  --management-profile org-management \
  --jump-from-profile default \
  --assume-role-name OrganizationAccountAccessRole \
  --ou-role-override LegacyAcquisition=CrossAccountAuditRole \
  --neo4j-pass "$NEO4J_PASSWORD"
```

All of these flags are repeatable, match against both OU id and display name, and are documented
in full — matching/precedence rules, inheritance, validation, and edge cases — in
[docs/limitations.md](docs/limitations.md).

---

## Organization-wide Collection (`collect org`)

`collect org` enumerates every account in an AWS Organization and collects IAM data from each
one, tagging every account with the same org collection run id and its Organizational Unit
ancestry. Two separate identities are involved:

- `--management-profile` — used only to call the Organizations APIs (enumerating OUs and
  accounts) from the management account. Never used for role assumption.
- `--jump-from-profile` — the source identity for `sts:AssumeRole` into `--assume-role-name`
  in every member account. Defaults to the standard AWS credential chain (`AWS_PROFILE` / the
  `default` profile) if omitted.

These are kept separate on purpose: if `--management-profile` itself resolves to an assumed role
(an SSO profile, or one with `role_arn`/`source_profile` chaining), reusing its credentials to
call `AssumeRole` again would be a double-hop assumption that most jump-role trust policies
reject.

```bash
export NEO4J_PASSWORD=your-password
aws-iam-grapher collect org \
    --management-profile org-management \
    --jump-from-profile default \
    --assume-role-name OrganizationAccountAccessRole \
    --neo4j-pass "$NEO4J_PASSWORD"
```

### Scoping which accounts are collected

- `--exclude-ou-id <id>` / `--exclude-ou-name <name>` (repeatable) — prune an OU, and all its
  descendants, out of collection.
- `--include-ou-name <name>` (repeatable) — scope collection to only the given OU(s) and their
  descendants; every other account is skipped. `--exclude-ou-id`/`--exclude-ou-name` still prune
  even a matching include. An id/name that never matches any OU encountered while walking the
  tree is reported as a warning, not silently ignored.

```bash
aws-iam-grapher collect org \
    --management-profile org-management \
    --assume-role-name OrganizationAccountAccessRole \
    --exclude-ou-id ou-root1-sandbox \
    --include-ou-name Production \
    --neo4j-pass "$NEO4J_PASSWORD"
```

### Mixed-authentication organizations (`--ou-profile-override`)

Some accounts can't assume the jump role from `--jump-from-profile` at all — for example, a
quarantined OU that requires its own SSO profile or a separate set of long-lived static
credentials. `--ou-profile-override <ou_id_or_name>=<aws_profile>` (repeatable) makes accounts
under a matching OU, and all its descendant OUs, assume `--assume-role-name` from that named
local profile instead of `--jump-from-profile`.

**This is not a way to bypass assume-role** — the override profile is only ever used to call
`sts:AssumeRole`, exactly like `--jump-from-profile` is, just scoped to that OU subtree instead
of the whole run. Every account, whichever profile it assumes from, still calls `sts:AssumeRole`
into the same role name and lands in the same collection run. The override profile itself only
needs permission to assume `--assume-role-name` — it does not need
`iam:GetAccountAuthorizationDetails`, since it's never used to call IAM APIs directly.

```bash
aws-iam-grapher collect org \
    --management-profile org-management \
    --jump-from-profile default \
    --assume-role-name OrganizationAccountAccessRole \
    --ou-profile-override Quarantine=legacy-static-creds \
    --ou-profile-override ThirdParty=vendor-sso \
    --neo4j-pass "$NEO4J_PASSWORD"
```

Matching mirrors `--exclude-ou-id`/`--exclude-ou-name`: the key is checked against both the OU's
id and its display name, and when nested overridden OUs disagree, the innermost (nearest
ancestor) override wins. An override key that never matches any OU encountered while walking the
tree is a **fatal** validation error, as is an override profile whose credentials can't be
resolved — both fail collection before any account is touched. See
[`docs/limitations.md`](docs/limitations.md) for further detail.

### Collection concurrency (`--concurrency`)

`collect org` collects member accounts with bounded concurrency instead of one at a time.
`--concurrency <n>` (default **4**) caps how many accounts are collected in parallel; values
outside `[1, 16]` are rejected with an error rather than silently adjusted. The default is kept
conservative because
the limiting factor is AWS-side per-account IAM throttling and the jump-role STS trust setup,
not local CPU. Output (`OrgCollectionResult.accounts`) is always sorted by account id, so it's
deterministic regardless of which accounts finish first.

```bash
aws-iam-grapher collect org \
    --management-profile org-management \
    --jump-from-profile default \
    --assume-role-name OrganizationAccountAccessRole \
    --concurrency 8 \
    --neo4j-pass "$NEO4J_PASSWORD"
```

---

## Logging

`collect` and `collect org` log each AWS API call they make (region resolution, pagination
progress, per-account jump-role assumption, etc.) at `info`/`debug` level via `tracing`.
`info`-level logs are shown by default; for more detail (e.g. every paginated page fetched), set:

```bash
RUST_LOG=iam_collector=debug aws-iam-grapher collect --mode live --account-alias production
```

---

## Data Coverage by Collection Mode

The table below shows what data is available in each mode. Missing data can silently skew analysis results — review this before interpreting the graph output.

| Field / Entity | Live Mode | Offline Mode |
|---|---|---|
| Users | ✓ complete | ✓ if present in `get-account-authorization-details` |
| Roles | ✓ complete | ✓ if present in `get-account-authorization-details` |
| Managed policies | ✓ complete | ✓ if present in `get-account-authorization-details` |
| Inline policies | ✓ complete | ✓ if present in `get-account-authorization-details` |
| Instance Profiles | ✓ via `list-instance-profiles` | ⚠ requires `--profiles-file` |
| Wildcard expansion | ✓ via awsiamactions.io | ✓ via awsiamactions.io |
| `create_date` of entities | ✓ | ✓ |
| `is_aws_managed` | ✓ derived from ARN/path | ✓ derived from ARN/path |
| Effective permissions with boundary | ⚠ boundary recorded, not evaluated | ⚠ boundary recorded, not evaluated |

See [`docs/limitations.md`](docs/limitations.md) for V1 analysis limitations.

---

## Query Commands

All query commands require `--neo4j-pass` (or the `NEO4J_PASSWORD` environment variable). If `--snapshot-id` is omitted, the most recent snapshot for the account is used automatically.

`--account-id` is optional. When it's provided, the query scopes to exactly that account (as
before). When it's **omitted**, `query` resolves every distinct account with at least one
snapshot in the graph and runs the query once per account, each correctly scoped to its own
`(account_id, snapshot_id)` — never merging results across accounts. This applies to
`who-can`, `entity-perms`, `instance-profiles-with`, `privilege-escalation`, and
`list-snapshots`. Output (table and JSON) groups results under an `=== Account: ... ===`
header (table) or an `account_id`/`snapshot_id`/`results` envelope per account (JSON). A
graph with only one account degrades to a single group. `--snapshot-id` cannot be combined
with multi-account mode (more than one account resolved) since a snapshot id would be
ambiguous across accounts — pass `--account-id` to target one account instead.

`diff` derives the account from its two snapshot ids when `--account-id` is omitted, and
errors if the two snapshots belong to different accounts.

`list-accounts` is inherently cross-account and never requires (or uses) `--account-id` — use
it to discover which accounts exist in the graph before targeting one with `--account-id`.

Add `--output-file <path>` to write the result as JSON to a file, regardless of `--output`. The
human-readable table still prints to stdout — useful for downstream tooling that wants a clean
JSON artifact without scraping stdout/stderr:

```bash
aws-iam-grapher query \
    --account-id 123456789012 \
    --output-file who-can.json \
    who-can s3:DeleteObject
```

The `collect` subcommand supports the same `--output-file` flag for its summary.

### Who can perform an action?

```bash
aws-iam-grapher query \
    --account-id 123456789012 \
    who-can s3:DeleteObject
```

```
Entities with permission s3:DeleteObject (snapshot: a3f2c1d0)

TYPE   ARN                                              RESOURCE
────── ──────────────────────────────────────────────── ─────────
Role   arn:aws:iam::123456789012:role/DataEngineer       *
Role   arn:aws:iam::123456789012:role/S3AdminRole        *
User   arn:aws:iam::123456789012:user/alice              *
```

Add `--resource <arn>` to intersect `Action: "*"` (full-admin) grants against a specific
resource, excluding grants whose resource scope doesn't cover it:

```bash
aws-iam-grapher query \
    --account-id 123456789012 \
    who-can s3:DeleteObject --resource arn:aws:s3:::my-bucket/object.txt
```

A principal with `"Action": "*", "Resource": "arn:aws:s3:::my-bucket"` is excluded here since
the grant is bucket-scoped, not object-scoped. See [`docs/limitations.md`](docs/limitations.md).

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

### List accounts

No `--account-id` needed — lists every account currently in the graph. Accounts collected
via `collect org` show their immediate Organizational Unit id/name; accounts collected via
standalone `collect` (live/offline/hybrid) show blank OU columns.

```bash
aws-iam-grapher query list-accounts
```

```
ACCOUNT ID     ALIAS         OU ID          OU NAME
────────────── ───────────── ────────────── ───────────
111122223333   production                              
222233334444   staging       ou-root1-a1b2  Sandbox
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

**Note:** Neo4j Community supports only a single database. Account isolation is logical (enforced via the `account_id` property on each node), not physical. See [`docs/limitations.md`](docs/limitations.md) for the implications of this design.

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
| `iam-expander` | lib | Expands wildcard IAM actions (`s3:*`) to their full enumerated list via awsiamactions.io |
| `iam-collector` | lib | Collects IAM data from the live AWS API, offline JSON exports, or a hybrid combination of both |
| `iam-graph` | lib | Ingests collected data into Neo4j and executes Cypher analysis queries |
| `iam-grapher` | bin | CLI entry point providing the `collect` and `query` subcommands |
