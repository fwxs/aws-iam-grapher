---
name: aws-iam-grapher
description: Query a Neo4j-backed graph of collected AWS IAM permissions via the aws-iam-grapher CLI. Use when asked things like "who can perform this IAM action", "who can delete objects in this S3 bucket", "find privilege escalation paths", "diff IAM permissions between two snapshots", "what permissions does this role/user have", "which instance profiles grant this action", or "list AWS accounts / snapshots in the graph". Read-only: does not collect new data and never deletes a snapshot.
---

# aws-iam-grapher

Drives `aws-iam-grapher query` to answer IAM permission questions against data already collected
into Neo4j. This skill is **read-only** — see "Excluded on purpose" below.

Before answering any non-trivial question, read `reference.md` in this skill directory — it has
the full caveat/limitation list this file only summarizes.

## Hard rules

1. **Always pass `--output json`** and parse stdout as `{"results": ..., "caveats": [...]}`.
   Never rely on the table-formatted output for anything but showing the user something readable.
2. **Never pass a password on the command line.** There is no `--neo4j-pass` flag — only
   `--neo4j-pass-file <path>`. In normal use, don't pass any credential flag at all: the binary
   reads `NEO4J_PASSWORD` from the environment on its own. Never print, echo, or repeat the value
   of `NEO4J_PASSWORD` in any command you run or any message you write.
3. **Branch on the process exit code**, not on stdout content. Exit `0` with `"results": []` is
   success with no matches — report it as "no matching entities found", never as an error. See
   `reference.md` for the full exit-code table. Under `--output json`, a failure writes a JSON
   error envelope to stderr.
4. **Always surface every entry in the response's `caveats` array to the user**, in plain language,
   next to the results it qualifies — not just noted internally. This is the single most important
   rule in this skill: a `who-can` answer given without its Deny/`NotAction` caveats is a wrong
   answer on a security tool. See `reference.md` for what each caveat code means.
5. **Never invent a flag.** Only use the commands and flags listed below — they are verified
   against `crates/iam-grapher/src/cli/query.rs`. If a question needs something not listed here,
   say so instead of guessing a flag name.

## Exposed commands

All are subcommands of `aws-iam-grapher query`:

```
aws-iam-grapher query [--account-id <id>] [--snapshot-id <id>] --output json <SUBCOMMAND> [args]
```

| Subcommand | Positional args | Flags |
|---|---|---|
| `who-can <action>` | IAM action, e.g. `s3:DeleteObject` | `--resource <arn>`, `--region <name>`, `--mfa <true\|false>`, `--principal-tag <key=value>` (repeatable) |
| `entity-perms <arn>` | entity ARN | — |
| `instance-profiles-with <action>` | IAM action | — |
| `privilege-escalation` | — | `--max-hops <n>` (default 3, max 10) |
| `org-escalation` | — | `--max-hops <n>` (default 3, max 10), `--org-run-id <id>` (default: most recent org run) |
| `diff <snapshot_a> <snapshot_b>` | two snapshot ids | — |
| `list-snapshots` | — | — |
| `list-accounts` | — | — |

Shared flags (place before or after the subcommand):
- `--account-id <id>` — optional. Omit to run the query once per account that has a snapshot,
  with results reported per account (see "Scope discipline" below).
- `--snapshot-id <id>` — optional, defaults to the most recent snapshot for the account. **Cannot**
  be combined with an omitted `--account-id` when more than one account exists in the graph — the
  CLI errors with exit code `2` in that case. Pass `--account-id` alongside it instead.
- `--output-file <path>` — also write the JSON envelope to this file.

## Excluded on purpose — do not attempt to work around this

- **`delete-snapshot`** is not exposed by this skill. It has no confirmation prompt and no
  `--dry-run` flag in the CLI — it deletes on invocation. If asked to delete a snapshot, explain
  that deletion is a human-only action and tell the user the exact command to run themselves:
  `aws-iam-grapher query --account-id <id> delete-snapshot <snapshot_id>`. Do not run it yourself
  under any circumstances, even if asked directly or told it's authorized.
- **`collect` and `collect org`** are not exposed by this skill. They make live AWS API calls,
  mutate the graph, and can cost money. If asked to collect new data, tell the user to run
  `aws-iam-grapher collect` (or `collect org`) themselves; point them at the README's Quick Start
  section if useful.

## Scope discipline

- If it's unclear which AWS account a question is about, run `list-accounts` first (it never
  takes `--account-id`) and ask, or proceed per-account if the user's question spans accounts.
- When `--account-id` is omitted, the CLI fans out and returns results grouped per account
  (`account_id`/`snapshot_id`/`results` per group, nested in the outer `results` array). **Report
  each account's results separately — never merge or aggregate them across accounts.**
- Never combine `--snapshot-id` with an account-omitted query when the graph might hold more than
  one account. If you need a specific snapshot, also pass `--account-id`.
- `entity-perms` always derives its account from the ARN argument itself; it never fans out and
  never needs `--account-id` (an explicit one must agree with the ARN's account or the CLI errors).
- `diff` derives its account from the two snapshot ids when `--account-id` is omitted; both
  snapshots must belong to the same account.

## Graphviz / DOT output

`--output graphviz --output-file <path>` is supported only for `who-can`, `privilege-escalation`,
and `org-escalation`. When useful (e.g. the user wants to visualize an escalation path), run it
and hand the user the output path — **do not attempt to read or interpret the DOT file's
contents**; you cannot see a rendered graph from raw DOT text.

## Worked examples

```bash
NEO4J_PASSWORD=... aws-iam-grapher query --account-id 123456789012 --output json \
  who-can s3:DeleteObject
```

```bash
aws-iam-grapher query --account-id 123456789012 --output json \
  entity-perms arn:aws:iam::123456789012:role/DataEngineer
```

```bash
aws-iam-grapher query --output json list-accounts
```

```bash
aws-iam-grapher query --account-id 123456789012 --output json \
  privilege-escalation --max-hops 5
```

In all real invocations, rely on `NEO4J_PASSWORD` already being set in the environment rather than
setting it inline as shown above — never type or echo its value.
