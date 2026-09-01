use crate::errors::GraphError;
use neo4rs::Graph;

const CONSTRAINTS: &[&str] = &[
    "CREATE CONSTRAINT snapshot_uid IF NOT EXISTS FOR (s:Snapshot) REQUIRE s.id IS UNIQUE",
    "CREATE CONSTRAINT account_uid IF NOT EXISTS FOR (a:AwsAccount) REQUIRE a.id IS UNIQUE",
    "CREATE CONSTRAINT service_prefix IF NOT EXISTS FOR (svc:AwsService) REQUIRE svc.prefix IS UNIQUE",
    "CREATE CONSTRAINT policy_uid IF NOT EXISTS FOR (p:Policy) REQUIRE p.uid IS UNIQUE",
    "CREATE CONSTRAINT inline_policy_uid IF NOT EXISTS FOR (ip:InlinePolicy) REQUIRE ip.uid IS UNIQUE",
    "CREATE CONSTRAINT role_uid IF NOT EXISTS FOR (r:Role) REQUIRE r.uid IS UNIQUE",
    "CREATE CONSTRAINT user_uid IF NOT EXISTS FOR (u:User) REQUIRE u.uid IS UNIQUE",
    "CREATE CONSTRAINT group_uid IF NOT EXISTS FOR (g:Group) REQUIRE g.uid IS UNIQUE",
    "CREATE CONSTRAINT instance_profile_uid IF NOT EXISTS FOR (ip:InstanceProfile) REQUIRE ip.uid IS UNIQUE",
    "CREATE CONSTRAINT permission_action IF NOT EXISTS FOR (perm:Permission) REQUIRE perm.action IS UNIQUE",
];

const INDEXES: &[&str] = &[
    "CREATE INDEX policy_account IF NOT EXISTS FOR (p:Policy) ON (p.account_id)",
    "CREATE INDEX role_account IF NOT EXISTS FOR (r:Role) ON (r.account_id)",
    "CREATE INDEX user_account IF NOT EXISTS FOR (u:User) ON (u.account_id)",
    "CREATE INDEX role_arn IF NOT EXISTS FOR (r:Role) ON (r.arn)",
    "CREATE INDEX user_arn IF NOT EXISTS FOR (u:User) ON (u.arn)",
    "CREATE INDEX role_aws_managed IF NOT EXISTS FOR (r:Role) ON (r.is_aws_managed)",
    "CREATE INDEX snapshot_org_run IF NOT EXISTS FOR (s:Snapshot) ON (s.org_collection_run_id)",
    "CREATE INDEX grants_effect IF NOT EXISTS FOR ()-[g:GRANTS]-() ON (g.effect)",
    "CREATE INDEX grants_snapshot IF NOT EXISTS FOR ()-[g:GRANTS]-() ON (g.snapshot_id)",
    "CREATE INDEX grants_account IF NOT EXISTS FOR ()-[g:GRANTS]-() ON (g.account_id)",
];

/// Run all constraints and indexes against `graph`. Safe to call multiple times.
pub async fn initialize(graph: &Graph) -> Result<(), GraphError> {
    for stmt in CONSTRAINTS.iter().chain(INDEXES.iter()) {
        graph
            .run(neo4rs::query(stmt))
            .await
            .map_err(|e| GraphError::SchemaInit {
                statement: stmt.to_string(),
                source: e,
            })?;
    }
    Ok(())
}
