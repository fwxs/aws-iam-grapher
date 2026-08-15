pub mod account;
pub mod group;
pub mod instance_profile;
pub mod permission;
pub mod policy;
pub mod relationships;
pub mod role;
pub mod uid;
pub mod user;

/// One UNWIND row: parameter map passed as an element of a `$rows` list param.
pub type Row = std::collections::HashMap<String, neo4rs::BoltType>;
