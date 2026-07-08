use std::collections::HashMap;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::ExpanderError;

const ACTIONS_URL: &str = "https://www.awsiamactions.io/json";
const USER_AGENT: &str = "aws-iam-grapher";

static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn http_client() -> &'static reqwest::Client {
    CLIENT.get_or_init(reqwest::Client::new)
}

#[derive(Deserialize)]
struct ServiceEntry {
    #[serde(rename = "servicePrefix")]
    prefix: String,
    actions: Vec<ActionEntry>,
}

#[derive(Deserialize)]
struct ActionEntry {
    action: String,
}

/// Fetches the full IAM action catalog from awsiamactions.io.
///
/// Expects `GET {ACTIONS_URL}` to return a JSON array of services, each with
/// a `servicePrefix` and an `actions` list of `{"action": "svc:Name", ...}`
/// entries. The host rejects non-browser clients, so a browser `User-Agent`
/// is required.
pub(crate) async fn fetch_all_actions() -> Result<HashMap<String, Vec<String>>, ExpanderError> {
    let response = http_client()
        .get(ACTIONS_URL)
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .send()
        .await?;

    let services: Vec<ServiceEntry> = response.error_for_status()?.json().await?;
    Ok(parse_services(services))
}

/// Maps each service's `servicePrefix` to its bare (prefix-stripped) action names.
fn parse_services(services: Vec<ServiceEntry>) -> HashMap<String, Vec<String>> {
    services
        .into_iter()
        .map(|entry| {
            let actions = entry
                .actions
                .into_iter()
                .map(|a| match a.action.split_once(':') {
                    Some((_, name)) => name.to_string(),
                    None => a.action,
                })
                .collect();
            (entry.prefix, actions)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_services_strips_prefix_and_keys_by_service_prefix() {
        let services = vec![
            ServiceEntry {
                prefix: "s3".to_string(),
                actions: vec![
                    ActionEntry {
                        action: "s3:GetObject".to_string(),
                    },
                    ActionEntry {
                        action: "s3:PutObject".to_string(),
                    },
                ],
            },
            ServiceEntry {
                prefix: "account".to_string(),
                actions: vec![ActionEntry {
                    action: "account:CloseAccount".to_string(),
                }],
            },
        ];

        let result = parse_services(services);

        assert_eq!(
            result.get("s3"),
            Some(&vec!["GetObject".to_string(), "PutObject".to_string()])
        );
        assert_eq!(
            result.get("account"),
            Some(&vec!["CloseAccount".to_string()])
        );
    }
}
