use std::sync::OnceLock;

use crate::ExpanderError;

const BASE_URL: &str = "https://awsiamactions.io";

static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn http_client() -> &'static reqwest::Client {
    CLIENT.get_or_init(reqwest::Client::new)
}

/// Fetches the action list for `service` from awsiamactions.io.
///
/// Expects the endpoint `GET {BASE_URL}/v1/{service}` to return a JSON array
/// of action name strings, e.g. `["GetObject", "PutObject", ...]`.
pub(crate) async fn fetch_actions(service: &str) -> Result<Vec<String>, ExpanderError> {
    let url = format!("{BASE_URL}/v1/{service}");
    let response = http_client().get(&url).send().await?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(ExpanderError::UnknownService(service.to_string()));
    }

    let actions: Vec<String> = response.error_for_status()?.json().await?;
    Ok(actions)
}
