//! `manytier status` -- show node status from the service API.

use crate::client::ApiClient;

/// Run the status command: GET /status and print node info.
pub async fn run(auth_token: &str, port: u16) -> anyhow::Result<()> {
    let client = ApiClient::new(auth_token.to_string(), port);
    let body = client.get("/status").await?;
    let status: serde_json::Value = serde_json::from_str(&body)?;
    println!(
        "200 info {}",
        status["address"].as_str().unwrap_or("unknown")
    );
    println!(
        "  version: {}",
        status["version"].as_str().unwrap_or("unknown")
    );
    println!(
        "  online: {}",
        status["online"].as_bool().unwrap_or(false)
    );
    Ok(())
}
