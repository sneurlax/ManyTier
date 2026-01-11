//! `manytier join <network-id>` -- join a ZeroTier network.

use crate::client::ApiClient;

/// Run the join command: POST /network/{id}.
pub async fn run(auth_token: &str, port: u16, network_id: &str) -> anyhow::Result<()> {
    let client = ApiClient::new(auth_token.to_string(), port);
    let body = client
        .post(&format!("/network/{}", network_id), None)
        .await?;
    let net: serde_json::Value = serde_json::from_str(&body)?;
    println!("200 join OK");
    println!("  network: {}", net["id"].as_str().unwrap_or(network_id));
    Ok(())
}
