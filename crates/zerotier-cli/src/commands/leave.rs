//! `manytier leave <network-id>` -- leave a ZeroTier network.

use crate::client::ApiClient;

/// Run the leave command: DELETE /network/{id}.
pub async fn run(auth_token: &str, port: u16, network_id: &str) -> anyhow::Result<()> {
    let client = ApiClient::new(auth_token.to_string(), port);
    client.delete(&format!("/network/{}", network_id)).await?;
    println!("200 leave OK");
    Ok(())
}
