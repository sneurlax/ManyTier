//! `manytier peers` -- list known peers from the service API.

use crate::client::ApiClient;

/// Run the peers command: GET /peer and print peer table.
pub async fn run(auth_token: &str, port: u16) -> anyhow::Result<()> {
    let client = ApiClient::new(auth_token.to_string(), port);
    let body = client.get("/peer").await?;
    let peers: Vec<serde_json::Value> = serde_json::from_str(&body)?;
    println!(
        "{:<12} {:<8} {:<8} {}",
        "ADDRESS", "ROLE", "LATENCY", "PATHS"
    );
    for peer in &peers {
        let address = peer["address"].as_str().unwrap_or("");
        let role = peer["role"].as_str().unwrap_or("LEAF");
        let latency = peer["latency"].as_i64().unwrap_or(-1);
        let paths: Vec<String> = peer["paths"]
            .as_array()
            .map(|ps| {
                ps.iter()
                    .filter_map(|p| p["address"].as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        println!(
            "{:<12} {:<8} {:<8} {}",
            address,
            role,
            if latency >= 0 {
                format!("{}ms", latency)
            } else {
                "-".to_string()
            },
            paths.join(",")
        );
    }
    Ok(())
}
