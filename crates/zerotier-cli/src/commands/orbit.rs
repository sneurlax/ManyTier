//! `manytier orbit|deorbit <moon-id>` -- manage custom root servers (moons).

use crate::client::ApiClient;

/// Run orbit (add moon) or deorbit (remove moon) command.
pub async fn run(auth_token: &str, port: u16, moon_id: &str, orbit: bool) -> anyhow::Result<()> {
    let client = ApiClient::new(auth_token.to_string(), port);
    if orbit {
        client
            .post(&format!("/moon/{}", moon_id), None)
            .await?;
        println!("200 orbit OK");
    } else {
        client
            .delete(&format!("/moon/{}", moon_id))
            .await?;
        println!("200 deorbit OK");
    }
    Ok(())
}
