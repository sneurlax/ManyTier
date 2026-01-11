//! Minimal HTTP client for talking to the ManyTier service API on localhost.
//!
//! Uses raw tokio TcpStream to avoid adding a heavy HTTP client dependency.
//! Only supports simple HTTP/1.1 requests to localhost.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// HTTP client for the ManyTier service API.
pub struct ApiClient {
    pub host: String,
    pub port: u16,
    pub auth_token: String,
}

impl ApiClient {
    /// Create a new ApiClient with the given auth token and default host.
    pub fn new(auth_token: String, port: u16) -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port,
            auth_token,
        }
    }

    /// Load auth token from an authtoken.secret file.
    pub fn from_authtoken_file(path: &str, port: u16) -> anyhow::Result<Self> {
        let token = std::fs::read_to_string(path)?.trim().to_string();
        Ok(Self::new(token, port))
    }

    /// Send a GET request to the given path.
    pub async fn get(&self, path: &str) -> anyhow::Result<String> {
        self.request("GET", path, None).await
    }

    /// Send a POST request to the given path with an optional JSON body.
    pub async fn post(&self, path: &str, body: Option<&str>) -> anyhow::Result<String> {
        self.request("POST", path, body).await
    }

    /// Send a DELETE request to the given path.
    pub async fn delete(&self, path: &str) -> anyhow::Result<String> {
        self.request("DELETE", path, None).await
    }

    /// Send an HTTP request and return the response body.
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> anyhow::Result<String> {
        let mut stream = TcpStream::connect(format!("{}:{}", self.host, self.port)).await?;

        let content_length = body.map(|b| b.len()).unwrap_or(0);
        let request = format!(
            "{} {} HTTP/1.1\r\nHost: {}:{}\r\nX-ZT1-Auth: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            method, path, self.host, self.port, self.auth_token,
            content_length, body.unwrap_or("")
        );

        stream.write_all(request.as_bytes()).await?;

        let mut response = String::new();
        stream.read_to_string(&mut response).await?;

        // Parse HTTP response -- extract body after \r\n\r\n
        let body_start = response.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
        Ok(response[body_start..].to_string())
    }
}
