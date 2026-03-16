use crate::indicator::{IndicatorError, IndicatorType};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OtxError {
    #[error("OTX_API_KEY env var not set")]
    MissingApiKey,
    #[error("Could not detect indicator type for '{0}'. Specify indicator_type.")]
    DetectionFailed(String),
    #[error("Section '{section}' not valid for {indicator_type}. Valid: {valid}")]
    InvalidSection {
        section: String,
        indicator_type: String,
        valid: String,
    },
    #[error("OTX API error ({status}): {body}")]
    ApiError { status: u16, body: String },
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}

impl From<IndicatorError> for OtxError {
    fn from(e: IndicatorError) -> Self {
        match e {
            IndicatorError::UnknownType(v) => OtxError::DetectionFailed(v),
        }
    }
}

pub struct OtxClient {
    http: reqwest::Client,
    api_key: String,
    base_url: String,
}

impl OtxClient {
    pub fn new() -> Result<Self, OtxError> {
        let api_key = std::env::var("OTX_API_KEY").map_err(|_| OtxError::MissingApiKey)?;
        Ok(Self {
            http: reqwest::Client::new(),
            api_key,
            base_url: "https://otx.alienvault.com/api/v1".to_string(),
        })
    }

    pub async fn get_indicator(
        &self,
        indicator_type: &IndicatorType,
        value: &str,
        section: &str,
    ) -> Result<serde_json::Value, OtxError> {
        let valid_sections = indicator_type.available_sections();
        if !valid_sections.contains(&section) {
            return Err(OtxError::InvalidSection {
                section: section.to_string(),
                indicator_type: format!("{indicator_type:?}"),
                valid: valid_sections.join(", "),
            });
        }

        let url = format!(
            "{}/indicators/{}/{}/{}",
            self.base_url,
            indicator_type.api_path(),
            value,
            section
        );

        let response = self
            .http
            .get(&url)
            .header("X-OTX-API-KEY", &self.api_key)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(OtxError::ApiError {
                status: status.as_u16(),
                body,
            });
        }

        let json = response.json::<serde_json::Value>().await?;
        Ok(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_api_key() {
        std::env::remove_var("OTX_API_KEY");
        let result = OtxClient::new();
        assert!(matches!(result, Err(OtxError::MissingApiKey)));
    }

    #[test]
    fn test_invalid_section_error_message() {
        let err = OtxError::InvalidSection {
            section: "badSection".to_string(),
            indicator_type: "IPv4".to_string(),
            valid: "general, geo".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("badSection"));
        assert!(msg.contains("IPv4"));
        assert!(msg.contains("general, geo"));
    }

    #[tokio::test]
    #[ignore]
    async fn test_fetch_ipv4_general() {
        let client = OtxClient::new().expect("API key required");
        let result = client
            .get_indicator(&IndicatorType::IPv4, "8.8.8.8", "general")
            .await
            .expect("request failed");
        assert!(result.get("indicator").is_some());
        assert!(result.get("type").is_some());
        assert!(result.get("pulse_info").is_some());
    }

    #[tokio::test]
    #[ignore]
    async fn test_fetch_domain_general() {
        let client = OtxClient::new().expect("API key required");
        let result = client
            .get_indicator(&IndicatorType::Domain, "google.com", "general")
            .await
            .expect("request failed");
        assert!(result.get("indicator").is_some());
        assert!(result.get("sections").is_some());
    }

    #[tokio::test]
    #[ignore]
    async fn test_fetch_cve_general() {
        let client = OtxClient::new().expect("API key required");
        let result = client
            .get_indicator(&IndicatorType::Cve, "CVE-2021-44228", "general")
            .await
            .expect("request failed");
        assert!(result.get("cvss").is_some());
        assert!(result.get("pulse_info").is_some());
    }

    #[tokio::test]
    #[ignore]
    async fn test_invalid_section_for_type() {
        let client = OtxClient::new().expect("API key required");
        let result = client
            .get_indicator(&IndicatorType::Email, "test@example.com", "passive_dns")
            .await;
        assert!(matches!(result, Err(OtxError::InvalidSection { .. })));
    }
}
