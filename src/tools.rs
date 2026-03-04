use std::sync::Arc;

use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_handler, tool_router, ServerHandler};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::formatting::{format_general, format_section, format_sections_list};
use crate::indicator::{self, IndicatorType};
use crate::otx_client::OtxClient;

#[derive(Clone)]
pub struct OtxTools {
    client: Arc<OtxClient>,
    tool_router: ToolRouter<Self>,
}

#[derive(Deserialize, JsonSchema)]
struct LookupParams {
    #[schemars(description = "Indicator value (IP, domain, hash, CVE, URL, email)")]
    indicator: String,
    #[schemars(
        description = "Override auto-detection: IPv4, IPv6, domain, hostname, file, url, cve, email"
    )]
    indicator_type: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct DetailsParams {
    #[schemars(description = "Indicator value")]
    indicator: String,
    #[schemars(
        description = "Section: geo, malware, url_list, passive_dns, whois, http_scans, nids_list, reputation, analysis"
    )]
    section: String,
    #[schemars(description = "Override type: IPv4, IPv6, domain, hostname, file, url, cve, email")]
    indicator_type: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct SectionsParams {
    #[schemars(description = "Indicator value")]
    indicator: String,
    #[schemars(description = "Override type: IPv4, IPv6, domain, hostname, file, url, cve, email")]
    indicator_type: Option<String>,
}

#[tool_router]
impl OtxTools {
    pub fn new(client: Arc<OtxClient>) -> Self {
        Self {
            client,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "Look up an indicator in AlienVault OTX. Auto-detects type (IP, domain, hostname, hash, URL, CVE, email). Returns general info, pulse membership, and threat context."
    )]
    async fn otx_lookup(&self, Parameters(params): Parameters<LookupParams>) -> String {
        let itype = match resolve_type(&params.indicator, params.indicator_type.as_deref()) {
            Ok(t) => t,
            Err(e) => return format!("Error: {e}"),
        };
        match self
            .client
            .get_indicator(&itype, &params.indicator, "general")
            .await
        {
            Ok(data) => format_general(&params.indicator, &itype, &data),
            Err(e) => format!("Error: {e}"),
        }
    }

    #[tool(
        description = "Get detailed data for a specific section of an OTX indicator. Use after otx_lookup to drill into passive_dns, malware, geo, whois, url_list, etc."
    )]
    async fn otx_indicator_details(&self, Parameters(params): Parameters<DetailsParams>) -> String {
        let itype = match resolve_type(&params.indicator, params.indicator_type.as_deref()) {
            Ok(t) => t,
            Err(e) => return format!("Error: {e}"),
        };
        match self
            .client
            .get_indicator(&itype, &params.indicator, &params.section)
            .await
        {
            Ok(data) => format_section(&params.section, &data),
            Err(e) => format!("Error: {e}"),
        }
    }

    #[tool(description = "List available detail sections for an indicator type. No API call made.")]
    async fn otx_indicator_sections(
        &self,
        Parameters(params): Parameters<SectionsParams>,
    ) -> String {
        let itype = match resolve_type(&params.indicator, params.indicator_type.as_deref()) {
            Ok(t) => t,
            Err(e) => return format!("Error: {e}"),
        };
        format_sections_list(&params.indicator, &itype)
    }
}

#[tool_handler]
impl ServerHandler for OtxTools {}

fn resolve_type(indicator: &str, override_type: Option<&str>) -> Result<IndicatorType, String> {
    match override_type {
        Some(t) => parse_type_override(t),
        None => indicator::detect(indicator).map_err(|e| e.to_string()),
    }
}

fn parse_type_override(s: &str) -> Result<IndicatorType, String> {
    match s.to_lowercase().as_str() {
        "ipv4" => Ok(IndicatorType::IPv4),
        "ipv6" => Ok(IndicatorType::IPv6),
        "domain" => Ok(IndicatorType::Domain),
        "hostname" => Ok(IndicatorType::Hostname),
        "file" => Ok(IndicatorType::File),
        "url" => Ok(IndicatorType::Url),
        "cve" => Ok(IndicatorType::Cve),
        "email" => Ok(IndicatorType::Email),
        _ => Err(format!(
            "Unknown type override: {s}. Valid: IPv4, IPv6, domain, hostname, file, url, cve, email"
        )),
    }
}
