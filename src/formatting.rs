use serde_json::Value;

use crate::indicator::IndicatorType;

/// Format the general section for an indicator into markdown.
pub fn format_general(indicator: &str, itype: &IndicatorType, data: &Value) -> String {
    let mut out = String::new();

    out.push_str(&format!("# OTX General: `{}`\n\n", indicator));
    out.push_str(&format!(
        "**Type:** {}\n\n",
        itype.api_path().to_uppercase()
    ));

    // Pulse info
    if let Some(pi) = data.get("pulse_info") {
        let count = pi.get("count").and_then(Value::as_u64).unwrap_or(0);
        out.push_str(&format!("## Pulse Info ({} pulses)\n\n", count));
        if let Some(pulses) = pi.get("pulses").and_then(Value::as_array) {
            let top = pulses.iter().take(10);
            for pulse in top {
                let name = str_field(pulse, "name");
                let adversary = str_field(pulse, "adversary");
                let tags: Vec<&str> = pulse
                    .get("tags")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                out.push_str(&format!("- **{}**", name));
                if !adversary.is_empty() {
                    out.push_str(&format!(" | Adversary: {}", adversary));
                }
                if !tags.is_empty() {
                    out.push_str(&format!(" | Tags: {}", tags.join(", ")));
                }
                out.push('\n');
            }
            if pulses.len() > 10 {
                out.push_str(&format!("  _(and {} more)_\n", pulses.len() - 10));
            }
        }
        out.push('\n');
    }

    // Sections
    if let Some(sections) = data.get("sections").and_then(Value::as_array) {
        let names: Vec<&str> = sections.iter().filter_map(Value::as_str).collect();
        if !names.is_empty() {
            out.push_str(&format!("**Sections:** {}\n\n", names.join(", ")));
        }
    }

    // Validation
    if let Some(validation) = data.get("validation").and_then(Value::as_array) {
        if !validation.is_empty() {
            out.push_str("**Validation:**\n");
            for v in validation {
                let msg = str_field(v, "message");
                let source = str_field(v, "source");
                out.push_str(&format!("- {} ({})\n", msg, source));
            }
            out.push('\n');
        }
    }

    // False positive
    if let Some(fp) = data.get("false_positive").and_then(Value::as_array) {
        if !fp.is_empty() {
            out.push_str("**False Positive Flags:** yes\n\n");
        }
    }

    // Type-specific extras
    match itype {
        IndicatorType::IPv4 | IndicatorType::IPv6 => {
            append_kv(&mut out, "ASN", data.get("asn"));
            append_kv(&mut out, "Country", data.get("country_name"));
            append_kv(&mut out, "Reputation", data.get("reputation"));
            if let (Some(lat), Some(lon)) = (data.get("latitude"), data.get("longitude")) {
                out.push_str(&format!("**Coordinates:** {}, {}\n", lat, lon));
            }
        }
        IndicatorType::Domain | IndicatorType::Hostname => {
            append_kv(&mut out, "Alexa", data.get("alexa"));
            if let Some(whois) = data.get("whois") {
                out.push_str(&format!("**Whois:** {}\n", whois));
            }
            if let Some(validation) = data.get("validation").and_then(Value::as_array) {
                for v in validation {
                    let vtype = str_field(v, "name");
                    let vmsg = str_field(v, "message");
                    if !vtype.is_empty() || !vmsg.is_empty() {
                        out.push_str(&format!("- Validation: {} {}\n", vtype, vmsg));
                    }
                }
            }
        }
        IndicatorType::Cve => {
            append_kv(&mut out, "CVSS", data.get("cvss"));
            if let Some(v2) = data.get("cvssv2") {
                append_kv(&mut out, "CVSSv2", Some(v2));
            }
            if let Some(v3) = data.get("cvssv3") {
                append_kv(&mut out, "CVSSv3", Some(v3));
            }
            if let Some(desc) = data.get("description").and_then(Value::as_str) {
                if !desc.is_empty() {
                    out.push_str(&format!("**Description:** {}\n\n", desc));
                }
            }
            if let Some(refs) = data.get("references").and_then(Value::as_array) {
                if !refs.is_empty() {
                    out.push_str("**References:**\n");
                    for r in refs.iter().take(10) {
                        if let Some(s) = r.as_str() {
                            out.push_str(&format!("- {}\n", s));
                        }
                    }
                    out.push('\n');
                }
            }
            append_kv(&mut out, "MITRE URL", data.get("mitre_url"));
            append_kv(&mut out, "NVD URL", data.get("nvd_url"));
            append_kv(&mut out, "EPSS", data.get("epss"));
            if let Some(exploits) = data.get("exploits").and_then(Value::as_array) {
                if !exploits.is_empty() {
                    out.push_str(&format!("**Exploits:** {} known\n", exploits.len()));
                }
            }
        }
        IndicatorType::File => {
            for hash_type in &["sha256", "sha1", "md5"] {
                if let Some(v) = data.get(hash_type).and_then(Value::as_str) {
                    if !v.is_empty() {
                        out.push_str(&format!("**{}:** `{}`\n", hash_type.to_uppercase(), v));
                    }
                }
            }
            if let Some(ftype) = data.get("type").and_then(Value::as_str) {
                out.push_str(&format!("**File Type:** {}\n", ftype));
            }
        }
        IndicatorType::Url => {
            // pulse_info already handled above
        }
        _ => {}
    }

    out
}

/// Format a specific section response into markdown.
pub fn format_section(section: &str, data: &Value) -> String {
    match section {
        "passive_dns" => format_passive_dns(data),
        "malware" => format_malware(data),
        "geo" => format_geo(data),
        "url_list" => format_url_list(data),
        "whois" => format_whois(data),
        "http_scans" => format_http_scans(data),
        "reputation" => format_reputation(data),
        "analysis" => format_analysis(data),
        "nids_list" => format_nids_list(data),
        _ => format_default(data),
    }
}

/// Return a markdown list of available sections for the indicator type.
pub fn format_sections_list(indicator: &str, itype: &IndicatorType) -> String {
    let sections = itype.available_sections();
    let mut out = format!(
        "# Available Sections for `{}` ({})\n\n",
        indicator,
        itype.api_path().to_uppercase()
    );
    for s in sections {
        out.push_str(&format!("- {}\n", s));
    }
    out
}

// --- Section formatters ---

fn format_passive_dns(data: &Value) -> String {
    let entries = data
        .get("passive_dns")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if entries.is_empty() {
        return "No passive DNS data.\n".to_string();
    }
    let total = entries.len();
    let shown = entries.iter().take(25);
    let mut out = format!("## Passive DNS ({} entries)\n\n", total);
    out.push_str("| Hostname | Type | First Seen | Last Seen |\n");
    out.push_str("|----------|------|------------|-----------|\n");
    for e in shown {
        let hostname = str_field(e, "hostname");
        let rtype = str_field(e, "record_type");
        let first = str_field(e, "first");
        let last = str_field(e, "last");
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            hostname, rtype, first, last
        ));
    }
    if total > 25 {
        out.push_str(&format!("\n_(truncated — showing 25 of {})_\n", total));
    }
    out
}

fn format_malware(data: &Value) -> String {
    let entries = data
        .get("data")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if entries.is_empty() {
        return "No malware data.\n".to_string();
    }
    let total = entries.len();
    let shown = entries.iter().take(25);
    let mut out = format!("## Malware Samples ({} entries)\n\n", total);
    out.push_str("| Hash | Date | Detections |\n");
    out.push_str("|------|------|------------|\n");
    for e in shown {
        let hash = str_field(e, "hash");
        let date = str_field(e, "date");
        let detections = e
            .get("detections")
            .and_then(Value::as_object)
            .map(|obj| {
                obj.iter()
                    .filter(|(_, v)| !v.is_null())
                    .map(|(k, v)| format!("{}:{}", k, v))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        out.push_str(&format!("| `{}` | {} | {} |\n", hash, date, detections));
    }
    if total > 25 {
        out.push_str(&format!("\n_(truncated — showing 25 of {})_\n", total));
    }
    out
}

fn format_geo(data: &Value) -> String {
    let mut out = "## Geo Information\n\n".to_string();
    append_kv(&mut out, "Country", data.get("country_name"));
    append_kv(&mut out, "City", data.get("city"));
    if let (Some(lat), Some(lon)) = (data.get("latitude"), data.get("longitude")) {
        out.push_str(&format!("**Coordinates:** {}, {}\n", lat, lon));
    }
    append_kv(&mut out, "ASN", data.get("asn"));
    append_kv(&mut out, "Region", data.get("region"));
    append_kv(&mut out, "Continent", data.get("continent_code"));
    out
}

fn format_url_list(data: &Value) -> String {
    let entries = data
        .get("url_list")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if entries.is_empty() {
        return "No URL list data.\n".to_string();
    }
    let total = entries.len();
    let shown = entries.iter().take(25);
    let mut out = format!("## URL List ({} entries)\n\n", total);
    out.push_str("| URL | Date | HTTP Code |\n");
    out.push_str("|-----|------|----------|\n");
    for e in shown {
        let url = str_field(e, "url");
        let date = str_field(e, "date");
        let httpcode = e
            .get("httpcode")
            .map(|v| v.to_string())
            .unwrap_or_default();
        out.push_str(&format!("| {} | {} | {} |\n", url, date, httpcode));
    }
    if total > 25 {
        out.push_str(&format!("\n_(truncated — showing 25 of {})_\n", total));
    }
    out
}

fn format_whois(data: &Value) -> String {
    let entries = data
        .get("data")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if entries.is_empty() {
        return "No whois data.\n".to_string();
    }
    let mut out = "## Whois\n\n".to_string();
    for e in entries {
        let key = str_field(e, "name");
        let val = str_field(e, "value");
        if !key.is_empty() {
            out.push_str(&format!("**{}:** {}\n", key, val));
        }
    }
    out
}

fn format_http_scans(data: &Value) -> String {
    let entries = data
        .get("data")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if entries.is_empty() {
        return "No HTTP scan data.\n".to_string();
    }
    let mut out = "## HTTP Scans\n\n".to_string();
    for e in entries {
        let key = str_field(e, "name");
        let val = str_field(e, "value");
        if !key.is_empty() {
            out.push_str(&format!("**{}:** {}\n", key, val));
        }
    }
    out
}

fn format_reputation(data: &Value) -> String {
    match data.get("reputation") {
        Some(Value::Null) | None => "**Reputation:** null\n".to_string(),
        Some(v) => format!("**Reputation:** {}\n", v),
    }
}

fn format_analysis(data: &Value) -> String {
    let mut out = "## Analysis\n\n".to_string();
    if let Some(analysis) = data.get("analysis").and_then(Value::as_object) {
        out.push_str("**Analysis keys:** ");
        let keys: Vec<&str> = analysis.keys().map(String::as_str).collect();
        out.push_str(&keys.join(", "));
        out.push_str("\n\n");
    }
    if let Some(page_type) = data.get("page_type").and_then(Value::as_str) {
        out.push_str(&format!("**Page type:** {}\n", page_type));
    }
    out
}

fn format_nids_list(data: &Value) -> String {
    // Try top-level array or nested "nids" key
    let rules: Vec<String> = if let Some(arr) = data.as_array() {
        arr.iter().filter_map(Value::as_str).map(String::from).collect()
    } else if let Some(arr) = data.get("nids_list").and_then(Value::as_array) {
        arr.iter().filter_map(Value::as_str).map(String::from).collect()
    } else {
        vec![]
    };
    if rules.is_empty() {
        return "No NIDS rules.\n".to_string();
    }
    let mut out = format!("## NIDS Rules ({} total)\n\n", rules.len());
    for rule in &rules {
        out.push_str(&format!("```\n{}\n```\n", rule));
    }
    out
}

fn format_default(data: &Value) -> String {
    let pretty = serde_json::to_string_pretty(data).unwrap_or_else(|_| data.to_string());
    let lines: Vec<&str> = pretty.lines().collect();
    let total = lines.len();
    let shown: Vec<&str> = lines.iter().copied().take(50).collect();
    let mut out = shown.join("\n");
    if total > 50 {
        out.push_str(&format!("\n... ({} lines truncated)", total - 50));
    }
    out
}

// --- Helpers ---

fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn append_kv(out: &mut String, label: &str, val: Option<&Value>) {
    if let Some(v) = val {
        if !v.is_null() {
            out.push_str(&format!("**{}:** {}\n", label, v));
        }
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_format_general_ipv4() {
        let data = json!({
            "indicator": "8.8.8.8",
            "type": "IPv4",
            "asn": "AS15169",
            "country_name": "United States",
            "reputation": 0,
            "latitude": 37.751,
            "longitude": -97.822,
            "pulse_info": {
                "count": 2,
                "pulses": [
                    {"name": "Test Pulse", "adversary": "APT1", "tags": ["dns", "google"]}
                ]
            },
            "sections": ["general", "geo"],
            "validation": [],
            "false_positive": []
        });
        let result = format_general("8.8.8.8", &IndicatorType::IPv4, &data);
        assert!(result.contains("AS15169"), "missing ASN");
        assert!(result.contains("United States"), "missing country");
    }

    #[test]
    fn test_format_general_cve() {
        let data = json!({
            "indicator": "CVE-2021-44228",
            "type": "cve",
            "cvss": 10.0,
            "description": "Log4Shell remote code execution vulnerability",
            "pulse_info": {
                "count": 5,
                "pulses": []
            },
            "references": [],
            "sections": ["general"],
            "validation": [],
            "false_positive": []
        });
        let result = format_general("CVE-2021-44228", &IndicatorType::Cve, &data);
        assert!(result.contains("CVE-2021-44228"), "missing indicator name");
        assert!(result.contains("pulse_info") || result.contains("Pulse"), "missing pulse_info section");
    }

    #[test]
    fn test_format_passive_dns() {
        let data = json!({
            "count": 3,
            "passive_dns": [
                {"hostname": "mail.example.com", "record_type": "A", "first": "2023-01-01", "last": "2023-06-01"},
                {"hostname": "smtp.example.com", "record_type": "MX", "first": "2022-05-01", "last": "2023-01-01"},
                {"hostname": "www.example.com",  "record_type": "A", "first": "2021-01-01", "last": "2023-06-15"}
            ]
        });
        let result = format_section("passive_dns", &data);
        assert!(result.contains("mail.example.com"), "missing hostname");
        assert!(result.contains("smtp.example.com"), "missing second hostname");
        assert!(result.contains("MX"), "missing record type");
        // No truncation note for 3 entries
        assert!(!result.contains("truncated"));
    }

    #[test]
    fn test_format_passive_dns_truncation() {
        let entries: Vec<serde_json::Value> = (0..30)
            .map(|i| {
                json!({
                    "hostname": format!("host{}.example.com", i),
                    "record_type": "A",
                    "first": "2023-01-01",
                    "last": "2023-06-01"
                })
            })
            .collect();
        let data = json!({ "passive_dns": entries });
        let result = format_section("passive_dns", &data);
        assert!(result.contains("truncated"), "should show truncation note for 30 entries");
    }

    #[test]
    fn test_format_malware_empty() {
        let data = json!({ "data": [], "count": 0, "size": 0 });
        let result = format_section("malware", &data);
        assert!(result.contains("No malware data"), "should indicate no data");
    }

    #[test]
    fn test_format_sections_list() {
        let result = format_sections_list("8.8.8.8", &IndicatorType::IPv4);
        assert!(result.contains("passive_dns"));
        assert!(result.contains("geo"));
        assert!(result.contains("reputation"));
    }
}
