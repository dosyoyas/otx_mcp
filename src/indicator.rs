use std::net::Ipv6Addr;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq)]
pub enum IndicatorType {
    IPv4,
    IPv6,
    Domain,
    Hostname,
    File,
    Url,
    Cve,
    Email,
    Nids,
    Ja3,
    Bitcoin,
    SslCert,
    Yara,
    Osquery,
}

#[derive(Debug, Error)]
pub enum IndicatorError {
    #[error("Unable to detect indicator type for: {0}")]
    UnknownType(String),
}

impl IndicatorType {
    pub fn api_path(&self) -> &str {
        match self {
            IndicatorType::IPv4 => "IPv4",
            IndicatorType::IPv6 => "IPv6",
            IndicatorType::Domain => "domain",
            IndicatorType::Hostname => "hostname",
            IndicatorType::File => "file",
            IndicatorType::Url => "url",
            IndicatorType::Cve => "cve",
            IndicatorType::Email => "email",
            IndicatorType::Nids => "nids",
            IndicatorType::Ja3 => "ja3",
            IndicatorType::Bitcoin => "bitcoin",
            IndicatorType::SslCert => "ssl",
            IndicatorType::Yara => "yara",
            IndicatorType::Osquery => "osquery",
        }
    }

    pub fn available_sections(&self) -> &[&str] {
        match self {
            IndicatorType::IPv4 => &[
                "general", "geo", "reputation", "url_list", "passive_dns",
                "malware", "nids_list", "http_scans",
            ],
            IndicatorType::IPv6 => &[
                "general", "geo", "reputation", "url_list", "passive_dns",
                "malware", "nids_list", "http_scans",
            ],
            IndicatorType::Domain => &[
                "general", "geo", "url_list", "passive_dns", "malware",
                "whois", "http_scans",
            ],
            IndicatorType::Hostname => &[
                "general", "geo", "url_list", "passive_dns", "malware",
                "whois", "http_scans",
            ],
            IndicatorType::File => &["general", "analysis"],
            IndicatorType::Url => &["general", "url_list", "http_scans", "screenshot"],
            IndicatorType::Cve => &["general", "nids_list", "malware"],
            IndicatorType::Email => &["general"],
            _ => &[],
        }
    }
}

pub fn detect(value: &str) -> Result<IndicatorType, IndicatorError> {
    if is_cve(value) {
        return Ok(IndicatorType::Cve);
    }

    if is_ipv4(value) {
        return Ok(IndicatorType::IPv4);
    }

    if value.contains(':') && Ipv6Addr::from_str(value).is_ok() {
        return Ok(IndicatorType::IPv6);
    }

    if is_email(value) {
        return Ok(IndicatorType::Email);
    }

    if matches!(value.len(), 32 | 40 | 64) && is_hex(value) {
        return Ok(IndicatorType::File);
    }

    if value.starts_with("http://") || value.starts_with("https://") {
        return Ok(IndicatorType::Url);
    }

    if let Some(label_count) = domain_label_count(value) {
        if label_count <= 2 {
            return Ok(IndicatorType::Domain);
        } else {
            return Ok(IndicatorType::Hostname);
        }
    }

    Err(IndicatorError::UnknownType(value.to_string()))
}

fn is_cve(value: &str) -> bool {
    let upper = value.to_uppercase();
    let Some(rest) = upper.strip_prefix("CVE-") else {
        return false;
    };
    let parts: Vec<&str> = rest.splitn(2, '-').collect();
    if parts.len() != 2 {
        return false;
    }
    let year = parts[0];
    let seq = parts[1];
    year.len() == 4
        && year.chars().all(|c| c.is_ascii_digit())
        && seq.len() >= 4
        && seq.chars().all(|c| c.is_ascii_digit())
}

fn is_ipv4(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        if p.is_empty() || p.len() > 3 {
            return false;
        }
        p.parse::<u8>().is_ok()
    })
}

fn is_email(value: &str) -> bool {
    if value.chars().any(|c| c.is_whitespace()) {
        return false;
    }
    let at_count = value.chars().filter(|&c| c == '@').count();
    if at_count != 1 {
        return false;
    }
    let at_pos = value.find('@').unwrap();
    let local = &value[..at_pos];
    let domain_part = &value[at_pos + 1..];
    if local.is_empty() || domain_part.is_empty() {
        return false;
    }
    domain_part.contains('.')
        && !domain_part.starts_with('.')
        && !domain_part.ends_with('.')
}

fn is_hex(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_valid_label(label: &str) -> bool {
    if label.is_empty() {
        return false;
    }
    let bytes = label.as_bytes();
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
        return false;
    }
    bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'-')
}

fn domain_label_count(value: &str) -> Option<usize> {
    let labels: Vec<&str> = value.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    if labels.iter().all(|l| is_valid_label(l)) {
        Some(labels.len())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4() {
        assert_eq!(detect("8.8.8.8").unwrap(), IndicatorType::IPv4);
    }

    #[test]
    fn test_ipv6() {
        assert_eq!(detect("2001:db8::1").unwrap(), IndicatorType::IPv6);
    }

    #[test]
    fn test_domain() {
        assert_eq!(detect("google.com").unwrap(), IndicatorType::Domain);
    }

    #[test]
    fn test_hostname() {
        assert_eq!(detect("mail.google.com").unwrap(), IndicatorType::Hostname);
    }

    #[test]
    fn test_cve_uppercase() {
        assert_eq!(detect("CVE-2021-44228").unwrap(), IndicatorType::Cve);
    }

    #[test]
    fn test_cve_lowercase() {
        assert_eq!(detect("cve-2021-44228").unwrap(), IndicatorType::Cve);
    }

    #[test]
    fn test_email() {
        assert_eq!(detect("user@example.com").unwrap(), IndicatorType::Email);
    }

    #[test]
    fn test_md5() {
        assert_eq!(
            detect("d41d8cd98f00b204e9800998ecf8427e").unwrap(),
            IndicatorType::File
        );
    }

    #[test]
    fn test_sha1() {
        assert_eq!(
            detect("da39a3ee5e6b4b0d3255bfef95601890afd80709").unwrap(),
            IndicatorType::File
        );
    }

    #[test]
    fn test_sha256() {
        assert_eq!(
            detect("6c5360d41bd2b14b1565f5b18e5c203cf512e493571b3bd5f6ba2ef4c7a9b334").unwrap(),
            IndicatorType::File
        );
    }

    #[test]
    fn test_url_http() {
        assert_eq!(detect("http://example.com").unwrap(), IndicatorType::Url);
    }

    #[test]
    fn test_url_https() {
        assert_eq!(
            detect("https://example.com/path").unwrap(),
            IndicatorType::Url
        );
    }

    #[test]
    fn test_unknown() {
        assert!(detect("not-a-valid-thing!").is_err());
    }

    #[test]
    fn test_available_sections_ipv4() {
        let sections = IndicatorType::IPv4.available_sections();
        assert!(sections.contains(&"general"));
        assert!(sections.contains(&"reputation"));
        assert!(sections.contains(&"passive_dns"));
        assert_eq!(sections.len(), 8);
    }

    #[test]
    fn test_available_sections_domain() {
        let sections = IndicatorType::Domain.available_sections();
        assert!(sections.contains(&"whois"));
        assert!(!sections.contains(&"reputation"));
        assert_eq!(sections.len(), 7);
    }

    #[test]
    fn test_available_sections_file() {
        let sections = IndicatorType::File.available_sections();
        assert_eq!(sections, &["general", "analysis"]);
    }

    #[test]
    fn test_available_sections_email() {
        assert_eq!(IndicatorType::Email.available_sections(), &["general"]);
    }

    #[test]
    fn test_api_path_ipv4() {
        assert_eq!(IndicatorType::IPv4.api_path(), "IPv4");
    }

    #[test]
    fn test_api_path_ipv6() {
        assert_eq!(IndicatorType::IPv6.api_path(), "IPv6");
    }

    #[test]
    fn test_api_path_domain() {
        assert_eq!(IndicatorType::Domain.api_path(), "domain");
    }

    #[test]
    fn test_api_path_hostname() {
        assert_eq!(IndicatorType::Hostname.api_path(), "hostname");
    }

    #[test]
    fn test_api_path_file() {
        assert_eq!(IndicatorType::File.api_path(), "file");
    }

    #[test]
    fn test_api_path_url() {
        assert_eq!(IndicatorType::Url.api_path(), "url");
    }

    #[test]
    fn test_api_path_cve() {
        assert_eq!(IndicatorType::Cve.api_path(), "cve");
    }

    #[test]
    fn test_api_path_email() {
        assert_eq!(IndicatorType::Email.api_path(), "email");
    }
}
