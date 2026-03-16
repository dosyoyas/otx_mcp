use std::io::Write;
use std::process::{Command, Stdio};

/// Verifies that the MCP server writes only valid JSON-RPC to stdout.
/// Previously, tracing logs (with ANSI escape codes) leaked onto stdout,
/// corrupting the JSON-RPC stream and breaking tool discovery.
#[test]
fn stdout_contains_only_valid_json() {
    let binary = env!("CARGO_BIN_EXE_otx_mcp");

    let mut child = Command::new(binary)
        .env("OTX_API_KEY", "dummy_key_for_testing")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn otx_mcp");

    let stdin = child.stdin.as_mut().unwrap();
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":0,"method":"initialize","params":{{"protocolVersion":"2024-11-05","capabilities":{{}},"clientInfo":{{"name":"test","version":"1.0"}}}}}}"#
    )
    .unwrap();
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","method":"notifications/initialized","params":{{}}}}"#
    )
    .unwrap();
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{{}}}}"#
    )
    .unwrap();
    stdin.flush().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(500));
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("failed to wait");
    let stdout = String::from_utf8(output.stdout).expect("stdout not utf8");

    assert!(!stdout.is_empty(), "expected JSON-RPC output on stdout");

    for line in stdout.lines().filter(|l| !l.is_empty()) {
        assert!(
            serde_json::from_str::<serde_json::Value>(line).is_ok(),
            "stdout line is not valid JSON: {:?}",
            line
        );
    }

    assert!(
        !stdout.contains('\x1B'),
        "stdout contains ANSI escape codes — logs are leaking onto stdout"
    );
}

/// Verifies that tools/list response includes the expected OTX tools.
#[test]
fn tools_list_returns_expected_tools() {
    let binary = env!("CARGO_BIN_EXE_otx_mcp");

    let mut child = Command::new(binary)
        .env("OTX_API_KEY", "dummy_key_for_testing")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn otx_mcp");

    let stdin = child.stdin.as_mut().unwrap();
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":0,"method":"initialize","params":{{"protocolVersion":"2024-11-05","capabilities":{{}},"clientInfo":{{"name":"test","version":"1.0"}}}}}}"#
    )
    .unwrap();
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","method":"notifications/initialized","params":{{}}}}"#
    )
    .unwrap();
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{{}}}}"#
    )
    .unwrap();
    stdin.flush().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(500));
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("failed to wait");
    let stdout = String::from_utf8(output.stdout).expect("stdout not utf8");

    let tools_response = stdout
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| v["id"] == 1)
        .expect("no response found for tools/list (id=1)");

    let tools = tools_response["result"]["tools"]
        .as_array()
        .expect("tools field missing or not an array");

    let tool_names: Vec<&str> = tools
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();

    assert!(tool_names.contains(&"otx_lookup"), "missing otx_lookup tool");
    assert!(
        tool_names.contains(&"otx_indicator_details"),
        "missing otx_indicator_details tool"
    );
    assert!(
        tool_names.contains(&"otx_indicator_sections"),
        "missing otx_indicator_sections tool"
    );
}
