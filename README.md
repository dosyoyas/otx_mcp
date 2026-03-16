# OTX MCP Server

An [MCP](https://modelcontextprotocol.io/) server that exposes [AlienVault OTX](https://otx.alienvault.com/) threat intelligence to Claude and other MCP clients.

## Prerequisites

- [Rust](https://rustup.rs/) (stable toolchain)
- A free AlienVault OTX account and API key — sign up at <https://otx.alienvault.com/api>

## Build

```bash
cargo build --release
```

The binary will be at `./target/release/otx_mcp`.

## Configuration

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "otx": {
      "command": "/absolute/path/to/otx_mcp",
      "env": { "OTX_API_KEY": "your-key" }
    }
  }
}
```

### Claude Code

This repo includes a `.claude/settings.json` that loads the server automatically once built. You just need `OTX_API_KEY` set in your shell environment:

```bash
export OTX_API_KEY=your-api-key
```

To use the server in a different project, add this to that project's `.claude/settings.json`:

```json
{
  "mcpServers": {
    "otx": {
      "command": "/absolute/path/to/otx_mcp",
      "env": { "OTX_API_KEY": "your-key" }
    }
  }
}
```

## Available Tools

| Tool | Description |
|------|-------------|
| `otx_lookup` | Look up an indicator (IP, domain, hash, CVE, URL, email). Auto-detects type and returns general threat context. |
| `otx_indicator_details` | Get a specific section (`geo`, `malware`, `url_list`, `passive_dns`, `whois`, etc.) for an indicator. |
| `otx_indicator_sections` | List available detail sections for an indicator type. |

### Example Prompts

- "Look up 8.8.8.8 in OTX"
- "Check CVE-2021-44228 threat intel"
- "Get passive DNS for google.com"

## Tests

Unit tests (no API key required):

```bash
cargo test
```

Integration tests (requires API key):

```bash
OTX_API_KEY=your-key cargo test -- --ignored
```
