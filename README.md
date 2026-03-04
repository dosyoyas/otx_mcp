# OTX MCP Server

An [MCP](https://modelcontextprotocol.io/) server that exposes [AlienVault OTX](https://otx.alienvault.com/) threat intelligence to Claude and other MCP clients.

## Build

```bash
cargo build --release
```

The binary will be at `./target/release/otx_mcp`.

## Configuration

### Environment Variable

```bash
export OTX_KEY_CI=your-api-key
```

Get your API key from <https://otx.alienvault.com/api>.

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "otx": {
      "command": "/absolute/path/to/otx_mcp",
      "env": { "OTX_KEY_CI": "your-key" }
    }
  }
}
```

### Claude Code (project)

Edit `.claude/settings.json` in the project root:

```json
{
  "mcpServers": {
    "otx": {
      "command": "/absolute/path/to/otx_mcp",
      "env": { "OTX_KEY_CI": "your-key" }
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
OTX_KEY_CI=your-key cargo test -- --ignored
```
