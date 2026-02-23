# py-sandboxrt — Python Sandbox Runtime

[![PyPI version](https://badge.fury.io/py/py-sandboxrt.svg)](https://badge.fury.io/py/py-sandboxrt)
[![CI](https://github.com/saolalab/py-sandboxrt/actions/workflows/ci.yml/badge.svg)](https://github.com/saolalab/py-sandboxrt/actions/workflows/ci.yml)
[![Python Versions](https://img.shields.io/pypi/pyversions/py-sandboxrt.svg)](https://pypi.org/project/py-sandboxrt/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A Python port of the [Anthropic Sandbox Runtime](https://github.com/anthropic-experimental/sandbox-runtime), providing lightweight OS-level sandboxing for arbitrary processes without requiring a container.

`py-sandboxrt` uses native OS sandboxing primitives (`sandbox-exec` on macOS, `bubblewrap` on Linux) and proxy-based network filtering. It can be used to sandbox the behaviour of agents, local MCP servers, bash commands, and arbitrary processes.

## Installation

Install from PyPI using pip:

```bash
pip install py-sandboxrt
```

Or using uv:

```bash
uv add py-sandboxrt
```

### Development Installation

Clone the repository and install in development mode:

```bash
git clone https://github.com/saolalab/py-sandboxrt.git
cd py-sandboxrt
pip install -e ".[dev]"
```

Or with uv:

```bash
uv sync --dev
```

## Quick Start

### CLI

```bash
# Run a command in the sandbox
srt echo "hello world"

# With debug logging
srt --debug curl https://example.com

# Custom settings file
srt --settings /path/to/srt-settings.json npm install

# Command string mode
srt -c "curl https://example.com && echo done"
```

### Library

```python
import asyncio
from srt import SandboxManager, SandboxRuntimeConfig
from srt.config import NetworkConfig, FilesystemConfig

config = SandboxRuntimeConfig(
    network=NetworkConfig(
        allowed_domains=["example.com", "api.github.com"],
        denied_domains=[],
    ),
    filesystem=FilesystemConfig(
        deny_read=["~/.ssh"],
        allow_write=[".", "/tmp"],
        deny_write=[".env"],
    ),
)


async def main():
    mgr = SandboxManager()
    await mgr.initialize(config)

    sandboxed_cmd = await mgr.wrap_with_sandbox("curl https://example.com")

    import subprocess
    proc = subprocess.Popen(sandboxed_cmd, shell=True)
    proc.wait()

    mgr.cleanup_after_command()
    await mgr.reset()


asyncio.run(main())
```

## Configuration

### Settings File

By default, `py-srt` reads `~/.srt-settings.json`. Override with `--settings`:

```bash
srt --settings /path/to/config.json <command>
```

The config file uses the same JSON format as the TypeScript version (camelCase keys are automatically converted):

```json
{
  "network": {
    "allowedDomains": [
      "github.com",
      "*.github.com",
      "npmjs.org",
      "*.npmjs.org"
    ],
    "deniedDomains": ["malicious.com"]
  },
  "filesystem": {
    "denyRead": ["~/.ssh"],
    "allowWrite": [".", "src/", "test/", "/tmp"],
    "denyWrite": [".env", "config/production.json"]
  }
}
```

### Network Configuration (allow-only pattern)

All network access is **denied by default**.

| Key | Description |
|---|---|
| `allowedDomains` | Domains permitted to connect to (supports `*.example.com` wildcards) |
| `deniedDomains` | Domains explicitly blocked (checked first, overrides allow) |
| `allowUnixSockets` | macOS only: specific Unix socket paths to allow |
| `allowAllUnixSockets` | Allow all Unix sockets on both platforms |
| `allowLocalBinding` | Allow binding to local ports (default: false) |

### Filesystem Configuration

| Key | Pattern | Description |
|---|---|---|
| `denyRead` | deny-only | Paths to block reading (default: allow all reads) |
| `allowWrite` | allow-only | Paths to allow writing (default: deny all writes) |
| `denyWrite` | deny-within-allow | Paths to block writing even within allowed paths |

### Mandatory Deny Paths (Auto-Protected)

Certain sensitive files are **always blocked from writes**, even within allowed paths:

- Shell configs: `.bashrc`, `.bash_profile`, `.zshrc`, `.zprofile`, `.profile`
- Git configs: `.gitconfig`, `.gitmodules`
- Other: `.ripgreprc`, `.mcp.json`
- Directories: `.vscode/`, `.idea/`, `.claude/commands/`, `.claude/agents/`, `.git/hooks/`

## How It Works

### Dual Isolation Model

- **macOS**: Uses `sandbox-exec` with dynamically generated Seatbelt profiles
- **Linux**: Uses `bubblewrap` for containerized filesystem and network namespace isolation

### Network Filtering

HTTP and SOCKS5 proxy servers run on the host, filtering all traffic against domain allowlists:

1. **HTTP/HTTPS** — intercepted by an HTTP proxy that validates `CONNECT` tunnels and forwards requests
2. **Other TCP** — handled by a SOCKS5 proxy for SSH, database connections, etc.
3. **Linux bridge** — `socat` relays between Unix sockets (inside sandbox) and TCP ports (host proxies)

### Filesystem Restrictions

- **Read** (deny-only): All reads allowed by default; deny specific paths
- **Write** (allow-only): All writes denied by default; explicitly allow paths
- macOS uses Seatbelt regex/glob matching; Linux uses `bubblewrap` bind mounts

## Architecture

```
src/srt/
├── __init__.py           # Public API exports
├── cli.py                # CLI entrypoint (srt command)
├── config.py             # Pydantic configuration models
├── sandbox_manager.py    # Main orchestrator
├── http_proxy.py         # HTTP/HTTPS proxy with domain filtering
├── socks_proxy.py        # SOCKS5 proxy with domain filtering
├── macos_sandbox.py      # macOS sandbox-exec Seatbelt profiles
├── linux_sandbox.py      # Linux bubblewrap sandboxing
├── sandbox_utils.py      # Shared utilities (paths, globs, env vars)
├── violation_store.py    # In-memory violation tracking
├── platform_utils.py     # Platform detection
└── debug.py              # Debug logging
```

## Platform Support

| Platform | Mechanism | Dependencies |
|---|---|---|
| **macOS** | `sandbox-exec` + Seatbelt profiles | `ripgrep` |
| **Linux** | `bubblewrap` + network namespaces | `bubblewrap`, `socat`, `ripgrep` |
| **Windows** | Not supported | — |

### Installing Dependencies

**macOS:**
```bash
brew install ripgrep
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt-get install bubblewrap socat ripgrep
```

## Debug Logging

Set the `SRT_DEBUG` environment variable to enable verbose logging to stderr:

```bash
SRT_DEBUG=1 srt curl https://example.com
# or
srt --debug curl https://example.com
```

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.

## Credits

Python port of [anthropic-experimental/sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime).
