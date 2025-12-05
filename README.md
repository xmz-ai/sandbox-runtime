# Xmz Sandbox Runtime (srt)

A lightweight sandboxing tool for enforcing filesystem and network restrictions on arbitrary processes at the OS level, without requiring a container.

`srt` uses native OS sandboxing primitives (`sandbox-exec` on macOS, `bubblewrap` on Linux) and proxy-based network filtering. It can be used to sandbox the behaviour of agents, local MCP servers, bash commands and arbitrary processes.

> **Note**
>
> This project is forked from [Anthropic's Sandbox Runtime](https://github.com/anthropics/sandbox-runtime) with significant architectural changes and enhancements. The API has been refactored from a singleton pattern to a flexible class-based architecture that supports multiple concurrent sandbox instances with different configurations.

## Key Differences from Original

This fork introduces several major enhancements based on commit [9c0d868](https://github.com/anthropics/sandbox-runtime/commit/9c0d868acc963b9e8a06d82d3b4fe3d591ff8978):

### Architecture Changes

- **Class-based architecture**: Refactored from singleton pattern to instantiable classes (`NetworkManager` and `SandboxManager`)
- **Dual-mode API**: Simple mode (SandboxManager manages NetworkManager internally) and Advanced mode (share NetworkManager across workers)
- **Multi-worker support**: Multiple concurrent sandbox instances with different filesystem/environment configurations
- **Separated concerns**: Network configuration (proxy lifecycle) now separate from instance configuration (filesystem/env)

### New Features

- **Custom environment variables** ([e647549](https://github.com/xmz-ai/sandbox-runtime/commit/e647549)): Set or inherit environment variables in sandboxed processes
- **Node.js global proxy** ([ccbe204](https://github.com/xmz-ai/sandbox-runtime/commit/ccbe204)): Automatic proxy configuration for Node.js HTTP clients via global-agent
- **WebSocket support** ([2cc0632](https://github.com/xmz-ai/sandbox-runtime/commit/2cc0632)): Handle WebSocket upgrade requests in HTTP proxy
- **Enhanced Linux security**: Improved mandatory deny paths with configurable search depth

### Bug Fixes

- **Empty allowedDomains fix**: Fixed security vulnerability where `allowedDomains: []` didn't block network access
- **Non-existent path handling** ([71d9033](https://github.com/xmz-ai/sandbox-runtime/commit/71d9033)): Improved write-deny for non-existent paths
- **Device file normalization**: Skip normalization for `/dev/*` paths to preserve device access

## Installation

```bash
npm install @xmz-ai/sandbox-runtime
```

Or install globally for CLI usage:

```bash
npm install -g @xmz-ai/sandbox-runtime
```

## Basic Usage

```bash
# Network restrictions
$ srt "curl anthropic.com"
Running: curl anthropic.com
<html>...</html>  # Request succeeds

$ srt "curl example.com"
Running: curl example.com
Connection blocked by network allowlist  # Request blocked

# Filesystem restrictions
$ srt "cat README.md"
Running: cat README.md
# Anthropic Sandb...  # Current directory access allowed

$ srt "cat ~/.ssh/id_rsa"
Running: cat ~/.ssh/id_rsa
cat: /Users/ollie/.ssh/id_rsa: Operation not permitted  # Specific file blocked
```

## Overview

This package provides a standalone sandbox implementation that can be used as both a CLI tool and a library. It's designed with a **secure-by-default** philosophy tailored for common developer use cases: processes start with minimal access, and you explicitly poke only the holes you need.

**Key capabilities:**

- **Network restrictions**: Control which hosts/domains can be accessed via HTTP/HTTPS and other protocols
- **Filesystem restrictions**: Control which files/directories can be read/written
- **Unix socket restrictions**: Control access to local IPC sockets
- **Violation monitoring**: On macOS, tap into the system's sandbox violation log store for real-time alerts

### Example Use Case: Sandboxing MCP Servers

A key use case is sandboxing Model Context Protocol (MCP) servers to restrict their capabilities. For example, to sandbox the filesystem MCP server:

**Without sandboxing** (`.mcp.json`):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem"]
    }
  }
}
```

**With sandboxing** (`.mcp.json`):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "srt",
      "args": ["npx", "-y", "@modelcontextprotocol/server-filesystem"]
    }
  }
}
```

Then configure restrictions in `~/.srt-settings.json`:

```json
{
  "filesystem": {
    "denyRead": [],
    "allowWrite": ["."],
    "denyWrite": ["~/sensitive-folder"]
  },
  "network": {
    "allowedDomains": [],
    "deniedDomains": []
  }
}
```

Now the MCP server will be blocked from writing to the denied path:

```
> Write a file to ~/sensitive-folder
✗ Error: EPERM: operation not permitted, open '/Users/ollie/sensitive-folder/test.txt'
```

## How It Works

The sandbox uses OS-level primitives to enforce restrictions that apply to the entire process tree:

- **macOS**: Uses `sandbox-exec` with dynamically generated [Seatbelt profiles](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf)
- **Linux**: Uses [bubblewrap](https://github.com/containers/bubblewrap) for containerization with network namespace isolation

![0d1c612947c798aef48e6ab4beb7e8544da9d41a-4096x2305](https://github.com/user-attachments/assets/76c838a9-19ef-4d0b-90bb-cbe1917b3551)

### Dual Isolation Model

Both filesystem and network isolation are required for effective sandboxing. Without file isolation, a compromised process could exfiltrate SSH keys or other sensitive files. Without network isolation, a process could escape the sandbox and gain unrestricted network access.

**Filesystem Isolation** enforces read and write restrictions:

- **Read**: Supports two modes depending on platform and configuration:
  - **Deny-only mode** (default on macOS, optional on Linux): By default, read access is allowed everywhere. You can deny specific paths using `denyRead` (e.g., `~/.ssh`). An empty deny list means full read access.
  - **Allow-only mode** (Linux only): By default, read access is denied everywhere. You must explicitly allow paths using `allowRead` (e.g., `/usr`, `.`). System paths like `/usr`, `/bin` are auto-included unless disabled. An empty allow list means no read access (except system paths if enabled). Use `denyRead` to block specific paths within allowed paths.
- **Write** (allow-only pattern): By default, write access is denied everywhere. You must explicitly allow paths (e.g., `.`, `/tmp`). An empty allow list means no write access.

**Network Isolation** (allow-only pattern): By default, all network access is denied. You must explicitly allow domains. An empty allowedDomains list means no network access. Network traffic is routed through proxy servers running on the host:

- **Linux**: Requests are routed via the filesystem over a Unix domain socket. The network namespace of the sandboxed process is removed entirely, so all network traffic must go through the proxies running on the host (listening on Unix sockets that are bind-mounted into the sandbox)

- **macOS**: The Seatbelt profile allows communication only to a specific localhost port. The proxies listen on this port, creating a controlled channel for all network access

Both HTTP/HTTPS (via HTTP proxy) and other TCP traffic (via SOCKS5 proxy) are mediated by these proxies, which enforce your domain allowlists and denylists.

**Changes from Original Architecture:**

This fork has refactored the singleton-based architecture into a class-based system:

- **Before**: `SandboxManager.initialize()` / `SandboxManager.reset()` (static methods, global state)
- **After**: `new SandboxManager()` / `sandbox.initialize()` (instance methods, no global state)

This enables multiple concurrent sandbox instances with different configurations, which was not possible with the original singleton design.

For more details on the original sandboxing approach in Claude Code, see:

- [Claude Code Sandboxing Documentation](https://docs.claude.com/en/docs/claude-code/sandboxing)
- [Beyond Permission Prompts: Making Claude Code More Secure and Autonomous](https://www.anthropic.com/engineering/claude-code-sandboxing)

## Architecture

```
src/
├── index.ts                  # Library exports
├── cli.ts                    # CLI entrypoint (srt command)
├── utils/                    # Shared utilities
│   ├── debug.ts             # Debug logging
│   ├── settings.ts          # Settings reader (permissions + sandbox config)
│   ├── platform.ts          # Platform detection
│   └── exec.ts              # Command execution utilities
└── sandbox/                  # Sandbox implementation
    ├── network-manager.ts    # NetworkManager class (proxy lifecycle)
    ├── sandbox-manager.ts    # SandboxManager class (per-instance restrictions)
    ├── sandbox-config.ts     # Zod schemas and TypeScript types
    ├── sandbox-schemas.ts    # Internal restriction schemas
    ├── sandbox-violation-store.ts # Violation tracking
    ├── sandbox-utils.ts      # Shared sandbox utilities
    ├── sandbox-dependencies.ts # Dependency checking
    ├── http-proxy.ts         # HTTP/HTTPS proxy for network filtering
    ├── socks-proxy.ts        # SOCKS5 proxy for network filtering
    ├── linux-sandbox-utils.ts # Linux bubblewrap sandboxing
    ├── linux-network-bridge.ts # Linux Unix socket bridge (socat)
    └── macos-sandbox-utils.ts # macOS sandbox-exec sandboxing (Seatbelt profiles)
```

**Key Components:**

- **NetworkManager**: Manages HTTP/SOCKS proxy servers for network filtering. Can be shared across multiple SandboxManager instances or created per-instance.

- **SandboxManager**: Manages filesystem/environment restrictions for a specific sandbox instance. Multiple instances can run concurrently with different configurations.

- **Platform-specific utilities**: Linux uses `bubblewrap` for containerization, macOS uses `sandbox-exec` with dynamically generated Seatbelt profiles.

## Usage

### As a CLI tool

The `srt` command (Anthropic Sandbox Runtime) wraps any command with security boundaries:

```bash
# Run a command in the sandbox
srt echo "hello world"

# With debug logging
srt --debug curl https://example.com

# Specify custom settings file
srt --settings /path/to/srt-settings.json npm install
```

### As a library

#### Simple Mode: Single Sandbox Instance

For single-process applications or when you don't need to share network proxies:

```typescript
import { SandboxManager } from '@xmz-ai/sandbox-runtime'
import { spawn } from 'child_process'

// Create SandboxManager with network and filesystem configuration
// SandboxManager will create and manage its own NetworkManager internally
const sandbox = new SandboxManager(
  // Network config
  {
    allowedDomains: ['example.com', 'api.github.com'],
    deniedDomains: [],
  },
  // Sandbox instance config
  {
    filesystem: {
      denyRead: ['~/.ssh'],
      allowWrite: ['.', '/tmp'],
      denyWrite: ['.env'],
    },
  },
)

// Initialize network proxies (required in simple mode)
await sandbox.initialize()

// Wrap a command with sandbox restrictions
const sandboxedCommand = await sandbox.wrapWithSandbox(
  'curl https://example.com',
)

// Execute the sandboxed command
const child = spawn(sandboxedCommand, { shell: true, stdio: 'inherit' })

// Handle exit
child.on('exit', async code => {
  console.log(`Command exited with code ${code}`)

  // Cleanup - automatically shuts down network proxies
  await sandbox.dispose()
})
```

#### Advanced Mode: Multiple Workers with Shared Network Proxy

For daemon processes that spawn multiple workers with different configurations but shared network filtering:

```typescript
import { NetworkManager, SandboxManager } from '@xmz-ai/sandbox-runtime'

// Create shared NetworkManager (used by all workers)
const networkManager = new NetworkManager()
await networkManager.initialize({
  allowedDomains: ['github.com', '*.npmjs.org'],
  deniedDomains: [],
})

// Create Worker 1 with specific filesystem config
const worker1Sandbox = new SandboxManager(networkManager, {
  filesystem: {
    allowWrite: ['/workspace/project1'],
  },
  env: {
    NODE_ENV: 'development',
  },
})

// Create Worker 2 with different filesystem config
const worker2Sandbox = new SandboxManager(networkManager, {
  filesystem: {
    allowWrite: ['/workspace/project2'],
  },
  env: {
    NODE_ENV: 'production',
  },
})

// Each worker can execute commands with its own restrictions
const cmd1 = await worker1Sandbox.wrapWithSandbox('npm install')
const cmd2 = await worker2Sandbox.wrapWithSandbox('python build.py')

// Cleanup - dispose workers first, then shutdown shared network
worker1Sandbox.dispose() // Does NOT shutdown network (not owned)
worker2Sandbox.dispose() // Does NOT shutdown network (not owned)
await networkManager.shutdown() // Manually shutdown shared network proxies
```

**Key differences between modes:**

- **Simple mode**: Pass `NetworkConfig` as first parameter. SandboxManager creates and manages its own NetworkManager. Call `sandbox.initialize()` before use, and `sandbox.dispose()` shuts down both sandbox and network.

- **Advanced mode**: Pass `NetworkManager` instance as first parameter. You control when to create and shutdown the NetworkManager. Multiple SandboxManager instances can share one NetworkManager. `sandbox.dispose()` only cleans up the instance, not the shared NetworkManager.

#### Available Exports

```typescript
// Core classes
import {
  NetworkManager, // Manages HTTP/SOCKS proxies for network filtering
  SandboxManager, // Manages sandbox instances with filesystem/env restrictions
  SandboxViolationStore, // Tracks sandbox violations
} from '@xmz-ai/sandbox-runtime'

// Configuration types
import type {
  NetworkConfig, // Network configuration (allowedDomains, etc.)
  SandboxInstanceConfig, // Per-instance config (filesystem, env)
  SandboxOptions, // Optional constructor options
  FilesystemConfig, // Filesystem restrictions
  IgnoreViolationsConfig, // Violation filtering rules
  EnvConfig, // Environment variable config
  RipgrepConfig, // Custom ripgrep configuration
} from '@xmz-ai/sandbox-runtime'

// Internal types (for advanced usage)
import type {
  NetworkContext, // Network context (proxy ports, Linux bridges)
  FsReadRestrictionConfig, // Internal read restriction format
  FsWriteRestrictionConfig, // Internal write restriction format
} from '@xmz-ai/sandbox-runtime'
```

**Constructor Signatures:**

```typescript
// Simple mode
new SandboxManager(
  networkConfig: NetworkConfig,
  instanceConfig: SandboxInstanceConfig,
  options?: SandboxOptions
)

// Advanced mode
new SandboxManager(
  networkManager: NetworkManager,
  instanceConfig: SandboxInstanceConfig,
  options?: SandboxOptions
)
```

## Configuration

### Settings File Location

By default, the sandbox runtime looks for configuration at `~/.srt-settings.json`. You can specify a custom path using the `--settings` flag:

```bash
srt --settings /path/to/srt-settings.json <command>
```

### Configuration Reference

#### NetworkConfig (for NetworkManager or simple mode)

```typescript
interface NetworkConfig {
  allowedDomains: string[] // Allowed domains (supports wildcards like "*.example.com")
  deniedDomains: string[] // Denied domains (checked first, takes precedence)
  allowUnixSockets?: string[] // Unix socket paths to allow (macOS only)
  allowAllUnixSockets?: boolean // Allow all Unix sockets (Linux only)
  allowLocalBinding?: boolean // Allow binding to local ports (default: false)
  httpProxyPort?: number // Use external HTTP proxy instead of starting one
  socksProxyPort?: number // Use external SOCKS proxy instead of starting one
}
```

#### SandboxInstanceConfig (for SandboxManager)

```typescript
interface SandboxInstanceConfig {
  filesystem: FilesystemConfig
  env?: Record<string, string | null> // Environment variables (null = inherit from host)
  ignoreViolations?: Record<string, string[]> // Violation filtering rules
  enableWeakerNestedSandbox?: boolean // Weaker mode for Docker (Linux only)
  ripgrep?: { command: string; args?: string[] } // Custom ripgrep config
  mandatoryDenySearchDepth?: number // Max depth for dangerous file search (1-10, default: 3)
  allowPty?: boolean // Allow pseudo-terminal operations (macOS only, for tmux/screen)
}
```

#### SandboxOptions (optional constructor parameter)

```typescript
interface SandboxOptions {
  enableLogMonitor?: boolean // Enable macOS sandbox log monitoring (default: false)
}
```

### Complete Configuration Example

**Example 1: Standard mode with simplified domain patterns:**

```json
{
  "network": {
    "allowedDomains": [
      ".github.com",  // Matches github.com AND all subdomains (simplified!)
      ".npmjs.org"    // Matches npmjs.org AND all subdomains
    ],
    "deniedDomains": ["malicious.com"],
    "allowUnixSockets": ["/var/run/docker.sock"],
    "allowLocalBinding": false
  },
  "filesystem": {
    "denyRead": ["~/.ssh"],
    "allowWrite": [".", "src/", "test/", "/tmp"],
    "denyWrite": [".env", "config/production.json"]
  },
  "ignoreViolations": {
    "*": ["/usr/bin", "/System"],
    "git push": ["/usr/bin/nc"],
    "npm": ["/private/tmp"]
  },
  "allowPty": false,
  "enableWeakerNestedSandbox": false
}
```

**Example 2: Allow-all mode for development:**

```json
{
  "network": {
    "allowedDomains": "*",  // Allow all domains (string, not array)
    "deniedDomains": [".internal-corp.com", "malicious.com"]  // Block internal and known bad domains
  },
  "filesystem": {
    "denyRead": ["~/.ssh"],
    "allowWrite": ["."],
    "denyWrite": [".env"]
  }
}
```

**Example 3: Deny-all mode with strict whitelist (Linux only):**

```json
{
  "network": {
    "allowedDomains": ["github.com", "npmjs.org"],  // Only these domains allowed
    "deniedDomains": "*"  // Deny all by default (string, not array)
  },
  "filesystem": {
    "allowRead": [".", "src/", "test/", "/tmp"],
    "denyRead": [".env", "secrets.json", ".aws/credentials"],
    "autoAllowSystemPaths": true,
    "allowWrite": [".", "src/", "test/", "/tmp"],
    "denyWrite": [".env", ".git"]
  },
  "allowPty": false,
  "mandatoryDenySearchDepth": 3,
  "enableWeakerNestedSandbox": false
}
```

**Example with PTY support for tmux/screen (macOS only):**

```json
{
  "network": {
    "allowedDomains": ["github.com"],
    "deniedDomains": []
  },
  "filesystem": {
    "allowWrite": ["."]
  },
  "allowPty": true
}
```

When `allowPty` is `true` on macOS, the sandbox allows pseudo-terminal operations needed by terminal multiplexers like tmux, screen, and the `script` command. This is disabled by default for security.

### Configuration Options

#### Network Configuration

Uses flexible filtering modes with multiple pattern types.

**Configuration Fields:**

- `network.allowedDomains` - Allowed domain patterns. Can be:
  - `"*"` (string) - Allow-all mode: permits all domains except those in `deniedDomains`
  - Array of patterns - Standard mode: only listed patterns are allowed
- `network.deniedDomains` - Denied domain patterns. Can be:
  - `"*"` (string) - Deny-all mode: blocks all domains except those in `allowedDomains`
  - Array of patterns - Block specific domains (takes precedence over `allowedDomains`)
- `network.allowUnixSockets` - Array of Unix socket paths that can be accessed (macOS only)
- `network.allowLocalBinding` - Allow binding to local ports (boolean, default: false)

**Domain Pattern Types:**

- **Exact match**: `"example.com"` - matches only `example.com`
- **Subdomain wildcard**: `"*.example.com"` - matches `api.example.com`, `sub.api.example.com`, but NOT `example.com`
- **Full wildcard**: `".example.com"` - matches `example.com` AND all subdomains (e.g., `api.example.com`, `sub.api.example.com`)
- **Match all**: `"*"` - matches any domain (must be a string, not in array)
- **localhost**: `"localhost"` - matches localhost

**Filtering Modes:**

1. **Standard mode** (default): `allowedDomains` is an array
   - Default: deny all
   - Check `deniedDomains` first (if matches, deny)
   - Then check `allowedDomains` (if matches, allow)
   - Otherwise, deny

2. **Allow-all mode**: `allowedDomains: "*"`
   - Default: allow all
   - Only `deniedDomains` can block access
   - Useful for development or when network filtering is handled externally

3. **Deny-all mode**: `deniedDomains: "*"`
   - Default: deny all
   - Only `allowedDomains` can permit access
   - Strictest mode: explicit whitelist only

#### Filesystem Configuration

**Read restrictions** support two modes:

**Deny-only mode** (backward compatible):

- `filesystem.denyRead` - Array of paths to deny read access. By default, all paths are readable except the denied ones.
- **Supported on**: Linux and macOS
- **Use case**: When you want to allow broad read access but block specific sensitive paths (e.g., `~/.ssh`, credentials files)
- **Example**: `"denyRead": ["~/.ssh", "~/.aws"]` means everything is readable except those paths

**Allow-only mode** (more secure):

- `filesystem.allowRead` - Array of paths to allow read access. By default, only specified paths are readable.
- `filesystem.denyRead` - When used with `allowRead`, this denies specific paths within the allowed paths (deny-within-allow pattern).
- `filesystem.autoAllowSystemPaths` - Boolean (default: `true`). Automatically include system paths (like `/usr`, `/bin`, `/lib`) needed for commands to execute.
- **Supported on**: Linux only (macOS does not support this mode due to sandbox-exec limitations)
- **Use case**: When you want maximum security and explicit control over what can be read
- **Example**: `"allowRead": [".", "/tmp"], "denyRead": [".env", "secrets.json"]` with `autoAllowSystemPaths: true` means only those paths (plus system paths) are readable, except `.env` and `secrets.json` are blocked

**Important notes:**

- **denyRead semantics**: The meaning of `denyRead` depends on whether you use `allowRead`:
  - **Without `allowRead`** (deny-only mode): `denyRead` globally denies paths
  - **With `allowRead`** (allow-only mode): `denyRead` denies paths within allowed paths
- **macOS limitation**: macOS only supports deny-only mode. If you specify `allowRead` on macOS, an error will be thrown
- **Linux supports both**: On Linux, you can use `denyRead` alone (deny-only) or combine `allowRead` + `denyRead` (allow-only with exceptions)
- **Default behavior**: If neither is specified, no read restrictions are applied (all reads allowed)

**Write restrictions** (allow-only pattern) - all writes denied by default:

- `filesystem.allowWrite` - Array of paths to allow write access. Empty array = no write access.
- `filesystem.denyWrite` - Array of paths to deny write access within allowed paths (takes precedence over allowWrite)

**Path Syntax (macOS):**

Paths support git-style glob patterns on macOS, similar to `.gitignore` syntax:

- `*` - Matches any characters except `/` (e.g., `*.ts` matches `foo.ts` but not `foo/bar.ts`)
- `**` - Matches any characters including `/` (e.g., `src/**/*.ts` matches all `.ts` files in `src/`)
- `?` - Matches any single character except `/` (e.g., `file?.txt` matches `file1.txt`)
- `[abc]` - Matches any character in the set (e.g., `file[0-9].txt` matches `file3.txt`)

Examples:

- `"allowWrite": ["src/"]` - Allow write to entire `src/` directory
- `"allowWrite": ["src/**/*.ts"]` - Allow write to all `.ts` files in `src/` and subdirectories
- `"denyRead": ["~/.ssh"]` - Deny read to SSH directory
- `"denyWrite": [".env"]` - Deny write to `.env` file (even if current directory is allowed)

**Path Syntax (Linux):**

**Linux currently does not support glob matching.** Use literal paths only:

- `"allowWrite": ["src/"]` - Allow write to `src/` directory
- `"denyRead": ["/home/user/.ssh"]` - Deny read to SSH directory

**All platforms:**

- Paths can be absolute (e.g., `/home/user/.ssh`) or relative to the current working directory (e.g., `./src`)
- `~` expands to the user's home directory

#### Other Configuration

- `ignoreViolations` - Object mapping command patterns to arrays of paths where violations should be ignored (macOS only)
- `allowPty` - Allow pseudo-terminal (PTY) operations for tmux and other terminal multiplexers (macOS only, default: false)
- `enableWeakerNestedSandbox` - Enable weaker sandbox mode for Docker environments (Linux only, default: false)
- `mandatoryDenySearchDepth` - Maximum directory depth to search for dangerous files (Linux only, 1-10, default: 3)
- `ripgrep` - Custom ripgrep configuration for file scanning (Linux only)
- `env` - Custom environment variables to set in sandboxed processes (string value or null to inherit from host)

### Pattern Migration Guide

The new `.example.com` pattern simplifies configuration by matching both the base domain and all subdomains with a single rule.

**Before (multiple rules needed):**
```json
{
  "allowedDomains": ["github.com", "*.github.com"]  // Two rules for base + subdomains
}
```

**After (single rule):**
```json
{
  "allowedDomains": [".github.com"]  // One rule matches both!
}
```

**Pattern comparison:**

| Pattern | Matches `example.com` | Matches `api.example.com` | Matches `deep.api.example.com` |
|---------|---------------------|-------------------------|------------------------------|
| `"example.com"` | ✅ Yes | ❌ No | ❌ No |
| `"*.example.com"` | ❌ No | ✅ Yes | ✅ Yes |
| `".example.com"` (NEW) | ✅ Yes | ✅ Yes | ✅ Yes |
| `"*"` (NEW) | ✅ Yes | ✅ Yes | ✅ Yes |

### Common Configuration Recipes

**Allow GitHub access** (simplified with new pattern):

```json
{
  "network": {
    "allowedDomains": [".github.com"],  // Matches github.com AND all subdomains!
    "deniedDomains": []
  },
  "filesystem": {
    "denyRead": [],
    "allowWrite": ["."],
    "denyWrite": []
  }
}
```

**Restrict to specific directories (deny-only mode):**

```json
{
  "network": {
    "allowedDomains": [],
    "deniedDomains": []
  },
  "filesystem": {
    "denyRead": ["~/.ssh"],
    "allowWrite": [".", "src/", "test/"],
    "denyWrite": [".env", "secrets/"]
  }
}
```

**Maximum security: only allow reading specific directories (allow-only mode, Linux only):**

```json
{
  "network": {
    "allowedDomains": [],
    "deniedDomains": []
  },
  "filesystem": {
    "allowRead": [".", "/tmp"],
    "denyRead": [".env", "secrets.json"],
    "autoAllowSystemPaths": true,
    "allowWrite": ["."],
    "denyWrite": [".env", ".git"]
  }
}
```

This configuration (Linux only):

- Only allows reading the current directory and `/tmp`
- Blocks reading `.env` and `secrets.json` even within the current directory
- Automatically includes system paths (`/usr`, `/bin`, `/lib`, etc.) for commands to execute
- Only allows writing to the current directory
- Blocks writing to `.env` and `.git` even within the current directory
- **Note**: On macOS, this will fall back to deny-only mode (no read restrictions)

**Sandbox MCP servers or AI agents (development mode):**

```json
{
  "network": {
    "allowedDomains": "*",  // Allow all for development
    "deniedDomains": [".internal-company.com"]  // Block internal domains
  },
  "filesystem": {
    "allowRead": ["/path/to/project"],
    "denyRead": ["/path/to/project/.env", "/path/to/project/secrets.json"],
    "autoAllowSystemPaths": true,
    "allowWrite": ["/path/to/project"],
    "denyWrite": ["/path/to/project/.env", "/path/to/project/.git"]
  },
  "env": {
    "NODE_ENV": "production",
    "PATH": null,
    "HOME": null
  }
}
```

This configuration:

- Restricts access to a specific project directory
- Blocks sensitive files like SSH keys, AWS credentials, and secrets
- Sets `NODE_ENV` to a specific value
- Inherits `PATH` and `HOME` from the host environment (null = inherit)

### Common Issues and Tips

**Running Jest:** Use `--no-watchman` flag to avoid sandbox violations:

```bash
srt "jest --no-watchman"
```

Watchman accesses files outside the sandbox boundaries, which will trigger permission errors. Disabling it allows Jest to run with the built-in file watcher instead.

## Platform Support

- **macOS**: Uses `sandbox-exec` with custom profiles (no additional dependencies)
- **Linux**: Uses `bubblewrap` (bwrap) for containerization
- **Windows**: Not yet supported

### Platform-Specific Dependencies

**Linux requires:**

- `bubblewrap` - Container runtime
  - Ubuntu/Debian: `apt-get install bubblewrap`
  - Fedora: `dnf install bubblewrap`
  - Arch: `pacman -S bubblewrap`
- `socat` - Socket relay for proxy bridging
  - Ubuntu/Debian: `apt-get install socat`
  - Fedora: `dnf install socat`
  - Arch: `pacman -S socat`
- `ripgrep` - Fast search tool for deny path detection
  - Ubuntu/Debian: `apt-get install ripgrep`
  - Fedora: `dnf install ripgrep`
  - Arch: `pacman -S ripgrep`

**Optional Linux dependencies (for seccomp fallback):**

The package includes pre-generated seccomp BPF filters for x86-64 and arm architectures. These dependencies are only needed if you are on a different architecture where pre-generated filters are not available:

- `gcc` or `clang` - C compiler
- `libseccomp-dev` - Seccomp library development files
  - Ubuntu/Debian: `apt-get install gcc libseccomp-dev`
  - Fedora: `dnf install gcc libseccomp-devel`
  - Arch: `pacman -S gcc libseccomp`

**macOS requires:**

- `ripgrep` - Fast search tool for deny path detection
  - Install via Homebrew: `brew install ripgrep`
  - Or download from: https://github.com/BurntSushi/ripgrep/releases

**Note**: On macOS, `ripgrep` is only required if you plan to use custom ripgrep configurations. The built-in `rg` command is sufficient for normal usage.

## Development

```bash
# Install dependencies
npm install

# Build the project
npm run build

# Build seccomp binaries (requires Docker)
npm run build:seccomp

# Run tests
npm test

# Run integration tests
npm run test:integration

# Type checking
npm run typecheck

# Lint code
npm run lint

# Format code
npm run format
```

### Building Seccomp Binaries

The pre-generated BPF filters are included in the repository, but you can rebuild them if needed:

```bash
npm run build:seccomp
```

This script uses Docker to cross-compile seccomp binaries for multiple architectures:

- x64 (x86-64)
- arm64 (aarch64)

The script builds static generator binaries, generates the BPF filters (~104 bytes each), and stores them in `vendor/seccomp/x64/` and `vendor/seccomp/arm64/`. The generator binaries are removed to keep the package size small.

## Implementation Details

### Network Isolation Architecture

The sandbox runs HTTP and SOCKS5 proxy servers on the host machine that filter all network requests based on permission rules:

1. **HTTP/HTTPS Traffic**: An HTTP proxy server intercepts requests and validates them against allowed/denied domains
2. **Other Network Traffic**: A SOCKS5 proxy handles all other TCP connections (SSH, database connections, etc.)
3. **Permission Enforcement**: The proxies enforce the `permissions` rules from your configuration

**Platform-specific proxy communication:**

- **Linux**: Requests are routed via the filesystem over Unix domain sockets (using `socat` for bridging). The network namespace is removed from the bubblewrap container, ensuring all network traffic must go through the proxies.

- **macOS**: The Seatbelt profile allows communication only to specific localhost ports where the proxies listen. All other network access is blocked.

### Filesystem Isolation

Filesystem restrictions are enforced at the OS level:

- **macOS**: Uses `sandbox-exec` with dynamically generated Seatbelt profiles that specify allowed read/write paths
- **Linux**: Uses `bubblewrap` with bind mounts, marking directories as read-only or read-write based on configuration

**Default filesystem permissions:**

- **Read** (deny-only): Allowed everywhere by default. You can deny specific paths.

  - Example: `denyRead: ["~/.ssh"]` to block access to SSH keys
  - Empty `denyRead: []` = full read access (nothing denied)

- **Write** (allow-only): Denied everywhere by default. You must explicitly allow paths.
  - Example: `allowWrite: [".", "/tmp"]` to allow writes to current directory and /tmp
  - Empty `allowWrite: []` = no write access (nothing allowed)
  - `denyWrite` creates exceptions within allowed paths

This model lets you start with broad read access but maximally restricted write access, then explicitly open the holes you need.

### Mandatory Deny Paths (Auto-Protected Files)

Certain sensitive files and directories are **always blocked from writes**, even if they fall within an allowed write path. This provides defense-in-depth against sandbox escapes and configuration tampering.

**Always-blocked files:**

- Shell config files: `.bashrc`, `.bash_profile`, `.zshrc`, `.zprofile`, `.profile`
- Git config files: `.gitconfig`, `.gitmodules`
- Other sensitive files: `.ripgreprc`, `.mcp.json`

**Always-blocked directories:**

- IDE directories: `.vscode/`, `.idea/`
- Claude config directories: `.claude/commands/`, `.claude/agents/`
- Git hooks and config: `.git/hooks/`, `.git/config`

These paths are blocked automatically - you don't need to add them to `denyWrite`. For example, even with `allowWrite: ["."]`, writing to `.bashrc` or `.git/hooks/pre-commit` will fail:

```bash
$ srt 'echo "malicious" >> .bashrc'
/bin/bash: .bashrc: Operation not permitted

$ srt 'echo "bad" > .git/hooks/pre-commit'
/bin/bash: .git/hooks/pre-commit: Operation not permitted
```

**Note (Linux):** On Linux, mandatory deny paths only block files that already exist. Non-existent files in these patterns cannot be blocked by bubblewrap's bind-mount approach. macOS uses glob patterns which block both existing and new files.

**Linux search depth:** On Linux, the sandbox uses `ripgrep` to scan for dangerous files in subdirectories within allowed write paths. By default, it searches up to 3 levels deep for performance. You can configure this with `mandatoryDenySearchDepth`:

```json
{
  "mandatoryDenySearchDepth": 5,
  "filesystem": {
    "allowWrite": ["."]
  }
}
```

- Default: `3` (searches up to 3 levels deep)
- Range: `1` to `10`
- Higher values provide more protection but slower performance
- Files in CWD (depth 0) are always protected regardless of this setting

### Unix Socket Restrictions (Linux)

On Linux, the sandbox uses **seccomp BPF (Berkeley Packet Filter)** to block Unix domain socket creation at the syscall level. This provides an additional layer of security to prevent processes from creating new Unix domain sockets for local IPC (unless explicitly allowed).

**How it works:**

1. **Pre-generated BPF filters**: The package includes pre-compiled BPF filters for different architectures (x64, ARM64). These are ~104 bytes each and stored in `vendor/seccomp/`. The filters are architecture-specific but libc-independent, so they work with both glibc and musl.

2. **Runtime detection**: The sandbox automatically detects your system's architecture and loads the appropriate pre-generated BPF filter.

3. **Syscall filtering**: The BPF filter intercepts the `socket()` syscall and blocks creation of `AF_UNIX` sockets by returning `EPERM`. This prevents sandboxed code from creating new Unix domain sockets.

4. **Two-stage application using apply-seccomp binary**:
   - Outer bwrap creates the sandbox with filesystem, network, and PID namespace restrictions
   - Network bridging processes (socat) start inside the sandbox (need Unix sockets)
   - apply-seccomp binary applies the seccomp filter via `prctl()`
   - apply-seccomp execs the user command with seccomp active
   - User command runs with all sandbox restrictions plus Unix socket creation blocking

**Security limitations**: The filter only blocks `socket(AF_UNIX, ...)` syscalls. It does not prevent operations on Unix socket file descriptors inherited from parent processes or passed via `SCM_RIGHTS`. For most sandboxing scenarios, blocking socket creation is sufficient to prevent unauthorized IPC.

**Zero runtime dependencies**: Pre-built static apply-seccomp binaries and pre-generated BPF filters are included for x64 and arm64 architectures. No compilation tools or external dependencies required at runtime.

**Architecture support**: x64 and arm64 are fully supported with pre-built binaries. Other architectures are not currently supported. To use sandboxing without Unix socket blocking on unsupported architectures, set `allowAllUnixSockets: true` in your configuration.

### Violation Detection and Monitoring

When a sandboxed process attempts to access a restricted resource:

1. **Blocks the operation** at the OS level (returns `EPERM` error)
2. **Logs the violation** (platform-specific mechanisms)
3. **Notifies the user** (in Claude Code, this triggers a permission prompt)

**macOS**: The sandbox runtime taps into macOS's system sandbox violation log store. This provides real-time notifications with detailed information about what was attempted and why it was blocked. This is the same mechanism Claude Code uses for violation detection.

```bash
# View sandbox violations in real-time
log stream --predicate 'process == "sandbox-exec"' --style syslog
```

**Linux**: Bubblewrap doesn't provide built-in violation reporting. Use `strace` to trace system calls and identify blocked operations:

```bash
# Trace all denied operations
strace -f srt <your-command> 2>&1 | grep EPERM

# Trace specific file operations
strace -f -e trace=open,openat,stat,access srt <your-command> 2>&1 | grep EPERM

# Trace network operations
strace -f -e trace=network srt <your-command> 2>&1 | grep EPERM
```

### Advanced: Bring Your Own Proxy

For more sophisticated network filtering, you can configure the sandbox to use your own proxy instead of the built-in ones. This enables:

- **Traffic inspection**: Use tools like [mitmproxy](https://mitmproxy.org/) to inspect and modify traffic
- **Custom filtering logic**: Implement complex rules beyond simple domain allowlists
- **Audit logging**: Log all network requests for compliance or debugging

**Example with mitmproxy:**

```bash
# Start mitmproxy with custom filtering script
mitmproxy -s custom_filter.py --listen-port 8888
```

Note: Custom proxy configuration is not yet supported in the new configuration format. This feature will be added in a future release.

**Important security consideration:** Even with domain allowlists, exfiltration vectors may exist. For example, allowing `github.com` lets a process push to any repository. With a custom MITM proxy and proper certificate setup, you can inspect and filter specific API calls to prevent this.

### Security Limitations

- Network Sandboxing Limitations: The network filtering system operates by restricting the domains that processes are allowed to connect to. It does not otherwise inspect the traffic passing through the proxy and users are responsible for ensuring they only allow trusted domains in their policy.

<Warning>
Users should be aware of potential risks that come from allowing broad domains like `github.com` that may allow for data exfiltration. Also, in some cases it may be possible to bypass the network filtering through [domain fronting](https://en.wikipedia.org/wiki/Domain_fronting).   
</Warning>

- Privilege Escalation via Unix Sockets: The `allowUnixSockets` configuration can inadvertently grant access to powerful system services that could lead to sandbox bypasses. For example, if it is used to allow access to `/var/run/docker.sock` this would effectively grant access to the host system through exploiting the docker socket. Users are encouraged to carefully consider any unix sockets that they allow through the sandbox.
- Filesystem Permission Escalation: Overly broad filesystem write permissions can enable privilege escalation attacks. Allowing writes to directories containing executables in `$PATH`, system configuration directories, or user shell configuration files (`.bashrc`, `.zshrc`) can lead to code execution in different security contexts when other users or system processes access these files.
- Linux Sandbox Strength: The Linux implementation provides strong filesystem and network isolation but includes an `enableWeakerNestedSandbox` mode that enables it to work inside of Docker environments without privileged namespaces. This option considerably weakens security and should only be used incases where additional isolation is otherwise enforced.

### Known Limitations and Future Work

**Linux proxy bypass**: Currently uses environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) to direct traffic through proxies. This works for most applications but may be ignored by programs that don't respect these variables, leading to them being unable to connect to the internet.

**Future improvements:**

- **Proxychains support**: Add support for `proxychains` with `LD_PRELOAD` on Linux to intercept network calls at a lower level, making bypass more difficult

- **Linux violation monitoring**: Implement automatic `strace`-based violation detection for Linux, integrated with the violation store. Currently, Linux users must manually run `strace` to see violations, unlike macOS which has automatic violation monitoring via the system log store
