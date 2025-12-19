import { homedir } from 'os'
import * as path from 'path'
import * as fs from 'fs'
import { getPlatform } from '../utils/platform.js'

/**
 * Environment variables reserved by sandbox-runtime
 * These cannot be overridden by user configuration
 * Note: Matching is case-insensitive (names are uppercased before checking)
 */
export const RESERVED_ENV_VARS = new Set([
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'ALL_PROXY',
  'NO_PROXY',
  'FTP_PROXY',
  'GRPC_PROXY',
  'RSYNC_PROXY',
  'GIT_SSH_COMMAND',
  'DOCKER_HTTP_PROXY',
  'DOCKER_HTTPS_PROXY',
  'CLOUDSDK_PROXY_TYPE',
  'CLOUDSDK_PROXY_ADDRESS',
  'CLOUDSDK_PROXY_PORT',
  'CLAUDE_CODE_HOST_HTTP_PROXY_PORT',
  'CLAUDE_CODE_HOST_SOCKS_PROXY_PORT',
  'GLOBAL_AGENT_HTTP_PROXY',
  'GLOBAL_AGENT_NO_PROXY',
  'SANDBOX_RUNTIME',
  'TMPDIR',
])

/**
 * Normalizes a path for case-insensitive comparison.
 * This prevents bypassing security checks using mixed-case paths on case-insensitive
 * filesystems (macOS/Windows) like `.cLauDe/Settings.locaL.json`.
 *
 * We always normalize to lowercase regardless of platform for consistent security.
 * @param path The path to normalize
 * @returns The lowercase path for safe comparison
 */
export function normalizeCaseForComparison(pathStr: string): string {
  return pathStr.toLowerCase()
}

/**
 * Check if a path pattern contains glob characters
 */
export function containsGlobChars(pathPattern: string): boolean {
  return (
    pathPattern.includes('*') ||
    pathPattern.includes('?') ||
    pathPattern.includes('[') ||
    pathPattern.includes(']')
  )
}

/**
 * Remove trailing /** glob suffix from a path pattern
 * Used to normalize path patterns since /** just means "directory and everything under it"
 */
export function removeTrailingGlobSuffix(pathPattern: string): string {
  return pathPattern.replace(/\/\*\*$/, '')
}

/**
 * Normalize a path for use in sandbox configurations
 * Handles:
 * - Tilde (~) expansion for home directory
 * - Relative paths (./foo, ../foo, etc.) converted to absolute
 * - Absolute paths remain unchanged
 * - Symlinks are resolved to their real paths for non-glob patterns
 * - Glob patterns preserve wildcards after path normalization
 *
 * Returns the absolute path with symlinks resolved (or normalized glob pattern)
 */
export function normalizePathForSandbox(pathPattern: string): string {
  const cwd = process.cwd()
  let normalizedPath = pathPattern

  // Expand ~ to home directory
  if (pathPattern === '~') {
    normalizedPath = homedir()
  } else if (pathPattern.startsWith('~/')) {
    normalizedPath = homedir() + pathPattern.slice(1)
  } else if (pathPattern.startsWith('./') || pathPattern.startsWith('../')) {
    // Convert relative to absolute based on current working directory
    normalizedPath = path.resolve(cwd, pathPattern)
  } else if (!path.isAbsolute(pathPattern)) {
    // Handle other relative paths (e.g., ".", "..", "foo/bar")
    normalizedPath = path.resolve(cwd, pathPattern)
  }

  // For glob patterns, resolve symlinks for the directory portion only
  if (containsGlobChars(normalizedPath)) {
    // Extract the static directory prefix before glob characters
    const staticPrefix = normalizedPath.split(/[*?[\]]/)[0]
    if (staticPrefix && staticPrefix !== '/') {
      // Get the directory containing the glob pattern
      // If staticPrefix ends with /, remove it to get the directory
      const baseDir = staticPrefix.endsWith('/')
        ? staticPrefix.slice(0, -1)
        : path.dirname(staticPrefix)

      // Try to resolve symlinks for the base directory
      try {
        const resolvedBaseDir = fs.realpathSync(baseDir)
        // Reconstruct the pattern with the resolved directory
        const patternSuffix = normalizedPath.slice(baseDir.length)
        return resolvedBaseDir + patternSuffix
      } catch {
        // If directory doesn't exist or can't be resolved, keep the original pattern
      }
    }
    return normalizedPath
  }

  if (normalizedPath.startsWith('/dev/')) {
    return normalizedPath
  }

  // Resolve symlinks to real paths to avoid bwrap issues
  try {
    normalizedPath = fs.realpathSync(normalizedPath)
  } catch {
    // If path doesn't exist or can't be resolved, keep the normalized path
  }

  return normalizedPath
}

/**
 * Ensure temporary directory exists and return its path.
 * Creates the directory if it doesn't exist.
 *
 * @param tmpDir Optional custom tmpDir path. If not provided, uses default '/tmp/xmz-ai-sandbox'
 * @param platform Platform identifier for logging (e.g., 'Linux', 'macOS')
 * @returns The final tmpDir path (either custom or default)
 */
export function ensureTmpDir(
  tmpDir: string | undefined,
  platform: string = 'Sandbox',
): string {
  const finalTmpDir = tmpDir || '/tmp/xmz-ai-sandbox'

  try {
    if (!fs.existsSync(finalTmpDir)) {
      fs.mkdirSync(finalTmpDir, { recursive: true, mode: 0o755 })
    }
  } catch (error) {
    console.warn(
      `[${platform}] Failed to create temporary directory ${finalTmpDir}:`,
      error,
    )
  }

  return finalTmpDir
}

/**
 * Generate proxy environment variables for sandboxed processes
 *
 * NOTE: The tmpDir should be created by the caller before calling this function.
 * This function only sets the TMPDIR environment variable, it doesn't create the directory.
 */
export function generateProxyEnvVars(
  httpProxyPort?: number,
  socksProxyPort?: number,
  options?: {
    tmpDir?: string
    noProxyAddresses?: string[]
  },
): string[] {
  const tmpDir = options?.tmpDir || '/tmp/xmz-ai-sandbox'
  const envVars: string[] = [`SANDBOX_RUNTIME=1`, `TMPDIR=${tmpDir}`]

  // If no proxy ports provided, return minimal env vars
  if (!httpProxyPort && !socksProxyPort) {
    return envVars
  }

  // Build NO_PROXY list: mandatory localhost/link-local/mDNS + user-provided addresses
  const mandatoryNoProxy = [
    'localhost',
    '127.0.0.1',
    '::1',
    '*.local', // mDNS/Bonjour
    '.local', // mDNS/Bonjour base domain
    '169.254.0.0/16', // Link-local addresses
  ]
  const userNoProxy = options?.noProxyAddresses || []

  const noProxyAddresses = [...mandatoryNoProxy, ...userNoProxy].join(',')

  envVars.push(`NO_PROXY=${noProxyAddresses}`)
  envVars.push(`no_proxy=${noProxyAddresses}`)
  envVars.push(`GLOBAL_AGENT_NO_PROXY=${noProxyAddresses}`)

  if (httpProxyPort) {
    envVars.push(`HTTP_PROXY=http://127.0.0.1:${httpProxyPort}`)
    envVars.push(`HTTPS_PROXY=http://127.0.0.1:${httpProxyPort}`)
    // Lowercase versions for compatibility with some tools
    envVars.push(`http_proxy=http://127.0.0.1:${httpProxyPort}`)
    envVars.push(`https_proxy=http://127.0.0.1:${httpProxyPort}`)
    envVars.push(`GLOBAL_AGENT_HTTP_PROXY=http://127.0.0.1:${httpProxyPort}`)
  }

  if (socksProxyPort) {
    // Use socks5h:// for proper DNS resolution through proxy
    envVars.push(`ALL_PROXY=socks5h://127.0.0.1:${socksProxyPort}`)
    envVars.push(`all_proxy=socks5h://127.0.0.1:${socksProxyPort}`)

    // Configure Git to use SSH through SOCKS proxy (platform-aware)
    if (getPlatform() === 'macos') {
      // macOS has nc available
      envVars.push(
        `GIT_SSH_COMMAND="ssh -o ProxyCommand='nc -X 5 -x localhost:${socksProxyPort} %h %p'"`,
      )
    }

    // FTP proxy support (use socks5h for DNS resolution through proxy)
    envVars.push(`FTP_PROXY=socks5h://127.0.0.1:${socksProxyPort}`)
    envVars.push(`ftp_proxy=socks5h://127.0.0.1:${socksProxyPort}`)

    // rsync proxy support
    envVars.push(`RSYNC_PROXY=127.0.0.1:${socksProxyPort}`)

    // Database tools NOTE: Most database clients don't have built-in proxy support
    // You typically need to use SSH tunneling or a SOCKS wrapper like tsocks/proxychains

    // Docker CLI uses HTTP for the API
    // This makes Docker use the HTTP proxy for registry operations
    envVars.push(
      `DOCKER_HTTP_PROXY=http://127.0.0.1:${httpProxyPort || socksProxyPort}`,
    )
    envVars.push(
      `DOCKER_HTTPS_PROXY=http://127.0.0.1:${httpProxyPort || socksProxyPort}`,
    )

    // Kubernetes kubectl - uses standard HTTPS_PROXY
    // kubectl respects HTTPS_PROXY which we already set above

    // AWS CLI - uses standard HTTPS_PROXY (v2 supports it well)
    // AWS CLI v2 respects HTTPS_PROXY which we already set above

    // Google Cloud SDK - has specific proxy settings
    // Use HTTPS proxy to match other HTTP-based tools
    if (httpProxyPort) {
      envVars.push(`CLOUDSDK_PROXY_TYPE=https`)
      envVars.push(`CLOUDSDK_PROXY_ADDRESS=localhost`)
      envVars.push(`CLOUDSDK_PROXY_PORT=${httpProxyPort}`)
    }

    // Azure CLI - uses HTTPS_PROXY
    // Azure CLI respects HTTPS_PROXY which we already set above

    // Terraform - uses standard HTTP/HTTPS proxy vars
    // Terraform respects HTTP_PROXY/HTTPS_PROXY which we already set above

    // gRPC-based tools - use standard proxy vars
    envVars.push(`GRPC_PROXY=socks5h://127.0.0.1:${socksProxyPort}`)
    envVars.push(`grpc_proxy=socks5h://127.0.0.1:${socksProxyPort}`)
  }

  // WARNING: Do not set HTTP_PROXY/HTTPS_PROXY to SOCKS URLs when only SOCKS proxy is available
  // Most HTTP clients do not support SOCKS URLs in these variables and will fail, and we want
  // to avoid overriding the client otherwise respecting the ALL_PROXY env var which points to SOCKS.

  return envVars
}

/**
 * Encode a command for sandbox monitoring
 * Truncates to 100 chars and base64 encodes to avoid parsing issues
 */
export function encodeSandboxedCommand(command: string): string {
  const truncatedCommand = command.slice(0, 100)
  return Buffer.from(truncatedCommand).toString('base64')
}

/**
 * Decode a base64-encoded command from sandbox monitoring
 */
export function decodeSandboxedCommand(encodedCommand: string): string {
  return Buffer.from(encodedCommand, 'base64').toString('utf8')
}

/**
 * Check if a hostname matches a domain pattern.
 * Supports multiple pattern types:
 * - Exact match: "example.com" matches only "example.com"
 * - Subdomain wildcard: "*.example.com" matches "api.example.com" but NOT "example.com"
 * - Full wildcard: ".example.com" matches "example.com" AND all subdomains
 * - Match all: "*" matches any hostname
 *
 * @param hostname The hostname to check
 * @param pattern The domain pattern
 * @returns true if hostname matches the pattern
 *
 * @example
 * matchesDomainPattern('example.com', '*') // true (matches everything)
 * matchesDomainPattern('api.example.com', '.example.com') // true
 * matchesDomainPattern('example.com', '.example.com') // true (base domain)
 * matchesDomainPattern('api.example.com', '*.example.com') // true
 * matchesDomainPattern('example.com', '*.example.com') // false
 * matchesDomainPattern('example.com', 'example.com') // true (exact match)
 */
export function matchesDomainPattern(
  hostname: string,
  pattern: string,
): boolean {
  // Normalize both to lowercase for case-insensitive matching
  const normalizedHost = hostname.toLowerCase()
  const normalizedPattern = pattern.toLowerCase()

  // NEW: Match-all wildcard
  if (normalizedPattern === '*') {
    return true
  }

  // NEW: Dot-prefix pattern (matches base domain AND all subdomains)
  // .example.com matches: example.com, api.example.com, deep.api.example.com
  if (
    normalizedPattern.startsWith('.') &&
    !normalizedPattern.startsWith('*.')
  ) {
    const baseDomain = normalizedPattern.substring(1) // Remove leading '.'
    return (
      normalizedHost === baseDomain || normalizedHost.endsWith('.' + baseDomain)
    )
  }

  // EXISTING: Subdomain wildcard pattern (matches subdomains only, NOT base domain)
  // *.example.com matches: api.example.com, but NOT example.com
  if (normalizedPattern.startsWith('*.')) {
    const baseDomain = normalizedPattern.substring(2) // Remove '*.'
    return normalizedHost.endsWith('.' + baseDomain)
  }

  // EXISTING: Exact match for non-wildcard patterns
  return normalizedHost === normalizedPattern
}

/**
 * Normalize and filter paths for sandbox configuration.
 * Removes trailing glob suffixes (/** at the end).
 *
 * NOTE: Glob patterns are now supported on both platforms:
 * - macOS: Uses regex matching in sandbox profiles (protects future files)
 * - Linux: Expands globs at config time via ripgrep (only existing files)
 *
 * @param paths The paths to normalize and filter
 * @param platform The platform to normalize for
 * @returns Normalized and filtered paths
 */
export function normalizeAndFilterPaths(
  paths: string[],
  _platform: 'macos' | 'linux' | 'unknown',
): string[] {
  return paths ? paths.map(path => removeTrailingGlobSuffix(path)) : []
}

/**
 * Get system paths that must be readable for commands to execute in allow-only mode.
 * These paths contain system binaries, libraries, and essential runtime files.
 *
 * IMPORTANT: This function is ONLY used by Linux allow-only mode.
 * - Linux: Uses allow-only mode, needs explicit system path list
 * - macOS: Uses deny-only mode (allows all reads by default), doesn't need this
 *
 * @param platform The platform to get system paths for
 * @returns Array of system paths that should be allowed for reading
 */
export function getDefaultSystemReadPaths(
  platform: 'macos' | 'linux' | 'unknown',
): string[] {
  if (platform === 'linux') {
    return [
      // Command-line binaries
      '/usr',
      '/bin',
      '/sbin',
      // System libraries
      '/lib',
      '/lib64',
    ]
  }

  return []
}
