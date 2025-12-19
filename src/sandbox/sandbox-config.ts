/**
 * Configuration for Sandbox Runtime
 * This is the main configuration interface that consumers pass to SandboxManager.initialize()
 */

import { z } from 'zod'

/**
 * Schema for domain patterns (e.g., "example.com", "*.npmjs.org", ".example.com")
 * Validates that domain patterns are safe and don't include overly broad wildcards
 */
const domainPatternSchema = z.string().refine(
  val => {
    // Reject protocols, paths, ports, etc.
    if (val.includes('://') || val.includes('/') || val.includes(':')) {
      return false
    }

    // Allow localhost
    if (val === 'localhost') return true

    // Allow wildcard domains like *.example.com
    if (val.startsWith('*.')) {
      const domain = val.slice(2)
      // After the *. there must be a valid domain with at least one more dot
      // e.g., *.example.com is valid, *.com is not (too broad)
      if (
        !domain.includes('.') ||
        domain.startsWith('.') ||
        domain.endsWith('.')
      ) {
        return false
      }
      // Count dots - must have at least 2 parts after the wildcard (e.g., example.com)
      const parts = domain.split('.')
      return parts.length >= 2 && parts.every(p => p.length > 0)
    }

    // NEW: Allow dot-prefix domains like .example.com (matches base domain + all subdomains)
    if (val.startsWith('.') && !val.startsWith('*.')) {
      const domain = val.slice(1)
      // Must have at least one dot after the leading dot (e.g., .example.com is valid, .com is not)
      if (
        !domain.includes('.') ||
        domain.startsWith('.') ||
        domain.endsWith('.')
      ) {
        return false
      }
      const parts = domain.split('.')
      return parts.length >= 2 && parts.every(p => p.length > 0)
    }

    // Reject any other use of wildcards (e.g., *., **, *foo, etc.)
    if (val.includes('*')) {
      return false
    }

    // Regular domains must have at least one dot and only valid characters
    return val.includes('.') && !val.startsWith('.') && !val.endsWith('.')
  },
  {
    message:
      'Invalid domain pattern. Must be a valid domain (e.g., "example.com"), ' +
      'wildcard (e.g., "*.example.com"), or dot-prefix (e.g., ".example.com"). ' +
      'Overly broad patterns like "*.com" or ".com" are not allowed for security reasons.',
  },
)

/**
 * Schema for filesystem paths
 */
const filesystemPathSchema = z.string().min(1, 'Path cannot be empty')

/**
 * Network configuration schema for validation
 */
export const NetworkConfigSchema = z.object({
  allowedDomains: z
    .union([
      z.literal('*').describe('Allow all domains (deny-only mode)'),
      z
        .array(domainPatternSchema)
        .describe(
          'List of allowed domains (e.g., ["github.com", "*.npmjs.org"])',
        ),
    ])
    .describe(
      'Allowed domains: "*" for allow-all mode, or array of domain patterns',
    ),
  deniedDomains: z
    .union([
      z
        .literal('*')
        .describe('Deny all domains (allow-only mode with whitelist)'),
      z.array(domainPatternSchema).describe('List of denied domains'),
    ])
    .describe(
      'Denied domains: "*" for deny-all mode, or array of domain patterns',
    ),
  allowUnixSockets: z
    .array(z.string())
    .optional()
    .describe('Unix socket paths that are allowed (macOS only)'),
  allowAllUnixSockets: z
    .boolean()
    .optional()
    .describe(
      'Allow ALL Unix sockets (Linux only - disables Unix socket blocking)',
    ),
  allowLocalBinding: z
    .boolean()
    .optional()
    .describe('Whether to allow binding to local ports (default: false)'),
  httpProxyPort: z
    .number()
    .int()
    .min(1)
    .max(65535)
    .optional()
    .describe(
      'Port of an external HTTP proxy to use instead of starting a local one. When provided, the library will skip starting its own HTTP proxy and use this port. The external proxy must handle domain filtering.',
    ),
  socksProxyPort: z
    .number()
    .int()
    .min(1)
    .max(65535)
    .optional()
    .describe(
      'Port of an external SOCKS proxy to use instead of starting a local one. When provided, the library will skip starting its own SOCKS proxy and use this port. The external proxy must handle domain filtering.',
    ),
  noProxyAddresses: z
    .array(z.string())
    .optional()
    .describe(
      'Additional addresses to exclude from proxy (e.g., ["example.internal", "192.168.0.0/16"]). ' +
        'These are added to the mandatory addresses (localhost, 127.0.0.1, ::1, *.local, .local, 169.254.0.0/16). ' +
        'Common use cases: private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), internal domains.',
    ),
  allowNetworkMetadata: z
    .boolean()
    .optional()
    .describe(
      'Allow access to system network metadata and configuration. ' +
        'macOS: Grants mach-lookup permissions for SystemConfiguration services (DNS, proxy info, network config). ' +
        'Linux: Allows reading /etc/resolv.conf, /etc/hosts, and /etc/nsswitch.conf. ' +
        'Default: true (undefined is treated as true) for backward compatibility. Set to false for maximum security in isolated environments.',
    ),
})

/**
 * Filesystem configuration schema for validation
 */
export const FilesystemConfigSchema = z.object({
  denyRead: z
    .array(filesystemPathSchema)
    .optional()
    .describe(
      'Paths denied for reading. Semantics depend on mode: ' +
        '(1) Without allowRead (deny-only mode): Globally deny reading these paths. ' +
        '(2) With allowRead (allow-only mode): Deny reading these paths within allowed paths (deny-within-allow pattern). ' +
        'Default: []',
    ),
  allowRead: z
    .array(filesystemPathSchema)
    .optional()
    .describe(
      'Paths allowed for reading (allow-only mode). System paths are auto-included. ' +
        'Use denyRead to block specific paths within allowed paths.',
    ),
  autoAllowSystemPaths: z
    .boolean()
    .optional()
    .describe(
      'When using allowRead, automatically include system paths (/usr, /bin, etc.) for command execution. Default: true.',
    ),
  allowWrite: z
    .array(filesystemPathSchema)
    .optional()
    .describe('Paths allowed for writing'),
  denyWrite: z
    .array(filesystemPathSchema)
    .optional()
    .describe('Paths denied for writing (takes precedence over allowWrite)'),
})

/**
 * Configuration schema for ignoring specific sandbox violations
 * Maps command patterns to filesystem paths to ignore violations for.
 */
export const IgnoreViolationsConfigSchema = z
  .record(z.string(), z.array(z.string()))
  .describe(
    'Map of command patterns to filesystem paths to ignore violations for. Use "*" to match all commands',
  )

/**
 * Ripgrep configuration schema
 */
export const RipgrepConfigSchema = z.object({
  command: z
    .string()
    .describe('The ripgrep command to execute (e.g., "rg", "claude")'),
  args: z
    .array(z.string())
    .optional()
    .describe(
      'Additional arguments to pass before ripgrep args (e.g., ["--ripgrep"])',
    ),
})

/**
 * Environment variables configuration schema
 * - String values: set the environment variable to that value
 * - null values: inherit from host environment (process.env)
 */
export const EnvConfigSchema = z
  .record(z.string(), z.string().nullable())
  .optional()
  .describe(
    'Custom environment variables to set in sandboxed processes. ' +
      'Keys are variable names, values can be strings (explicit value) or null (inherit from host).',
  )

/**
 * Instance configuration schema for SandboxManager
 * This includes per-worker configuration that varies between sandbox instances
 */
export const SandboxInstanceConfigSchema = z.object({
  filesystem: FilesystemConfigSchema.describe(
    'Filesystem restrictions configuration',
  ),
  env: EnvConfigSchema.describe(
    'Custom environment variables for sandboxed processes',
  ),
  ignoreViolations: IgnoreViolationsConfigSchema.optional().describe(
    'Optional configuration for ignoring specific violations',
  ),
  enableWeakerNestedSandbox: z
    .boolean()
    .optional()
    .describe('Enable weaker nested sandbox mode (for Docker environments)'),
  ripgrep: RipgrepConfigSchema.optional().describe(
    'Custom ripgrep configuration (default: { command: "rg" })',
  ),
  mandatoryDenySearchDepth: z
    .number()
    .int()
    .min(1)
    .max(10)
    .optional()
    .describe(
      'Maximum directory depth to search for dangerous files on Linux (default: 3). ' +
        'Higher values provide more protection but slower performance.',
    ),
  allowPty: z
    .boolean()
    .optional()
    .describe(
      'Allow pseudo-terminal (pty) operations for tmux and other terminal multiplexers (macOS only)',
    ),
  tmpDir: z
    .string()
    .optional()
    .describe(
      'Custom temporary directory path for sandboxed processes (default: /tmp/xmz-ai-sandbox). ' +
        'Must be an absolute path and not in sensitive locations.',
    ),
})

/**
 * Options schema for SandboxManager constructor
 */
export const SandboxOptionsSchema = z.object({
  enableLogMonitor: z
    .boolean()
    .optional()
    .describe('Enable macOS sandbox log monitoring (default: false)'),
})

// Export inferred types
export type NetworkConfig = z.infer<typeof NetworkConfigSchema>
export type FilesystemConfig = z.infer<typeof FilesystemConfigSchema>
export type IgnoreViolationsConfig = z.infer<
  typeof IgnoreViolationsConfigSchema
>
export type RipgrepConfig = z.infer<typeof RipgrepConfigSchema>
export type EnvConfig = z.infer<typeof EnvConfigSchema>
export type SandboxInstanceConfig = z.infer<typeof SandboxInstanceConfigSchema>
export type SandboxOptions = z.infer<typeof SandboxOptionsSchema>
