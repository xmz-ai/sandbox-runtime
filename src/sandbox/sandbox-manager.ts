import { logForDebugging } from '../utils/debug.js'
import { getPlatform, type Platform } from '../utils/platform.js'
import type {
  SandboxInstanceConfig,
  SandboxOptions,
  NetworkConfig,
} from './sandbox-config.js'
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from './sandbox-schemas.js'
import { wrapCommandWithSandboxLinux } from './linux-sandbox-utils.js'
import {
  wrapCommandWithSandboxMacOS,
  startMacOSSandboxLogMonitor,
} from './macos-sandbox-utils.js'
import {
  containsGlobChars,
  removeTrailingGlobSuffix,
  getDefaultSystemReadPaths,
  normalizeAndFilterPaths,
  RESERVED_ENV_VARS,
} from './sandbox-utils.js'
import {
  isSupportedPlatform,
  checkSandboxDependencies,
} from './sandbox-dependencies.js'
import { SandboxViolationStore } from './sandbox-violation-store.js'
import { EOL } from 'node:os'
import { NetworkManager } from './network-manager.js'

/**
 * SandboxManager - Manages filesystem/env restrictions for sandboxed processes
 *
 * Each instance has its own configuration and can be used by different workers.
 *
 * Two usage modes:
 * 1. Simple: Pass NetworkConfig, SandboxManager creates and manages NetworkManager internally
 * 2. Advanced: Pass NetworkManager instance for sharing across multiple workers
 */
export class SandboxManager {
  private networkManager: NetworkManager
  private config: SandboxInstanceConfig
  private options: SandboxOptions
  private sandboxViolationStore: SandboxViolationStore
  private logMonitorShutdown: (() => void) | undefined
  private ownsNetworkManager: boolean
  private networkInitialized = false
  private pendingNetworkConfig?: NetworkConfig

  /**
   * Create a new SandboxManager
   *
   * @param networkOrConfig - Either a NetworkConfig (simple mode) or NetworkManager instance (advanced mode)
   * @param config - Sandbox instance configuration (filesystem, env, etc.)
   * @param options - Optional configuration (log monitoring, etc.)
   *
   * @example
   * // Simple mode - SandboxManager manages network internally
   * const sandbox = new SandboxManager(
   *   { allowedDomains: ['example.com'], deniedDomains: [] },
   *   { filesystem: { allowWrite: ['.'] } }
   * )
   * await sandbox.initialize()
   * // ... use sandbox
   * await sandbox.dispose() // Cleans up network automatically
   *
   * @example
   * // Advanced mode - Share NetworkManager across workers
   * const networkManager = new NetworkManager()
   * await networkManager.initialize({ allowedDomains: ['example.com'], deniedDomains: [] })
   *
   * const worker1 = new SandboxManager(networkManager, { filesystem: { allowWrite: ['/worker1'] } })
   * const worker2 = new SandboxManager(networkManager, { filesystem: { allowWrite: ['/worker2'] } })
   *
   * worker1.dispose() // Doesn't shutdown network (shared)
   * worker2.dispose() // Doesn't shutdown network (shared)
   * await networkManager.shutdown() // Manual cleanup
   */
  constructor(
    networkOrConfig: NetworkManager | NetworkConfig,
    config: SandboxInstanceConfig,
    options?: SandboxOptions,
  ) {
    // Check platform and dependencies before initialization
    const platform = getPlatform()
    if (!isSupportedPlatform(platform)) {
      throw new Error(
        `Platform '${platform}' is not supported. Supported platforms: macOS, Linux.`,
      )
    }

    // Determine if we're in simple or advanced mode
    if (networkOrConfig instanceof NetworkManager) {
      // Advanced mode: Use provided NetworkManager (shared, don't auto-cleanup)
      this.networkManager = networkOrConfig
      this.ownsNetworkManager = false

      // Check dependencies immediately
      const allowAllUnixSockets =
        networkOrConfig.getConfig()?.allowAllUnixSockets ?? false
      if (!checkSandboxDependencies(config.ripgrep, allowAllUnixSockets)) {
        this.throwDependencyError(platform)
      }
    } else {
      // Simple mode: Create our own NetworkManager (owned, auto-cleanup)
      this.networkManager = new NetworkManager()
      this.ownsNetworkManager = true

      // Check dependencies (network not initialized yet, assume allowAllUnixSockets from config)
      const allowAllUnixSockets = networkOrConfig.allowAllUnixSockets ?? false
      if (!checkSandboxDependencies(config.ripgrep, allowAllUnixSockets)) {
        this.throwDependencyError(platform)
      }

      // Store network config for later initialization
      this.pendingNetworkConfig = networkOrConfig
    }

    this.config = config
    this.options = options || {}
    this.sandboxViolationStore = new SandboxViolationStore()

    // Start log monitor for macOS if enabled
    if (this.options.enableLogMonitor && getPlatform() === 'macos') {
      this.logMonitorShutdown = startMacOSSandboxLogMonitor(
        this.sandboxViolationStore.addViolation.bind(
          this.sandboxViolationStore,
        ),
        config.ignoreViolations,
      )
      logForDebugging('Started macOS sandbox log monitor')
    }
  }

  /**
   * Initialize the sandbox (only needed in simple mode)
   *
   * In simple mode (when NetworkConfig was passed), this initializes the internal NetworkManager.
   * In advanced mode (when NetworkManager instance was passed), this is a no-op.
   *
   * @example
   * const sandbox = new SandboxManager(
   *   { allowedDomains: ['example.com'], deniedDomains: [] },
   *   { filesystem: { allowWrite: ['.'] } }
   * )
   * await sandbox.initialize() // Required in simple mode
   */
  async initialize(): Promise<void> {
    // Only initialize if we own the NetworkManager and haven't initialized yet
    if (this.ownsNetworkManager && !this.networkInitialized) {
      if (!this.pendingNetworkConfig) {
        throw new Error('No network config available for initialization')
      }
      await this.networkManager.initialize(this.pendingNetworkConfig)
      this.networkInitialized = true
      logForDebugging('NetworkManager initialized by SandboxManager')
    }
  }

  /**
   * Throw helpful error message when dependencies are missing
   */
  private throwDependencyError(platform: Platform): never {
    let errorMessage = 'Sandbox dependencies are not available on this system.'

    if (platform === 'linux') {
      errorMessage += ' Required: ripgrep (rg), bubblewrap (bwrap), and socat.'
    } else if (platform === 'macos') {
      errorMessage += ' Required: ripgrep (rg).'
    }

    throw new Error(errorMessage)
  }

  /**
   * Wrap a command with sandbox restrictions
   */
  async wrapWithSandbox(
    command: string,
    binShell?: string,
    abortSignal?: AbortSignal,
  ): Promise<string> {
    // Auto-initialize if we own the NetworkManager and haven't initialized yet
    if (this.ownsNetworkManager && !this.networkInitialized) {
      await this.initialize()
    }

    const platform = getPlatform()

    // Get network context from NetworkManager
    const networkContext = this.networkManager.getNetworkContext()
    const networkConfig = this.networkManager.getConfig()

    // Determine if we need network restrictions
    // needsNetworkRestriction: true if network config exists (either allowed or denied domains)
    const hasNetworkConfig = this.networkManager.isInitialized()
    const needsNetworkRestriction = hasNetworkConfig

    // needsNetworkProxy: Only use proxy if there are domains to filter
    // If allowedDomains is empty, we block ALL network (no proxy needed - DNS will fail)
    const allowedDomains = networkConfig?.allowedDomains ?? []
    const needsNetworkProxy = allowedDomains.length > 0

    // Only error if we need a proxy but don't have the infrastructure
    // (allowedDomains: [] is valid - no proxy needed, just block all network)
    if (needsNetworkProxy && !networkContext) {
      throw new Error(
        'NetworkManager must have proxy infrastructure when allowedDomains is non-empty',
      )
    }

    const readConfig = this.getFsReadConfig()
    const writeConfig = this.getFsWriteConfig()
    const envVars = this.getResolvedEnvVars()
    switch (platform) {
      case 'macos':
        return wrapCommandWithSandboxMacOS({
          command,
          needsNetworkRestriction,
          // Only pass proxy ports if we're actually filtering domains
          httpProxyPort: needsNetworkProxy
            ? networkContext?.httpProxyPort
            : undefined,
          socksProxyPort: needsNetworkProxy
            ? networkContext?.socksProxyPort
            : undefined,
          readConfig,
          writeConfig,
          allowUnixSockets: networkConfig?.allowUnixSockets,
          allowAllUnixSockets: networkConfig?.allowAllUnixSockets,
          allowLocalBinding: networkConfig?.allowLocalBinding,
          ignoreViolations: this.config.ignoreViolations,
          binShell,
          envVars,
        })

      case 'linux':
        return wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction,
          // Only pass proxy paths/ports if we're actually filtering domains
          httpSocketPath: needsNetworkProxy
            ? networkContext?.linuxBridge?.httpSocketPath
            : undefined,
          socksSocketPath: needsNetworkProxy
            ? networkContext?.linuxBridge?.socksSocketPath
            : undefined,
          httpProxyPort: needsNetworkProxy
            ? networkContext?.httpProxyPort
            : undefined,
          socksProxyPort: needsNetworkProxy
            ? networkContext?.socksProxyPort
            : undefined,
          readConfig,
          writeConfig,
          enableWeakerNestedSandbox: this.config.enableWeakerNestedSandbox,
          allowAllUnixSockets: networkConfig?.allowAllUnixSockets,
          binShell,
          ripgrepConfig: this.getRipgrepConfig(),
          mandatoryDenySearchDepth: this.getMandatoryDenySearchDepth(),
          abortSignal,
          envVars,
        })

      default:
        throw new Error(
          `Sandbox configuration is not supported on platform: ${platform}`,
        )
    }
  }

  /**
   * Get the current instance configuration
   */
  getConfig(): SandboxInstanceConfig {
    return this.config
  }

  /**
   * Get filesystem read restriction config
   */
  getFsReadConfig(): FsReadRestrictionConfig | undefined {
    const filesystem = this.config.filesystem
    const platform = getPlatform()

    const hasDenyRead = filesystem.denyRead && filesystem.denyRead.length > 0
    const hasAllowRead = filesystem.allowRead && filesystem.allowRead.length > 0

    if (platform === 'linux') {
      // Linux supports both deny-only and allow-only modes
      if (hasAllowRead) {
        // Allow-only mode: user specified allowRead
        let allowPaths = normalizeAndFilterPaths(
          filesystem.allowRead || [],
          platform,
        )

        // Auto-include system paths if enabled (default: true)
        const autoAllowSystem = filesystem.autoAllowSystemPaths !== false
        if (autoAllowSystem) {
          const systemPaths = getDefaultSystemReadPaths('linux')
          allowPaths = [...allowPaths, ...systemPaths]
          logForDebugging(
            `Auto-included ${systemPaths.length} system paths for reading`,
          )
        }

        // Get sensitive paths to exclude (denyWithinAllow)
        const denyWithinAllow = normalizeAndFilterPaths(
          filesystem.denyRead || [],
          platform,
        )

        return {
          mode: 'allow-only',
          allowPaths,
          denyWithinAllow,
        }
      } else {
        if (hasDenyRead) {
          return {
            mode: 'deny-only',
            denyPaths: normalizeAndFilterPaths(
              filesystem.denyRead || [],
              platform,
            ),
          }
        }
        // No read restrictions specified
        return undefined
      }
    } else if (platform === 'macos') {
      // macOS only supports deny-only mode
      if (hasAllowRead) {
        throw new Error(
          'macOS sandbox does not support allow-only mode (allowRead). ' +
            'Please use deny-only mode (denyRead) instead.',
        )
      }

      if (hasDenyRead) {
        return {
          mode: 'deny-only',
          denyPaths: normalizeAndFilterPaths(
            filesystem.denyRead || [],
            platform,
          ),
        }
      }

      // No read restrictions
      return undefined
    }

    return undefined
  }

  /**
   * Get filesystem write restriction config
   */
  getFsWriteConfig(): FsWriteRestrictionConfig {
    // Filter out glob patterns on Linux for allowWrite
    const allowPaths = (this.config.filesystem.allowWrite || [])
      .map(path => removeTrailingGlobSuffix(path))
      .filter(path => {
        if (getPlatform() === 'linux' && containsGlobChars(path)) {
          logForDebugging(`Skipping glob pattern on Linux: ${path}`)
          return false
        }
        return true
      })

    // Filter out glob patterns on Linux for denyWrite
    const denyPaths = (this.config.filesystem.denyWrite || [])
      .map(path => removeTrailingGlobSuffix(path))
      .filter(path => {
        if (getPlatform() === 'linux' && containsGlobChars(path)) {
          logForDebugging(`Skipping glob pattern on Linux: ${path}`)
          return false
        }
        return true
      })

    return {
      allowOnly: allowPaths,
      denyWithinAllow: denyPaths,
    }
  }

  /**
   * Get violation ignore rules
   */
  getIgnoreViolations(): Record<string, string[]> | undefined {
    return this.config.ignoreViolations
  }

  /**
   * Get weaker nested sandbox flag (Linux)
   */
  getEnableWeakerNestedSandbox(): boolean | undefined {
    return this.config.enableWeakerNestedSandbox
  }

  /**
   * Get ripgrep configuration
   */
  getRipgrepConfig(): { command: string; args?: string[] } {
    return this.config.ripgrep ?? { command: 'rg' }
  }

  /**
   * Get mandatory deny search depth
   */
  getMandatoryDenySearchDepth(): number {
    return this.config.mandatoryDenySearchDepth ?? 3
  }

  /**
   * Get resolved environment variables (with inheritance from host)
   */
  getResolvedEnvVars(): Array<{ name: string; value: string }> {
    if (!this.config.env) {
      return []
    }

    const resolved: Array<{ name: string; value: string }> = []

    for (const [name, configValue] of Object.entries(this.config.env)) {
      // Check if variable is reserved
      if (RESERVED_ENV_VARS.has(name.toUpperCase())) {
        logForDebugging(`Skipping reserved environment variable: ${name}`, {
          level: 'warn',
        })
        continue
      }

      let value: string | undefined

      if (configValue === null) {
        // Inherit from host
        value = process.env[name]
      } else {
        // Use explicit value
        value = configValue
      }

      if (value !== undefined) {
        resolved.push({ name, value })
      }
    }

    return resolved
  }

  /**
   * Get the sandbox violation store for this instance
   */
  getSandboxViolationStore(): SandboxViolationStore {
    return this.sandboxViolationStore
  }

  /**
   * Annotate stderr with sandbox violations
   */
  annotateStderrWithSandboxFailures(command: string, stderr: string): string {
    const violations =
      this.sandboxViolationStore.getViolationsForCommand(command)
    if (violations.length === 0) {
      return stderr
    }

    let annotated = stderr
    annotated += EOL + '<sandbox_violations>' + EOL
    for (const violation of violations) {
      annotated += violation.line + EOL
    }
    annotated += '</sandbox_violations>'

    return annotated
  }

  /**
   * Get glob patterns that are not fully supported on Linux
   */
  getLinuxGlobPatternWarnings(): string[] {
    // Only warn on Linux
    if (getPlatform() !== 'linux') {
      return []
    }

    const globPatterns: string[] = []

    // Check filesystem paths for glob patterns
    const allPaths = [
      ...(this.config.filesystem.denyRead || []),
      ...(this.config.filesystem.allowRead || []),
      ...(this.config.filesystem.allowWrite || []),
      ...(this.config.filesystem.denyWrite || []),
    ]

    for (const path of allPaths) {
      // Strip trailing /** since that's just a subpath
      const pathWithoutTrailingStar = removeTrailingGlobSuffix(path)

      // Only warn if there are still glob characters after removing trailing /**
      if (containsGlobChars(pathWithoutTrailingStar)) {
        globPatterns.push(path)
      }
    }

    return globPatterns
  }

  /**
   * Clean up resources (log monitor, and network if owned)
   *
   * In simple mode (when we own the NetworkManager), this also shuts down the network proxies.
   * In advanced mode (shared NetworkManager), only cleans up instance-specific resources.
   */
  async dispose(): Promise<void> {
    // Stop log monitor
    if (this.logMonitorShutdown) {
      this.logMonitorShutdown()
      this.logMonitorShutdown = undefined
      logForDebugging('Stopped macOS sandbox log monitor')
    }

    // If we own the NetworkManager, shut it down
    if (this.ownsNetworkManager && this.networkInitialized) {
      await this.networkManager.shutdown()
      logForDebugging('NetworkManager shutdown by SandboxManager')
    }
  }
}
