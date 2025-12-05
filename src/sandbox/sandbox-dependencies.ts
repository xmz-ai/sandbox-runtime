import { getPlatform } from '../utils/platform.js'
import { hasRipgrepSync } from '../utils/ripgrep.js'
import { hasLinuxSandboxDependenciesSync } from './linux-sandbox-utils.js'

/**
 * Check if a platform is supported by the sandbox runtime
 *
 * @param platform The platform to check
 * @returns true if the platform is supported
 */
export function isSupportedPlatform(platform: string): boolean {
  const supportedPlatforms = ['macos', 'linux']
  return supportedPlatforms.includes(platform)
}

/**
 * Check if all sandbox dependencies are available for the current platform
 *
 * @param ripgrepConfig Optional custom ripgrep configuration
 * @param allowAllUnixSockets Whether Unix socket restrictions are disabled (Linux only)
 * @returns true if all required dependencies are available
 */
export function checkSandboxDependencies(
  ripgrepConfig?: {
    command: string
    args?: string[]
  },
  allowAllUnixSockets?: boolean,
): boolean {
  const platform = getPlatform()

  // Check platform support
  if (!isSupportedPlatform(platform)) {
    return false
  }

  // Check ripgrep - only check 'rg' if no custom command is configured
  const hasCustomRipgrep = ripgrepConfig?.command !== undefined
  if (!hasCustomRipgrep) {
    // Only check for default 'rg' command
    if (!hasRipgrepSync()) {
      return false
    }
  }

  // Platform-specific dependency checks
  if (platform === 'linux') {
    // For Linux, we need bubblewrap and socat (unless allowAllUnixSockets is true)
    const skipUnixSocketCheck = allowAllUnixSockets ?? false
    return hasLinuxSandboxDependenciesSync(skipUnixSocketCheck)
  }

  // macOS only needs ripgrep (already checked above)
  return true
}
