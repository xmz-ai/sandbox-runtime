import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { NetworkManager } from '../../src/sandbox/network-manager.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { getPlatform } from '../../src/utils/platform.js'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'

function skipIfUnsupportedPlatform(): boolean {
  const platform = getPlatform()
  return platform !== 'linux' && platform !== 'macos'
}

describe('wrapWithSandbox with different configurations', () => {
  let networkManager: NetworkManager
  let sandboxManager: SandboxManager

  beforeAll(async () => {
    if (skipIfUnsupportedPlatform()) {
      return
    }

    // Initialize NetworkManager with some allowed domains
    networkManager = new NetworkManager()
    await networkManager.initialize({
      allowedDomains: ['example.com', 'api.github.com'],
      deniedDomains: [],
    })

    // Initialize SandboxManager with filesystem restrictions
    sandboxManager = new SandboxManager(networkManager, {
      filesystem: {
        denyRead: ['~/.ssh'],
        allowWrite: ['.', '/tmp'],
        denyWrite: ['.env'],
      },
    })
  })

  afterAll(async () => {
    if (skipIfUnsupportedPlatform()) {
      return
    }
    await sandboxManager?.dispose()
    await networkManager?.shutdown()
  })

  describe('basic usage', () => {
    it('wraps command with configured restrictions', async () => {
      if (skipIfUnsupportedPlatform()) {
        return
      }

      const command = 'echo hello'
      const wrapped = await sandboxManager.wrapWithSandbox(command)

      // Should wrap the command (not return it as-is)
      expect(wrapped).not.toBe(command)
      expect(wrapped.length).toBeGreaterThan(command.length)
    })
  })

  describe('different configurations via different instances', () => {
    it('can create instance with no write permissions', async () => {
      if (skipIfUnsupportedPlatform()) {
        return
      }

      // Create a restrictive instance with no writes allowed
      const restrictiveSandbox = new SandboxManager(networkManager, {
        filesystem: {
          denyRead: [],
          allowWrite: [], // Block all writes
          denyWrite: [],
        },
      })

      const command = 'echo hello'
      const wrapped = await restrictiveSandbox.wrapWithSandbox(command)

      // Should still wrap the command
      expect(wrapped).not.toBe(command)
      expect(wrapped.length).toBeGreaterThan(command.length)

      await restrictiveSandbox.dispose()
    })

    it('can create instance with custom denyRead', async () => {
      if (skipIfUnsupportedPlatform()) {
        return
      }

      // Create instance blocking specific file
      const customSandbox = new SandboxManager(networkManager, {
        filesystem: {
          denyRead: ['/etc/passwd'], // Block this specific file
          allowWrite: [],
          denyWrite: [],
        },
      })

      const command = 'cat /etc/passwd'
      const wrapped = await customSandbox.wrapWithSandbox(command)

      expect(wrapped).not.toBe(command)

      await customSandbox.dispose()
    })

    it('can create instance with no network (empty allowedDomains)', async () => {
      if (skipIfUnsupportedPlatform()) {
        return
      }

      // Create NetworkManager with no allowed domains
      const noNetworkManager = new NetworkManager()
      await noNetworkManager.initialize({
        allowedDomains: [], // Block all network
        deniedDomains: [],
      })

      const noNetworkSandbox = new SandboxManager(noNetworkManager, {
        filesystem: {
          denyRead: [],
          allowWrite: [],
          denyWrite: [],
        },
      })

      const command = 'curl https://example.com'
      const wrapped = await noNetworkSandbox.wrapWithSandbox(command)

      // Should wrap the command
      expect(wrapped).not.toBe(command)

      await noNetworkSandbox.dispose()
      await noNetworkManager.shutdown()
    })

    it('can create readonly instance (no writes, no network)', async () => {
      if (skipIfUnsupportedPlatform()) {
        return
      }

      // Create fully restricted instance
      const readonlyNetworkManager = new NetworkManager()
      await readonlyNetworkManager.initialize({
        allowedDomains: [], // Block all network
        deniedDomains: [],
      })

      const readonlySandbox = new SandboxManager(readonlyNetworkManager, {
        filesystem: {
          denyRead: [],
          allowWrite: [], // Block all writes
          denyWrite: [],
        },
      })

      const command = 'ls -la'
      const wrapped = await readonlySandbox.wrapWithSandbox(command)

      // Should wrap the command with restrictions
      expect(wrapped).not.toBe(command)
      expect(wrapped.length).toBeGreaterThan(command.length)

      await readonlySandbox.dispose()
      await readonlyNetworkManager.shutdown()
    })
  })
})

/**
 * Tests for restriction pattern semantics
 *
 * These test the platform functions directly to verify:
 * - Read (deny-only): undefined or empty denyOnly = no restrictions
 * - Write (allow-only): undefined = no restrictions, any config = restrictions
 * - Network: needsNetworkRestriction = false means no network sandbox
 */
describe('restriction pattern semantics', () => {
  const command = 'echo hello'

  describe('no sandboxing needed (early return)', () => {
    it('returns command unchanged when no restrictions on Linux', async () => {
      if (getPlatform() !== 'linux') {
        return
      }

      // No network, empty read deny, no write config = no sandboxing
      const result = await wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { mode: 'deny-only', denyPaths: [] },
        writeConfig: undefined,
      })

      expect(result).toBe(command)
    })

    it('returns command unchanged when no restrictions on macOS', () => {
      if (getPlatform() !== 'macos') {
        return
      }

      // No network, empty read deny, no write config = no sandboxing
      const result = wrapCommandWithSandboxMacOS({
        command,
        needsNetworkRestriction: false,
        readConfig: { mode: 'deny-only', denyPaths: [] },
        writeConfig: undefined,
      })

      expect(result).toBe(command)
    })

    it('returns command unchanged with undefined readConfig on Linux', async () => {
      if (getPlatform() !== 'linux') {
        return
      }

      const result = await wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: undefined,
      })

      expect(result).toBe(command)
    })

    it('returns command unchanged with undefined readConfig on macOS', () => {
      if (getPlatform() !== 'macos') {
        return
      }

      const result = wrapCommandWithSandboxMacOS({
        command,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: undefined,
      })

      expect(result).toBe(command)
    })
  })

  describe('read restrictions (deny-only pattern)', () => {
    it('empty denyOnly means no read restrictions on Linux', async () => {
      if (getPlatform() !== 'linux') {
        return
      }

      // Only write restrictions, empty read = should sandbox but no read rules
      const result = await wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { mode: 'deny-only', denyPaths: [] },
        writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      })

      // Should wrap because of write restrictions
      expect(result).not.toBe(command)
      expect(result).toContain('bwrap')
    })

    it('non-empty denyOnly means has read restrictions on Linux', async () => {
      if (getPlatform() !== 'linux') {
        return
      }

      const result = await wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { mode: 'deny-only', denyPaths: ['/secret'] },
        writeConfig: undefined,
      })

      // Should wrap because of read restrictions
      expect(result).not.toBe(command)
      expect(result).toContain('bwrap')
    })
  })

  describe('write restrictions (allow-only pattern)', () => {
    it('undefined writeConfig means no write restrictions on Linux', async () => {
      if (getPlatform() !== 'linux') {
        return
      }

      // Has read restrictions but no write = should sandbox
      const result = await wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { mode: 'deny-only', denyPaths: ['/secret'] },
        writeConfig: undefined,
      })

      expect(result).not.toBe(command)
    })

    it('empty allowOnly means maximally restrictive (has restrictions) on Linux', async () => {
      if (getPlatform() !== 'linux') {
        return
      }

      // Empty allowOnly = no writes allowed = has restrictions
      const result = await wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { mode: 'deny-only', denyPaths: [] },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })

      // Should wrap because empty allowOnly is still a restriction
      expect(result).not.toBe(command)
      expect(result).toContain('bwrap')
    })

    it('any writeConfig means has restrictions on macOS', () => {
      if (getPlatform() !== 'macos') {
        return
      }

      const result = wrapCommandWithSandboxMacOS({
        command,
        needsNetworkRestriction: false,
        readConfig: { mode: 'deny-only', denyPaths: [] },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })

      // Should wrap because writeConfig is defined
      expect(result).not.toBe(command)
      expect(result).toContain('sandbox-exec')
    })
  })

  describe('network restrictions', () => {
    it('needsNetworkRestriction false skips network sandbox on Linux', async () => {
      if (getPlatform() !== 'linux') {
        return
      }

      const result = await wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { mode: 'deny-only', denyPaths: ['/secret'] },
        writeConfig: undefined,
      })

      // Should wrap for filesystem but not include network args
      expect(result).not.toBe(command)
      expect(result).not.toContain('--unshare-net')
    })

    it('needsNetworkRestriction false skips network sandbox on macOS', () => {
      if (getPlatform() !== 'macos') {
        return
      }

      const result = wrapCommandWithSandboxMacOS({
        command,
        needsNetworkRestriction: false,
        readConfig: { mode: 'deny-only', denyPaths: ['/secret'] },
        writeConfig: undefined,
      })

      // Should wrap for filesystem
      expect(result).not.toBe(command)
      expect(result).toContain('sandbox-exec')
    })

    // Tests for the empty allowedDomains fix (CVE fix)
    // Empty allowedDomains should block all network, not allow all
    it('needsNetworkRestriction true without proxy sockets blocks all network on Linux', async () => {
      if (getPlatform() !== 'linux') {
        return
      }

      // Network restriction enabled but no proxy sockets = block all network
      const result = await wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: true,
        httpSocketPath: undefined, // No proxy available
        socksSocketPath: undefined, // No proxy available
        readConfig: { mode: 'deny-only', denyPaths: [] },
        writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      })

      // Should wrap with --unshare-net to block all network
      expect(result).not.toBe(command)
      expect(result).toContain('bwrap')
      expect(result).toContain('--unshare-net')
      // Should NOT contain proxy-related environment variables since no proxy
      expect(result).not.toContain('HTTP_PROXY')
    })

    it('needsNetworkRestriction true without proxy ports blocks all network on macOS', () => {
      if (getPlatform() !== 'macos') {
        return
      }

      // Network restriction enabled but no proxy ports = block all network
      const result = wrapCommandWithSandboxMacOS({
        command,
        needsNetworkRestriction: true,
        httpProxyPort: undefined, // No proxy available
        socksProxyPort: undefined, // No proxy available
        readConfig: { mode: 'deny-only', denyPaths: [] },
        writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      })

      // Should wrap with sandbox-exec
      expect(result).not.toBe(command)
      expect(result).toContain('sandbox-exec')
      // The sandbox profile should NOT contain "(allow network*)" since restrictions are enabled
      // Note: We can't easily check the profile content, but we verify it doesn't skip sandboxing
    })

    it('needsNetworkRestriction true with proxy allows filtered network on Linux', async () => {
      if (getPlatform() !== 'linux') {
        return
      }

      // Create temporary socket files for the test
      const fs = await import('fs')
      const os = await import('os')
      const path = await import('path')
      const tmpDir = os.tmpdir()
      const httpSocket = path.join(tmpDir, `test-http-${Date.now()}.sock`)
      const socksSocket = path.join(tmpDir, `test-socks-${Date.now()}.sock`)

      // Create dummy socket files
      fs.writeFileSync(httpSocket, '')
      fs.writeFileSync(socksSocket, '')

      try {
        const result = await wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: true,
          httpSocketPath: httpSocket,
          socksSocketPath: socksSocket,
          httpProxyPort: 3128,
          socksProxyPort: 1080,
          readConfig: { mode: 'deny-only', denyPaths: [] },
          writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
        })

        // Should wrap with network namespace isolation
        expect(result).not.toBe(command)
        expect(result).toContain('bwrap')
        expect(result).toContain('--unshare-net')
        // Should bind the socket files
        expect(result).toContain(httpSocket)
        expect(result).toContain(socksSocket)
      } finally {
        // Cleanup
        fs.unlinkSync(httpSocket)
        fs.unlinkSync(socksSocket)
      }
    })

    it('needsNetworkRestriction true with proxy allows filtered network on macOS', () => {
      if (getPlatform() !== 'macos') {
        return
      }

      const result = wrapCommandWithSandboxMacOS({
        command,
        needsNetworkRestriction: true,
        httpProxyPort: 3128,
        socksProxyPort: 1080,
        readConfig: { mode: 'deny-only', denyPaths: [] },
        writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      })

      // Should wrap with sandbox-exec and proxy env vars
      expect(result).not.toBe(command)
      expect(result).toContain('sandbox-exec')
      // Should set proxy environment variables
      expect(result).toContain('HTTP_PROXY')
      expect(result).toContain('HTTPS_PROXY')
    })
  })
})

/**
 * Tests for the empty allowedDomains vulnerability fix
 *
 * These tests verify that when allowedDomains is explicitly set to an empty array [],
 * network access is blocked (as documented) rather than allowed (the bug).
 *
 * Documentation states: "Empty array = no network access"
 * Bug behavior: Empty array = full unrestricted network access
 * Fixed behavior: Empty array = network isolation enabled, all network blocked
 */
describe('empty allowedDomains network blocking (CVE fix)', () => {
  const command = 'curl https://example.com'

  it('empty allowedDomains triggers network restriction on Linux', async () => {
    if (getPlatform() !== 'linux') {
      return
    }

    // Create NetworkManager with empty allowedDomains
    const emptyNetworkManager = new NetworkManager()
    await emptyNetworkManager.initialize({
      allowedDomains: [], // Empty = block all network (documented behavior)
      deniedDomains: [],
    })

    const emptySandbox = new SandboxManager(emptyNetworkManager, {
      filesystem: {
        denyRead: [],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    const result = await emptySandbox.wrapWithSandbox(command)

    // With the fix, empty allowedDomains should trigger network isolation
    expect(result).not.toBe(command)
    expect(result).toContain('bwrap')
    expect(result).toContain('--unshare-net')

    await emptySandbox.dispose()
    await emptyNetworkManager.shutdown()
  })

  it('empty allowedDomains triggers network restriction on macOS', async () => {
    if (getPlatform() !== 'macos') {
      return
    }

    // Create NetworkManager with empty allowedDomains
    const emptyNetworkManager = new NetworkManager()
    await emptyNetworkManager.initialize({
      allowedDomains: [], // Empty = block all network (documented behavior)
      deniedDomains: [],
    })

    const emptySandbox = new SandboxManager(emptyNetworkManager, {
      filesystem: {
        denyRead: [],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    const result = await emptySandbox.wrapWithSandbox(command)

    // With the fix, empty allowedDomains should trigger sandbox
    expect(result).not.toBe(command)
    expect(result).toContain('sandbox-exec')

    await emptySandbox.dispose()
    await emptyNetworkManager.shutdown()
  })

  it('non-empty allowedDomains still works correctly', async () => {
    if (skipIfUnsupportedPlatform()) {
      return
    }

    // Create NetworkManager with specific allowed domain
    const allowedNetworkManager = new NetworkManager()
    await allowedNetworkManager.initialize({
      allowedDomains: ['example.com'], // Specific domain allowed
      deniedDomains: [],
    })

    const allowedSandbox = new SandboxManager(allowedNetworkManager, {
      filesystem: {
        denyRead: [],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    const result = await allowedSandbox.wrapWithSandbox(command)

    // Should still wrap with sandbox
    expect(result).not.toBe(command)
    // Should have proxy environment variables for filtering
    expect(result).toContain('HTTP_PROXY')

    await allowedSandbox.dispose()
    await allowedNetworkManager.shutdown()
  })
})
