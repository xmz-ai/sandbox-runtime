import { describe, test, expect } from 'bun:test'
import { wrapCommandWithSandboxMacOS } from '../src/sandbox/macos-sandbox-utils.js'
import { platform } from 'os'

const skipIfNotMacOS = () => {
  if (platform() !== 'darwin') {
    console.log('Skipping macOS-specific test')
    return true
  }
  return false
}

const skipIfNotLinux = () => {
  if (platform() !== 'linux') {
    console.log('Skipping Linux-specific test')
    return true
  }
  return false
}

describe('Network Metadata Permissions', () => {
  describe('macOS', () => {
    test('should include SystemConfiguration permissions when allowNetworkMetadata is undefined (default true)', () => {
      if (skipIfNotMacOS()) return

      const command = wrapCommandWithSandboxMacOS({
        command: 'echo test',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: {
          allowOnly: ['/tmp'],
          denyWithinAllow: [],
        }, // Need at least one restriction to trigger sandbox
        allowNetworkMetadata: undefined, // Should default to true
      })

      // Check that sandbox profile includes SystemConfiguration permissions
      expect(command).toContain('SystemConfiguration.configd')
      expect(command).toContain('SystemConfiguration.DNSConfiguration')
    })

    test('should include SystemConfiguration permissions when allowNetworkMetadata is explicitly true', () => {
      if (skipIfNotMacOS()) return

      const command = wrapCommandWithSandboxMacOS({
        command: 'echo test',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: {
          allowOnly: ['/tmp'],
          denyWithinAllow: [],
        }, // Need at least one restriction to trigger sandbox
        allowNetworkMetadata: true,
      })

      // Check that sandbox profile includes SystemConfiguration permissions
      expect(command).toContain('SystemConfiguration.configd')
      expect(command).toContain('SystemConfiguration.DNSConfiguration')
    })

    test('should NOT include SystemConfiguration permissions when allowNetworkMetadata is false', () => {
      if (skipIfNotMacOS()) return

      const command = wrapCommandWithSandboxMacOS({
        command: 'echo test',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: {
          allowOnly: ['/tmp'],
          denyWithinAllow: [],
        }, // Need at least one restriction to trigger sandbox
        allowNetworkMetadata: false,
      })

      // Check that sandbox profile does NOT include SystemConfiguration permissions
      expect(command).not.toContain('SystemConfiguration.configd')
      expect(command).not.toContain('SystemConfiguration.DNSConfiguration')
    })

    test('should work correctly with write restrictions', () => {
      if (skipIfNotMacOS()) return

      const command = wrapCommandWithSandboxMacOS({
        command: 'echo test',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: {
          allowOnly: ['/tmp'],
          denyWithinAllow: [],
        },
        allowNetworkMetadata: true,
      })

      // Should include both SystemConfiguration permissions and write restrictions
      expect(command).toContain('SystemConfiguration.configd')
      expect(command).toContain('file-write')
    })
  })

  describe('Linux', () => {
    test('should bind DNS files in allow-only mode when allowNetworkMetadata is true', async () => {
      if (skipIfNotLinux()) return

      const { wrapCommandWithSandboxLinux } = await import(
        '../src/sandbox/linux-sandbox-utils.js'
      )

      const command = await wrapCommandWithSandboxLinux({
        command: 'echo test',
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'allow-only',
          allowPaths: ['/bin', '/usr'],
          denyWithinAllow: [],
        },
        writeConfig: undefined,
        allowNetworkMetadata: true,
      })

      // Should include bindings for DNS files
      expect(command).toContain('/etc/resolv.conf')
      expect(command).toContain('/etc/hosts')
      expect(command).toContain('/etc/nsswitch.conf')
    })

    test('should NOT bind DNS files in allow-only mode when allowNetworkMetadata is false', async () => {
      if (skipIfNotLinux()) return

      const { wrapCommandWithSandboxLinux } = await import(
        '../src/sandbox/linux-sandbox-utils.js'
      )

      const command = await wrapCommandWithSandboxLinux({
        command: 'echo test',
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'allow-only',
          allowPaths: ['/bin', '/usr'],
          denyWithinAllow: [],
        },
        writeConfig: undefined,
        allowNetworkMetadata: false,
      })

      // Should NOT include automatic bindings for DNS files
      // (they might still appear if user explicitly added /etc to allowPaths)
      // We're testing that they're not automatically added
      const etcCount = (command.match(/--ro-bind.*\/etc\/resolv\.conf/g) || [])
        .length
      // If user didn't add /etc explicitly, DNS files shouldn't be bound
      expect(etcCount).toBe(0)
    })

    test('should block DNS files in deny-only mode when allowNetworkMetadata is false', async () => {
      if (skipIfNotLinux()) return

      const { wrapCommandWithSandboxLinux } = await import(
        '../src/sandbox/linux-sandbox-utils.js'
      )

      const command = await wrapCommandWithSandboxLinux({
        command: 'echo test',
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'deny-only',
          denyPaths: [],
        },
        writeConfig: undefined,
        allowNetworkMetadata: false,
      })

      // Should include /dev/null bindings to block DNS files
      expect(command).toContain('--ro-bind')
      expect(command).toContain('/dev/null')
      // At least one DNS file should be blocked
      const blockedCount =
        (command.match(/--ro-bind.*\/dev\/null.*\/etc\/resolv\.conf/g) || [])
          .length +
        (command.match(/--ro-bind.*\/dev\/null.*\/etc\/hosts/g) || []).length +
        (command.match(/--ro-bind.*\/dev\/null.*\/etc\/nsswitch\.conf/g) || [])
          .length
      expect(blockedCount).toBeGreaterThan(0)
    })

    test('should allow DNS files in deny-only mode when allowNetworkMetadata is true (default)', async () => {
      if (skipIfNotLinux()) return

      const { wrapCommandWithSandboxLinux } = await import(
        '../src/sandbox/linux-sandbox-utils.js'
      )

      const command = await wrapCommandWithSandboxLinux({
        command: 'echo test',
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'deny-only',
          denyPaths: [],
        },
        writeConfig: undefined,
        allowNetworkMetadata: true,
      })

      // Should NOT block DNS files (no /dev/null bindings for them)
      expect(command).not.toContain('/dev/null /etc/resolv.conf')
      expect(command).not.toContain('/dev/null /etc/hosts')
      expect(command).not.toContain('/dev/null /etc/nsswitch.conf')
    })
  })
})
