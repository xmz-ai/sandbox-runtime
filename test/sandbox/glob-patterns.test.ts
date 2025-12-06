/**
 * Glob Pattern Support Tests
 *
 * Tests glob pattern expansion on Linux and glob pattern usage on macOS.
 *
 * Platform differences:
 * - macOS: Uses regex matching in sandbox profiles (protects future files)
 * - Linux: Expands globs at config time via ripgrep (only existing files)
 */

import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { NetworkManager } from '../../src/sandbox/network-manager.js'
import { getPlatform } from '../../src/utils/platform.js'
import { spawn } from 'node:child_process'
import { mkdirSync, writeFileSync, unlinkSync, rmSync } from 'node:fs'
import { join } from 'node:path'

describe('Glob Pattern Support Tests', () => {
  let networkManager: NetworkManager
  let testDir: string

  function skipIfUnsupportedPlatform(): boolean {
    const platform = getPlatform()
    if (platform !== 'macos' && platform !== 'linux') {
      console.log(`Skipping glob pattern test on ${platform}`)
      return true
    }
    return false
  }

  beforeAll(async () => {
    if (skipIfUnsupportedPlatform()) return

    // Create test directory structure with various files
    testDir = join(process.cwd(), 'test-glob-patterns')
    try {
      rmSync(testDir, { recursive: true, force: true })
    } catch {
      // Directory doesn't exist, that's fine
    }

    mkdirSync(testDir, { recursive: true })
    mkdirSync(join(testDir, 'src'), { recursive: true })
    mkdirSync(join(testDir, 'config'), { recursive: true })
    mkdirSync(join(testDir, 'secrets'), { recursive: true })

    // Create test files
    writeFileSync(join(testDir, '.env'), 'SECRET=test')
    writeFileSync(join(testDir, '.env.local'), 'SECRET=local')
    writeFileSync(join(testDir, 'src', '.env'), 'SECRET=src')
    writeFileSync(join(testDir, 'config', 'prod.json'), '{"db":"prod"}')
    writeFileSync(join(testDir, 'config', 'dev.json'), '{"db":"dev"}')
    writeFileSync(join(testDir, 'secrets', 'key.pem'), 'PRIVATE_KEY')
    writeFileSync(join(testDir, 'README.md'), '# Test')

    // Initialize network manager
    networkManager = new NetworkManager()
    await networkManager.initialize({
      allowedDomains: [],
      deniedDomains: '*',
    })
  })

  afterAll(async () => {
    if (skipIfUnsupportedPlatform()) return

    await networkManager?.shutdown()

    // Clean up test directory
    try {
      rmSync(testDir, { recursive: true, force: true })
    } catch {
      // Ignore cleanup errors
    }
  })

  /**
   * Helper function to run a sandboxed command
   */
  async function runSandboxedCommand(
    command: string,
    config: {
      allowWrite?: string[]
      denyWrite?: string[]
      allowRead?: string[]
      denyRead?: string[]
    },
  ): Promise<{ success: boolean; output: string; error: string }> {
    const sandbox = new SandboxManager(networkManager, {
      filesystem: config,
    })

    try {
      const wrappedCommand = await sandbox.wrapWithSandbox(command)

      return new Promise((resolve, reject) => {
        const proc = spawn('bash', ['-c', wrappedCommand], {
          cwd: process.cwd(),
          stdio: ['pipe', 'pipe', 'pipe'],
        })

        let stdout = ''
        let stderr = ''

        proc.stdout?.on('data', data => {
          stdout += data.toString()
        })

        proc.stderr?.on('data', data => {
          stderr += data.toString()
        })

        proc.on('close', code => {
          resolve({
            success: code === 0,
            output: stdout,
            error: stderr,
          })
        })

        proc.on('error', err => {
          reject(err)
        })

        // Timeout after 10 seconds
        setTimeout(() => {
          proc.kill()
          reject(new Error('Command timeout'))
        }, 10000)
      })
    } finally {
      await sandbox.dispose()
    }
  }

  describe('Glob patterns in denyWrite configuration', () => {
    it('should deny writes to all .env files using **/.env pattern', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedCommand(
        `echo "MODIFIED" > ${join(testDir, '.env')}`,
        {
          allowWrite: [testDir],
          denyWrite: ['**/.env'],
        },
      )

      // Command should fail due to .env being blocked
      expect(result.success).toBe(false)
    })

    it('should deny writes to .env.* files using **/.env.* pattern', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedCommand(
        `echo "MODIFIED" > ${join(testDir, '.env.local')}`,
        {
          allowWrite: [testDir],
          denyWrite: ['**/.env*'],
        },
      )

      expect(result.success).toBe(false)
    })

    it('should deny writes to config/*.json files using glob', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedCommand(
        `echo "MODIFIED" > ${join(testDir, 'config', 'prod.json')}`,
        {
          allowWrite: [testDir],
          denyWrite: [`${testDir}/config/*.json`],
        },
      )

      expect(result.success).toBe(false)
    })

    it('should allow writes to non-matching files', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedCommand(
        `echo "MODIFIED" > ${join(testDir, 'README.md')}`,
        {
          allowWrite: [testDir],
          denyWrite: ['**/.env'],
        },
      )

      expect(result.success).toBe(true)
    })
  })

  describe('Glob patterns in allowWrite configuration', () => {
    it('should only allow writes to src/**/*.ts files', async () => {
      if (skipIfUnsupportedPlatform()) return

      // Create a test .ts file
      writeFileSync(join(testDir, 'src', 'test.ts'), 'export {}')

      const result = await runSandboxedCommand(
        `echo "MODIFIED" > ${join(testDir, 'src', 'test.ts')}`,
        {
          allowWrite: [`${testDir}/src/**/*.ts`],
        },
      )

      expect(result.success).toBe(true)
    })

    it('should deny writes outside the glob pattern', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedCommand(
        `echo "MODIFIED" > ${join(testDir, 'README.md')}`,
        {
          allowWrite: [`${testDir}/src/**/*.ts`],
        },
      )

      // Should fail because README.md is not in src/**/*.ts
      expect(result.success).toBe(false)
    })
  })

  describe('Glob patterns in denyRead configuration', () => {
    it('should deny reads to secrets/* using glob', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedCommand(
        `cat ${join(testDir, 'secrets', 'key.pem')}`,
        {
          denyRead: [`${testDir}/secrets/*`],
        },
      )

      // Should fail to read the file
      expect(result.success).toBe(false)
    })

    it('should allow reads to non-matching files', async () => {
      if (skipIfUnsupportedPlatform()) return

      // Restore README.md content in case previous tests modified it
      writeFileSync(join(testDir, 'README.md'), '# Test')

      const result = await runSandboxedCommand(
        `cat ${join(testDir, 'README.md')}`,
        {
          denyRead: [`${testDir}/secrets/*`],
        },
      )

      expect(result.success).toBe(true)
      expect(result.output).toContain('# Test')
    })
  })

  describe('Complex glob patterns', () => {
    it('should handle multiple glob patterns', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedCommand(`echo "test"`, {
        allowWrite: [testDir],
        denyWrite: ['**/.env*', '**/secrets/*', '**/config/*.json'],
      })

      // Just verify the sandbox configuration doesn't crash
      expect(result.success).toBe(true)
    })

    it('should handle mix of globs and literal paths', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedCommand(`echo "test"`, {
        allowWrite: [testDir],
        denyWrite: [
          '**/.env',
          join(testDir, 'secrets', 'key.pem'), // literal path
          `${testDir}/config/*.json`, // glob
        ],
      })

      expect(result.success).toBe(true)
    })
  })

  describe('Platform-specific behavior', () => {
    it('on Linux, glob patterns only protect files that exist at init time', async () => {
      const platform = getPlatform()
      if (platform !== 'linux') {
        console.log('Skipping Linux-specific test')
        return
      }

      // This test verifies Linux behavior: globs expanded at config time
      // Files created AFTER sandbox init are NOT protected

      const newFile = join(testDir, '.env.new')

      // Run sandbox with glob that would match .env.new
      const result = await runSandboxedCommand(
        `touch ${newFile} && echo "NEW" > ${newFile}`,
        {
          allowWrite: [testDir],
          denyWrite: ['**/.env*'],
        },
      )

      // On Linux, this should succeed because .env.new didn't exist
      // when the glob was expanded
      expect(result.success).toBe(true)

      // Clean up
      try {
        unlinkSync(newFile)
      } catch {
        // Ignore
      }
    })

    it('on macOS, glob patterns protect future files', async () => {
      const platform = getPlatform()
      if (platform !== 'macos') {
        console.log('Skipping macOS-specific test')
        return
      }

      // This test verifies macOS behavior: globs use regex matching
      // Files created AFTER sandbox init ARE protected

      const newFile = join(testDir, '.env.new')

      // Run sandbox with glob that would match .env.new
      const result = await runSandboxedCommand(
        `touch ${newFile} && echo "NEW" > ${newFile}`,
        {
          allowWrite: [testDir],
          denyWrite: ['**/.env*'],
        },
      )

      // On macOS, this should fail because .env.new matches the pattern
      expect(result.success).toBe(false)

      // Clean up
      try {
        unlinkSync(newFile)
      } catch {
        // Ignore
      }
    })
  })
})
