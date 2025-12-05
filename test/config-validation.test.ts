import { describe, test, expect } from 'bun:test'
import {
  NetworkConfigSchema,
  FilesystemConfigSchema,
  IgnoreViolationsConfigSchema,
  RipgrepConfigSchema,
  EnvConfigSchema,
} from '../src/sandbox/sandbox-config.js'
import { z } from 'zod'

// Local schema for testing the legacy config format
const SandboxRuntimeConfigSchema = z.object({
  network: NetworkConfigSchema,
  filesystem: FilesystemConfigSchema,
  ignoreViolations: IgnoreViolationsConfigSchema.optional(),
  enableWeakerNestedSandbox: z.boolean().optional(),
  ripgrep: RipgrepConfigSchema.optional(),
  mandatoryDenySearchDepth: z.number().int().min(1).max(10).optional(),
  env: EnvConfigSchema.optional(),
})

describe('Config Validation', () => {
  test('should validate a valid minimal config', () => {
    const config = {
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
  })

  test('should validate a config with valid domains', () => {
    const config = {
      network: {
        allowedDomains: ['example.com', '*.github.com', 'localhost'],
        deniedDomains: ['evil.com'],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
  })

  test('should reject invalid domain patterns', () => {
    const config = {
      network: {
        allowedDomains: ['not-a-domain'],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(false)
  })

  test('should reject domain with protocol', () => {
    const config = {
      network: {
        allowedDomains: ['https://example.com'],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(false)
  })

  test('should reject empty filesystem paths', () => {
    const config = {
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [''],
        allowWrite: [],
        denyWrite: [],
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(false)
  })

  test('should validate config with optional fields', () => {
    const config = {
      network: {
        allowedDomains: ['example.com'],
        deniedDomains: [],
        allowUnixSockets: ['/var/run/docker.sock'],
        allowAllUnixSockets: false,
        allowLocalBinding: true,
      },
      filesystem: {
        denyRead: ['/etc/shadow'],
        allowWrite: ['/tmp'],
        denyWrite: ['/etc'],
      },
      ignoreViolations: {
        '*': ['/usr/bin'],
        'git push': ['/usr/bin/nc'],
      },
      enableWeakerNestedSandbox: true,
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
  })

  test('should reject missing required fields', () => {
    const config = {
      network: {
        allowedDomains: [],
      },
      filesystem: {
        denyRead: [],
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(false)
  })

  test('should validate wildcard domains correctly', () => {
    const validWildcards = ['*.example.com', '*.github.io', '*.co.uk']

    const invalidWildcards = [
      '*example.com', // Missing dot after asterisk
      '*.com', // No subdomain
      '*.', // Invalid format
    ]

    for (const domain of validWildcards) {
      const config = {
        network: { allowedDomains: [domain], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      }
      const result = SandboxRuntimeConfigSchema.safeParse(config)
      expect(result.success).toBe(true)
    }

    for (const domain of invalidWildcards) {
      const config = {
        network: { allowedDomains: [domain], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      }
      const result = SandboxRuntimeConfigSchema.safeParse(config)
      expect(result.success).toBe(false)
    }
  })

  test('should validate config with custom ripgrep command', () => {
    const config = {
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
      },
      ripgrep: {
        command: '/usr/local/bin/rg',
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.ripgrep?.command).toBe('/usr/local/bin/rg')
    }
  })

  test('should validate config with custom ripgrep command and args', () => {
    const config = {
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
      },
      ripgrep: {
        command: 'claude',
        args: ['--ripgrep'],
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.ripgrep?.command).toBe('claude')
      expect(result.data.ripgrep?.args).toEqual(['--ripgrep'])
    }
  })

  test('should use default ripgrep command when not specified', () => {
    const config = {
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.ripgrep).toBeUndefined()
    }
  })

  describe('dot-prefix domain patterns - NEW', () => {
    test('should validate dot-prefix domain patterns', () => {
      const validDotPrefix = [
        '.example.com',
        '.github.io',
        '.co.uk',
        '.api.example.com',
      ]

      for (const domain of validDotPrefix) {
        const config = {
          network: { allowedDomains: [domain], deniedDomains: [] },
          filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
        }
        const result = SandboxRuntimeConfigSchema.safeParse(config)
        expect(result.success).toBe(true)
      }
    })

    test('should reject invalid dot-prefix patterns', () => {
      const invalidDotPrefix = [
        '.com', // Too broad (only one part)
        '..example.com', // Double dot
        '.example.', // Trailing dot
      ]

      for (const domain of invalidDotPrefix) {
        const config = {
          network: { allowedDomains: [domain], deniedDomains: [] },
          filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
        }
        const result = SandboxRuntimeConfigSchema.safeParse(config)
        expect(result.success).toBe(false)
      }
    })
  })

  describe('wildcard * string configuration - NEW', () => {
    test('should validate standalone * wildcard as string for allowedDomains', () => {
      const config = {
        network: {
          allowedDomains: '*', // String, not array
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowWrite: [],
          denyWrite: [],
        },
      }
      const result = SandboxRuntimeConfigSchema.safeParse(config)
      expect(result.success).toBe(true)
    })

    test('should validate standalone * wildcard as string for deniedDomains', () => {
      const config = {
        network: {
          allowedDomains: [],
          deniedDomains: '*', // String, not array
        },
        filesystem: {
          denyRead: [],
          allowWrite: [],
          denyWrite: [],
        },
      }
      const result = SandboxRuntimeConfigSchema.safeParse(config)
      expect(result.success).toBe(true)
    })

    test('should reject * wildcard in array format', () => {
      const config = {
        network: {
          allowedDomains: ['*'], // Array containing * - should be rejected
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowWrite: [],
          denyWrite: [],
        },
      }
      const result = SandboxRuntimeConfigSchema.safeParse(config)
      expect(result.success).toBe(false)
    })

    test('should validate normal array configuration', () => {
      const config = {
        network: {
          allowedDomains: ['example.com', '.github.com'],
          deniedDomains: ['malicious.com'],
        },
        filesystem: {
          denyRead: [],
          allowWrite: [],
          denyWrite: [],
        },
      }
      const result = SandboxRuntimeConfigSchema.safeParse(config)
      expect(result.success).toBe(true)
    })

    test('should reject invalid wildcard variants', () => {
      const invalidPatterns = ['**', '*foo', 'foo*', '*.*']

      for (const pattern of invalidPatterns) {
        const config = {
          network: { allowedDomains: [pattern], deniedDomains: [] },
          filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
        }
        const result = SandboxRuntimeConfigSchema.safeParse(config)
        expect(result.success).toBe(false)
      }
    })
  })
})
