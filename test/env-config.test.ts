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

describe('Environment Variables Config Validation', () => {
  test('should validate config with explicit env var values', () => {
    const config = {
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      env: {
        MY_VAR: 'my_value',
        DEBUG: 'true',
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.env).toEqual({
        MY_VAR: 'my_value',
        DEBUG: 'true',
      })
    }
  })

  test('should validate config with inherited env vars (null)', () => {
    const config = {
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      env: {
        HOME: null,
        PATH: null,
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.env).toEqual({
        HOME: null,
        PATH: null,
      })
    }
  })

  test('should validate config with mixed explicit and inherited', () => {
    const config = {
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      env: {
        CUSTOM_VAR: 'custom',
        INHERITED_VAR: null,
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.env).toEqual({
        CUSTOM_VAR: 'custom',
        INHERITED_VAR: null,
      })
    }
  })

  test('should allow config without env (backward compatible)', () => {
    const config = {
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.env).toBeUndefined()
    }
  })

  test('should allow empty env object', () => {
    const config = {
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      env: {},
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.env).toEqual({})
    }
  })

  test('should allow empty string value', () => {
    const config = {
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      env: {
        EMPTY_VAR: '',
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.env).toEqual({
        EMPTY_VAR: '',
      })
    }
  })

  test('should reject env config with non-string, non-null values', () => {
    const config = {
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      env: {
        INVALID_VAR: 123, // Should be string or null
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(false)
  })
})

describe('EnvConfig Schema', () => {
  test('should validate record with string values', () => {
    const result = EnvConfigSchema.safeParse({
      VAR1: 'value1',
      VAR2: 'value2',
    })
    expect(result.success).toBe(true)
  })

  test('should validate record with null values', () => {
    const result = EnvConfigSchema.safeParse({
      VAR1: null,
      VAR2: null,
    })
    expect(result.success).toBe(true)
  })

  test('should validate record with mixed string and null values', () => {
    const result = EnvConfigSchema.safeParse({
      VAR1: 'value',
      VAR2: null,
    })
    expect(result.success).toBe(true)
  })

  test('should validate undefined (optional)', () => {
    const result = EnvConfigSchema.safeParse(undefined)
    expect(result.success).toBe(true)
  })

  test('should validate empty object', () => {
    const result = EnvConfigSchema.safeParse({})
    expect(result.success).toBe(true)
  })

  test('should reject non-string, non-null values', () => {
    const result = EnvConfigSchema.safeParse({
      VAR: 123,
    })
    expect(result.success).toBe(false)
  })

  test('should reject boolean values', () => {
    const result = EnvConfigSchema.safeParse({
      VAR: true,
    })
    expect(result.success).toBe(false)
  })
})

describe('Reserved Environment Variables', () => {
  test('should allow setting non-reserved variables', () => {
    const config = {
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      env: {
        MY_CUSTOM_VAR: 'value',
        ANOTHER_VAR: 'value2',
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
  })

  test('should accept reserved variables in config (filtering happens at runtime)', () => {
    // Config validation allows reserved vars - they are filtered during execution
    const config = {
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      env: {
        NODE_OPTIONS: 'custom value', // Reserved, will be filtered
        http_proxy: 'http://proxy', // Reserved (case-insensitive), will be filtered
        MY_VAR: 'allowed',
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
  })
})
