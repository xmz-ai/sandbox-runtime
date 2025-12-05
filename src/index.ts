// Library exports
export { NetworkManager } from './sandbox/network-manager.js'
export type { NetworkContext } from './sandbox/network-manager.js'
export { SandboxManager } from './sandbox/sandbox-manager.js'
export { SandboxViolationStore } from './sandbox/sandbox-violation-store.js'

// Configuration types and schemas
export type {
  NetworkConfig,
  FilesystemConfig,
  IgnoreViolationsConfig,
  SandboxInstanceConfig,
  SandboxOptions,
} from './sandbox/sandbox-config.js'

export {
  NetworkConfigSchema,
  FilesystemConfigSchema,
  IgnoreViolationsConfigSchema,
  RipgrepConfigSchema,
  SandboxInstanceConfigSchema,
  SandboxOptionsSchema,
} from './sandbox/sandbox-config.js'

// Schema types and utilities
export type {
  SandboxAskCallback,
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
  NetworkRestrictionConfig,
  NetworkHostPattern,
} from './sandbox/sandbox-schemas.js'

// Platform-specific utilities
export type { SandboxViolationEvent } from './sandbox/macos-sandbox-utils.js'

// Utility functions
export {
  isSupportedPlatform,
  checkSandboxDependencies,
} from './sandbox/sandbox-dependencies.js'
