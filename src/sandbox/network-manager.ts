import { createHttpProxyServer } from './http-proxy.js'
import { createSocksProxyServer } from './socks-proxy.js'
import type { SocksProxyWrapper } from './socks-proxy.js'
import { logForDebugging } from '../utils/debug.js'
import { getPlatform } from '../utils/platform.js'
import * as fs from 'fs'
import type { SandboxAskCallback } from './sandbox-schemas.js'
import {
  initializeLinuxNetworkBridge,
  type LinuxNetworkBridgeContext,
} from './linux-sandbox-utils.js'
import { matchesDomainPattern } from './sandbox-utils.js'

/**
 * Network context containing proxy ports and Linux bridge information
 */
export interface NetworkContext {
  httpProxyPort: number
  socksProxyPort: number
  linuxBridge?: LinuxNetworkBridgeContext
}

/**
 * Configuration for NetworkManager
 */
export interface NetworkConfig {
  allowedDomains: string[]
  deniedDomains: string[]
  allowUnixSockets?: string[]
  allowAllUnixSockets?: boolean
  allowLocalBinding?: boolean
  httpProxyPort?: number
  socksProxyPort?: number
}

/**
 * NetworkManager - Manages HTTP/SOCKS proxy servers and network restrictions
 *
 * Users can create one shared instance (recommended) or multiple instances for isolation.
 * Each instance manages its own proxy servers and network filtering rules.
 */
export class NetworkManager {
  private httpProxyServer: ReturnType<typeof createHttpProxyServer> | undefined
  private socksProxyServer: SocksProxyWrapper | undefined
  private networkContext: NetworkContext | undefined
  private initializationPromise: Promise<NetworkContext | undefined> | undefined
  private cleanupRegistered = false
  private config: NetworkConfig | undefined
  private sandboxAskCallback: SandboxAskCallback | undefined
  private initialized = false

  constructor() {
    // Public constructor - users instantiate as needed
  }

  /**
   * Initialize the network manager with proxy servers
   */
  async initialize(
    config: NetworkConfig,
    sandboxAskCallback?: SandboxAskCallback,
  ): Promise<void> {
    // Return if already initializing (idempotent)
    if (this.initializationPromise) {
      await this.initializationPromise
      return
    }

    // Store config
    this.config = config
    this.sandboxAskCallback = sandboxAskCallback

    // Register cleanup handlers
    this.registerCleanup()

    // Initialize network infrastructure
    this.initializationPromise = (async () => {
      try {
        // Only start proxies and bridges if we have domains to filter
        // If allowedDomains is empty, we block ALL network (no proxy/bridge needed)
        const needsProxy = config.allowedDomains.length > 0

        if (!needsProxy) {
          logForDebugging(
            'Empty allowedDomains - network will be completely blocked (no proxy)',
          )
          // Return undefined context - signals "initialized but no proxy"
          this.networkContext = undefined
          return undefined
        }

        // Conditionally start proxy servers based on config
        let httpProxyPort: number
        if (config.httpProxyPort !== undefined) {
          // Use external HTTP proxy (don't start a server)
          httpProxyPort = config.httpProxyPort
          logForDebugging(`Using external HTTP proxy on port ${httpProxyPort}`)
        } else {
          // Start local HTTP proxy
          httpProxyPort = await this.startHttpProxyServer()
        }

        let socksProxyPort: number
        if (config.socksProxyPort !== undefined) {
          // Use external SOCKS proxy (don't start a server)
          socksProxyPort = config.socksProxyPort
          logForDebugging(
            `Using external SOCKS proxy on port ${socksProxyPort}`,
          )
        } else {
          // Start local SOCKS proxy
          socksProxyPort = await this.startSocksProxyServer()
        }

        // Initialize platform-specific infrastructure
        let linuxBridge: LinuxNetworkBridgeContext | undefined
        if (getPlatform() === 'linux') {
          linuxBridge = await initializeLinuxNetworkBridge(
            httpProxyPort,
            socksProxyPort,
          )
        }

        const context: NetworkContext = {
          httpProxyPort,
          socksProxyPort,
          linuxBridge,
        }
        this.networkContext = context
        logForDebugging('Network infrastructure initialized')
        return context
      } catch (error) {
        // Clear state on error so initialization can be retried
        this.initializationPromise = undefined
        this.networkContext = undefined
        this.shutdown().catch(e => {
          logForDebugging(`Cleanup failed in initializationPromise ${e}`, {
            level: 'error',
          })
        })
        throw error
      }
    })()

    await this.initializationPromise
    this.initialized = true
  }

  /**
   * Shutdown the network manager and clean up resources
   */
  async shutdown(): Promise<void> {
    if (this.networkContext?.linuxBridge) {
      const {
        httpSocketPath,
        socksSocketPath,
        httpBridgeProcess,
        socksBridgeProcess,
      } = this.networkContext.linuxBridge

      // Create array to wait for process exits
      const exitPromises: Promise<void>[] = []

      // Kill HTTP bridge and wait for it to exit
      if (httpBridgeProcess.pid && !httpBridgeProcess.killed) {
        try {
          process.kill(httpBridgeProcess.pid, 'SIGTERM')
          logForDebugging('Sent SIGTERM to HTTP bridge process')

          // Wait for process to exit
          exitPromises.push(
            new Promise<void>(resolve => {
              httpBridgeProcess.once('exit', () => {
                logForDebugging('HTTP bridge process exited')
                resolve()
              })
              // Timeout after 5 seconds
              setTimeout(() => {
                if (!httpBridgeProcess.killed) {
                  logForDebugging('HTTP bridge did not exit, forcing SIGKILL', {
                    level: 'warn',
                  })
                  try {
                    if (httpBridgeProcess.pid) {
                      process.kill(httpBridgeProcess.pid, 'SIGKILL')
                    }
                  } catch {
                    // Process may have already exited
                  }
                }
                resolve()
              }, 5000)
            }),
          )
        } catch (err) {
          if ((err as NodeJS.ErrnoException).code !== 'ESRCH') {
            logForDebugging(`Error killing HTTP bridge: ${err}`, {
              level: 'error',
            })
          }
        }
      }

      // Kill SOCKS bridge and wait for it to exit
      if (socksBridgeProcess.pid && !socksBridgeProcess.killed) {
        try {
          process.kill(socksBridgeProcess.pid, 'SIGTERM')
          logForDebugging('Sent SIGTERM to SOCKS bridge process')

          // Wait for process to exit
          exitPromises.push(
            new Promise<void>(resolve => {
              socksBridgeProcess.once('exit', () => {
                logForDebugging('SOCKS bridge process exited')
                resolve()
              })
              // Timeout after 5 seconds
              setTimeout(() => {
                if (!socksBridgeProcess.killed) {
                  logForDebugging(
                    'SOCKS bridge did not exit, forcing SIGKILL',
                    {
                      level: 'warn',
                    },
                  )
                  try {
                    if (socksBridgeProcess.pid) {
                      process.kill(socksBridgeProcess.pid, 'SIGKILL')
                    }
                  } catch {
                    // Process may have already exited
                  }
                }
                resolve()
              }, 5000)
            }),
          )
        } catch (err) {
          if ((err as NodeJS.ErrnoException).code !== 'ESRCH') {
            logForDebugging(`Error killing SOCKS bridge: ${err}`, {
              level: 'error',
            })
          }
        }
      }

      // Wait for both processes to exit
      await Promise.all(exitPromises)

      // Clean up sockets
      if (httpSocketPath) {
        try {
          fs.rmSync(httpSocketPath, { force: true })
          logForDebugging('Cleaned up HTTP socket')
        } catch (err) {
          logForDebugging(`HTTP socket cleanup error: ${err}`, {
            level: 'error',
          })
        }
      }

      if (socksSocketPath) {
        try {
          fs.rmSync(socksSocketPath, { force: true })
          logForDebugging('Cleaned up SOCKS socket')
        } catch (err) {
          logForDebugging(`SOCKS socket cleanup error: ${err}`, {
            level: 'error',
          })
        }
      }
    }

    // Close servers in parallel (only if they exist, i.e., were started by us)
    const closePromises: Promise<void>[] = []

    if (this.httpProxyServer) {
      const server = this.httpProxyServer
      const httpClose = new Promise<void>(resolve => {
        server.close(error => {
          if (error && error.message !== 'Server is not running.') {
            logForDebugging(
              `Error closing HTTP proxy server: ${error.message}`,
              {
                level: 'error',
              },
            )
          }
          resolve()
        })
      })
      closePromises.push(httpClose)
    }

    if (this.socksProxyServer) {
      const socksClose = this.socksProxyServer.close().catch((error: Error) => {
        logForDebugging(`Error closing SOCKS proxy server: ${error.message}`, {
          level: 'error',
        })
      })
      closePromises.push(socksClose)
    }

    // Wait for all servers to close
    await Promise.all(closePromises)

    // Clear references
    this.httpProxyServer = undefined
    this.socksProxyServer = undefined
    this.networkContext = undefined
    this.initializationPromise = undefined
    this.initialized = false
  }

  /**
   * Check if the network manager is initialized
   */
  isInitialized(): boolean {
    return this.initialized
  }

  /**
   * Get the network context (proxy ports and Linux bridge info)
   */
  getNetworkContext(): NetworkContext | undefined {
    return this.networkContext
  }

  /**
   * Get the HTTP proxy port
   */
  getHttpProxyPort(): number | undefined {
    return this.networkContext?.httpProxyPort
  }

  /**
   * Get the SOCKS proxy port
   */
  getSocksProxyPort(): number | undefined {
    return this.networkContext?.socksProxyPort
  }

  /**
   * Get the Linux HTTP socket path (Linux only)
   */
  getLinuxHttpSocketPath(): string | undefined {
    return this.networkContext?.linuxBridge?.httpSocketPath
  }

  /**
   * Get the Linux SOCKS socket path (Linux only)
   */
  getLinuxSocksSocketPath(): string | undefined {
    return this.networkContext?.linuxBridge?.socksSocketPath
  }

  /**
   * Get the network configuration
   */
  getConfig(): NetworkConfig | undefined {
    return this.config
  }

  // ============================================================================
  // Private Helper Methods
  // ============================================================================

  private registerCleanup(): void {
    if (this.cleanupRegistered) {
      return
    }
    const cleanupHandler = () =>
      this.shutdown().catch(e => {
        logForDebugging(`Cleanup failed in registerCleanup ${e}`, {
          level: 'error',
        })
      })
    process.once('exit', cleanupHandler)
    process.once('SIGINT', cleanupHandler)
    process.once('SIGTERM', cleanupHandler)
    this.cleanupRegistered = true
  }

  private async filterNetworkRequest(
    port: number,
    host: string,
  ): Promise<boolean> {
    if (!this.config) {
      logForDebugging('No config available, denying network request')
      return false
    }

    // Check denied domains first
    for (const deniedDomain of this.config.deniedDomains) {
      if (matchesDomainPattern(host, deniedDomain)) {
        logForDebugging(`Denied by config rule: ${host}:${port}`)
        return false
      }
    }

    // Check allowed domains
    for (const allowedDomain of this.config.allowedDomains) {
      if (matchesDomainPattern(host, allowedDomain)) {
        logForDebugging(`Allowed by config rule: ${host}:${port}`)
        return true
      }
    }

    // No matching rules - ask user or deny
    if (!this.sandboxAskCallback) {
      logForDebugging(`No matching config rule, denying: ${host}:${port}`)
      return false
    }

    logForDebugging(`No matching config rule, asking user: ${host}:${port}`)
    try {
      const userAllowed = await this.sandboxAskCallback({ host, port })
      if (userAllowed) {
        logForDebugging(`User allowed: ${host}:${port}`)
        return true
      } else {
        logForDebugging(`User denied: ${host}:${port}`)
        return false
      }
    } catch (error) {
      logForDebugging(`Error in permission callback: ${error}`, {
        level: 'error',
      })
      return false
    }
  }

  private async startHttpProxyServer(): Promise<number> {
    this.httpProxyServer = createHttpProxyServer({
      filter: (port: number, host: string) =>
        this.filterNetworkRequest(port, host),
    })

    return new Promise<number>((resolve, reject) => {
      if (!this.httpProxyServer) {
        reject(new Error('HTTP proxy server undefined before listen'))
        return
      }

      const server = this.httpProxyServer

      server.once('error', reject)
      server.once('listening', () => {
        const address = server.address()
        if (address && typeof address === 'object') {
          server.unref()
          logForDebugging(`HTTP proxy listening on localhost:${address.port}`)
          resolve(address.port)
        } else {
          reject(new Error('Failed to get proxy server address'))
        }
      })

      server.listen(0, '127.0.0.1')
    })
  }

  private async startSocksProxyServer(): Promise<number> {
    this.socksProxyServer = createSocksProxyServer({
      filter: (port: number, host: string) =>
        this.filterNetworkRequest(port, host),
    })

    return new Promise<number>((resolve, reject) => {
      if (!this.socksProxyServer) {
        // This is mostly just for the typechecker
        reject(new Error('SOCKS proxy server undefined before listen'))
        return
      }

      this.socksProxyServer
        .listen(0, '127.0.0.1')
        .then((port: number) => {
          this.socksProxyServer?.unref()
          resolve(port)
        })
        .catch(reject)
    })
  }
}
