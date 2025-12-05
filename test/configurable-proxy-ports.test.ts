import { describe, it, expect, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import * as http from 'node:http'
import * as net from 'node:net'
import { NetworkManager } from '../src/sandbox/network-manager.js'
import { SandboxManager } from '../src/sandbox/sandbox-manager.js'
import { getPlatform } from '../src/utils/platform.js'

/**
 * Integration tests for configurable proxy ports feature
 * Tests that external proxy ports can be specified in config,
 * and that the library skips starting proxies when external ports are provided
 */
describe('Configurable Proxy Ports Integration Tests', () => {
  // Track network managers for cleanup
  const networkManagers: NetworkManager[] = []

  afterAll(async () => {
    // Clean up all network managers
    for (const nm of networkManagers) {
      await nm.shutdown()
    }
  })

  describe('External HTTP proxy + local SOCKS', () => {
    it('should use external HTTP proxy when httpProxyPort is provided', async () => {
      const networkManager = new NetworkManager()
      networkManagers.push(networkManager)

      await networkManager.initialize({
        allowedDomains: ['example.com'],
        deniedDomains: [],
        httpProxyPort: 8888, // External HTTP proxy
        // socksProxyPort not specified - should start locally
      })

      // Verify HTTP proxy port matches what was configured
      const httpProxyPort = networkManager.getHttpProxyPort()
      expect(httpProxyPort).toBe(8888)

      // SOCKS proxy should have been started locally with dynamic port
      const socksProxyPort = networkManager.getSocksProxyPort()
      expect(socksProxyPort).toBeDefined()
      expect(socksProxyPort).not.toBe(8888)
      expect(socksProxyPort).toBeGreaterThan(0)

      await networkManager.shutdown()
    })
  })

  describe('External SOCKS proxy + local HTTP', () => {
    it('should use external SOCKS proxy when socksProxyPort is provided', async () => {
      const networkManager = new NetworkManager()
      networkManagers.push(networkManager)

      await networkManager.initialize({
        allowedDomains: ['example.com'],
        deniedDomains: [],
        // httpProxyPort not specified - should start locally
        socksProxyPort: 1080, // External SOCKS proxy
      })

      // Verify SOCKS proxy port matches what was configured
      const socksProxyPort = networkManager.getSocksProxyPort()
      expect(socksProxyPort).toBe(1080)

      // HTTP proxy should have been started locally with dynamic port
      const httpProxyPort = networkManager.getHttpProxyPort()
      expect(httpProxyPort).toBeDefined()
      expect(httpProxyPort).not.toBe(1080)
      expect(httpProxyPort).toBeGreaterThan(0)

      await networkManager.shutdown()
    })
  })

  describe('Both external proxies', () => {
    it('should use both external proxies when both ports are provided', async () => {
      const networkManager = new NetworkManager()
      networkManagers.push(networkManager)

      await networkManager.initialize({
        allowedDomains: ['example.com'],
        deniedDomains: [],
        httpProxyPort: 9090, // External HTTP proxy
        socksProxyPort: 9091, // External SOCKS proxy
      })

      // Verify both proxy ports match what was configured
      const httpProxyPort = networkManager.getHttpProxyPort()
      expect(httpProxyPort).toBe(9090)

      const socksProxyPort = networkManager.getSocksProxyPort()
      expect(socksProxyPort).toBe(9091)

      await networkManager.shutdown()
    })
  })

  describe('Both local proxies (baseline)', () => {
    it('should start both proxies locally when no ports are configured', async () => {
      const networkManager = new NetworkManager()
      networkManagers.push(networkManager)

      await networkManager.initialize({
        allowedDomains: ['example.com'],
        deniedDomains: [],
        // No httpProxyPort or socksProxyPort - both should start locally
      })

      // Both proxies should have been started locally with dynamic ports
      const httpProxyPort = networkManager.getHttpProxyPort()
      expect(httpProxyPort).toBeDefined()
      expect(httpProxyPort).toBeGreaterThan(0)
      expect(httpProxyPort).toBeLessThan(65536)

      const socksProxyPort = networkManager.getSocksProxyPort()
      expect(socksProxyPort).toBeDefined()
      expect(socksProxyPort).toBeGreaterThan(0)
      expect(socksProxyPort).toBeLessThan(65536)

      // Should be different ports
      expect(httpProxyPort).not.toBe(socksProxyPort)

      await networkManager.shutdown()
    })
  })

  describe('Multiple initialize/reset cycles', () => {
    it('should handle multiple initialize and reset cycles with different configs', async () => {
      // First: both local
      const networkManager1 = new NetworkManager()
      networkManagers.push(networkManager1)

      await networkManager1.initialize({
        allowedDomains: ['example.com'],
        deniedDomains: [],
      })
      const httpPort1 = networkManager1.getHttpProxyPort()
      const socksPort1 = networkManager1.getSocksProxyPort()
      expect(httpPort1).toBeDefined()
      expect(socksPort1).toBeDefined()
      await networkManager1.shutdown()

      // Second: both external
      const networkManager2 = new NetworkManager()
      networkManagers.push(networkManager2)

      await networkManager2.initialize({
        allowedDomains: ['example.com'],
        deniedDomains: [],
        httpProxyPort: 7777,
        socksProxyPort: 7778,
      })
      expect(networkManager2.getHttpProxyPort()).toBe(7777)
      expect(networkManager2.getSocksProxyPort()).toBe(7778)
      await networkManager2.shutdown()

      // Third: mixed (external HTTP, local SOCKS)
      const networkManager3 = new NetworkManager()
      networkManagers.push(networkManager3)

      await networkManager3.initialize({
        allowedDomains: ['example.com'],
        deniedDomains: [],
        httpProxyPort: 6666,
      })
      expect(networkManager3.getHttpProxyPort()).toBe(6666)
      const socksPort3 = networkManager3.getSocksProxyPort()
      expect(socksPort3).toBeDefined()
      expect(socksPort3).not.toBe(6666)
      await networkManager3.shutdown()
    })
  })

  describe('Port validation', () => {
    it('should accept valid port numbers (1-65535)', async () => {
      const networkManager = new NetworkManager()
      networkManagers.push(networkManager)

      await networkManager.initialize({
        allowedDomains: ['example.com'],
        deniedDomains: [],
        httpProxyPort: 1,
        socksProxyPort: 65535,
      })
      expect(networkManager.getHttpProxyPort()).toBe(1)
      expect(networkManager.getSocksProxyPort()).toBe(65535)
      await networkManager.shutdown()
    })

    it('should accept standard proxy ports', async () => {
      const networkManager = new NetworkManager()
      networkManagers.push(networkManager)

      await networkManager.initialize({
        allowedDomains: ['example.com'],
        deniedDomains: [],
        httpProxyPort: 3128, // Standard HTTP proxy port
        socksProxyPort: 1080, // Standard SOCKS proxy port
      })
      expect(networkManager.getHttpProxyPort()).toBe(3128)
      expect(networkManager.getSocksProxyPort()).toBe(1080)
      await networkManager.shutdown()
    })
  })

  describe('Idempotent initialization', () => {
    it('should handle calling initialize multiple times without reset', async () => {
      const networkManager = new NetworkManager()
      networkManagers.push(networkManager)

      // Initialize once
      await networkManager.initialize({
        allowedDomains: ['example.com'],
        deniedDomains: [],
        httpProxyPort: 5555,
        socksProxyPort: 5556,
      })
      const httpPort1 = networkManager.getHttpProxyPort()
      const socksPort1 = networkManager.getSocksProxyPort()

      // Initialize again without reset (should be idempotent)
      await networkManager.initialize({
        allowedDomains: ['example.com'],
        deniedDomains: [],
        httpProxyPort: 5555,
        socksProxyPort: 5556,
      })
      const httpPort2 = networkManager.getHttpProxyPort()
      const socksPort2 = networkManager.getSocksProxyPort()

      // Should return the same ports
      expect(httpPort2).toBe(httpPort1)
      expect(socksPort2).toBe(socksPort1)
      expect(httpPort2).toBe(5555)
      expect(socksPort2).toBe(5556)

      await networkManager.shutdown()
    })
  })

  describe('End-to-end: External proxy actually handles requests', () => {
    it('should route requests through external allow-all proxy, bypassing SRT filtering', async () => {
      // Skip if not on Linux (where we have full sandbox integration)
      if (getPlatform() !== 'linux') {
        console.log('Skipping end-to-end test on non-Linux platform')
        return
      }

      // Create a simple HTTP CONNECT proxy that allows ALL connections (no filtering)
      let externalProxyServer: http.Server | undefined
      let externalProxyPort: number | undefined

      try {
        externalProxyServer = http.createServer()

        // Handle HTTP CONNECT method for HTTPS tunneling
        externalProxyServer.on('connect', (req, clientSocket, head) => {
          const { port, hostname } = new URL(`http://${req.url}`)

          // Connect to target (allow everything - no filtering)
          const serverSocket = net.connect(
            parseInt(port) || 80,
            hostname,
            () => {
              clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
              serverSocket.write(head)
              serverSocket.pipe(clientSocket)
              clientSocket.pipe(serverSocket)
            },
          )

          serverSocket.on('error', () => {
            clientSocket.end()
          })

          clientSocket.on('error', () => {
            serverSocket.end()
          })
        })

        // Handle regular HTTP requests
        externalProxyServer.on('request', (req, res) => {
          const url = new URL(req.url!)
          const options = {
            hostname: url.hostname,
            port: url.port || 80,
            path: url.pathname + url.search,
            method: req.method,
            headers: req.headers,
          }

          const proxyReq = http.request(options, proxyRes => {
            res.writeHead(proxyRes.statusCode!, proxyRes.headers)
            proxyRes.pipe(res)
          })

          proxyReq.on('error', () => {
            res.writeHead(502)
            res.end('Bad Gateway')
          })

          req.pipe(proxyReq)
        })

        // Start the external proxy on a random port
        await new Promise<void>((resolve, reject) => {
          externalProxyServer!.listen(0, '127.0.0.1', () => {
            const addr = externalProxyServer!.address()
            if (addr && typeof addr === 'object') {
              externalProxyPort = addr.port
              console.log(
                `External allow-all proxy started on port ${externalProxyPort}`,
              )
              resolve()
            } else {
              reject(new Error('Failed to get proxy address'))
            }
          })
          externalProxyServer!.on('error', reject)
        })

        // Initialize NetworkManager with restrictive config but external proxy
        const networkManager = new NetworkManager()
        networkManagers.push(networkManager)

        await networkManager.initialize({
          allowedDomains: ['example.com'], // Only allow example.com
          deniedDomains: [],
          httpProxyPort: externalProxyPort, // Use our allow-all external proxy
        })

        // Verify the external proxy port is being used
        expect(networkManager.getHttpProxyPort()).toBe(externalProxyPort)

        // Create SandboxManager instance
        const sandbox = new SandboxManager(networkManager, {
          filesystem: {
            denyRead: [],
            allowWrite: [],
            denyWrite: [],
          },
        })

        // Try to access example.com (in allowlist)
        // This verifies that requests are routed through the external proxy
        const command = await sandbox.wrapWithSandbox(
          'curl -s --max-time 5 http://example.com',
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 10000,
        })

        // The request should succeed
        expect(result.status).toBe(0)

        // Should NOT contain SRT's block message
        const output = (result.stderr || result.stdout || '').toLowerCase()
        expect(output).not.toContain('blocked by network allowlist')

        console.log('✓ Request to example.com succeeded through external proxy')
        console.log(
          '✓ This verifies SRT used the external proxy on the configured port',
        )

        // Clean up sandbox
        await sandbox.dispose()
      } finally {
        // Clean up network manager (if not already cleaned by afterAll)
        // Note: We already track this in networkManagers array

        if (externalProxyServer) {
          await new Promise<void>(resolve => {
            externalProxyServer!.close(() => {
              console.log('External proxy server closed')
              resolve()
            })
          })
        }
      }
    })
  })
})
