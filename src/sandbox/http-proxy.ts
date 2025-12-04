import type { Socket, Server } from 'node:net'
import type { Duplex } from 'node:stream'
import { createServer } from 'node:http'
import { request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { connect } from 'node:net'
import { URL } from 'node:url'
import { logForDebugging } from '../utils/debug.js'

export interface HttpProxyServerOptions {
  filter(
    port: number,
    host: string,
    socket: Socket | Duplex,
  ): Promise<boolean> | boolean
}

export function createHttpProxyServer(options: HttpProxyServerOptions): Server {
  const server = createServer()

  // Handle CONNECT requests for HTTPS traffic
  server.on('connect', async (req, socket) => {
    // Attach error handler immediately to prevent unhandled errors
    socket.on('error', err => {
      logForDebugging(`Client socket error: ${err.message}`, { level: 'error' })
    })

    try {
      const [hostname, portStr] = req.url!.split(':')
      const port = portStr === undefined ? undefined : parseInt(portStr, 10)

      if (!hostname || !port) {
        logForDebugging(`Invalid CONNECT request: ${req.url}`, {
          level: 'error',
        })
        socket.end('HTTP/1.1 400 Bad Request\r\n\r\n')
        return
      }

      const allowed = await options.filter(port, hostname, socket)
      if (!allowed) {
        logForDebugging(`Connection blocked to ${hostname}:${port}`, {
          level: 'error',
        })
        socket.end(
          'HTTP/1.1 403 Forbidden\r\n' +
            'Content-Type: text/plain\r\n' +
            'X-Proxy-Error: blocked-by-allowlist\r\n' +
            '\r\n' +
            'Connection blocked by network allowlist',
        )
        return
      }

      const serverSocket = connect(port, hostname, () => {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
        serverSocket.pipe(socket)
        socket.pipe(serverSocket)
      })

      serverSocket.on('error', err => {
        logForDebugging(`CONNECT tunnel failed: ${err.message}`, {
          level: 'error',
        })
        socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')
      })

      socket.on('error', err => {
        logForDebugging(`Client socket error: ${err.message}`, {
          level: 'error',
        })
        serverSocket.destroy()
      })

      socket.on('end', () => serverSocket.end())
      serverSocket.on('end', () => socket.end())
    } catch (err) {
      logForDebugging(`Error handling CONNECT: ${err}`, { level: 'error' })
      socket.end('HTTP/1.1 500 Internal Server Error\r\n\r\n')
    }
  })

  // Handle WebSocket upgrade requests (for ws://)
  server.on('upgrade', async (req, socket, head) => {
    socket.on('error', err => {
      logForDebugging(`Upgrade client socket error: ${err.message}`, {
        level: 'error',
      })
    })

    logForDebugging(
      `WebSocket upgrade requested: ${req.url ?? ''} host=${req.headers.host ?? ''}`,
    )

    try {
      // Parse URL - for proxied requests, req.url should contain full URL
      // If not, fall back to Host header
      let hostname: string
      let port: number

      try {
        const url = new URL(req.url!)
        hostname = url.hostname
        port = url.port ? parseInt(url.port, 10) : 80
      } catch {
        // If req.url is not a full URL, try to construct it from Host header
        const host = req.headers.host
        if (!host) {
          socket.end('HTTP/1.1 400 Bad Request\r\n\r\n')
          return
        }
        const [hostnamePart, portStr] = host.split(':')
        hostname = hostnamePart
        port = portStr ? parseInt(portStr, 10) : 80
      }

      // Apply domain filtering
      const allowed = await options.filter(port, hostname, socket)
      if (!allowed) {
        logForDebugging(`WebSocket upgrade blocked to ${hostname}:${port}`, {
          level: 'error',
        })
        socket.end(
          'HTTP/1.1 403 Forbidden\r\n' +
            'Content-Type: text/plain\r\n' +
            'X-Proxy-Error: blocked-by-allowlist\r\n' +
            '\r\n' +
            'Connection blocked by network allowlist',
        )
        return
      }

      // Connect to target server
      const serverSocket = connect(port, hostname, () => {
        logForDebugging(`WebSocket proxy connected to ${hostname}:${port}`)
        // Forward the original upgrade request
        // Extract path from req.url (or use / if it's just a host)
        let path = '/'
        try {
          const parsedUrl = new URL(req.url!)
          path = parsedUrl.pathname + parsedUrl.search
        } catch {
          // If it's not a full URL, use req.url directly (it should be a path)
          path = req.url || '/'
        }

        const requestLine = `${req.method} ${path} HTTP/1.1\r\n`
        const headers = Object.entries(req.headers)
          .map(
            ([key, value]) =>
              `${key}: ${Array.isArray(value) ? value.join(', ') : value}`,
          )
          .join('\r\n')

        serverSocket.write(requestLine + headers + '\r\n\r\n')

        serverSocket.once('data', chunk => {
          logForDebugging(`WebSocket target response: ${chunk.toString()}`)
          const forwarded = socket.write(chunk)
          logForDebugging(`Forwarded handshake to client (ok=${forwarded})`)

          serverSocket.pipe(socket)
          socket.pipe(serverSocket)
        })

        if (process.env.SRT_DEBUG) {
          socket.on('data', chunk => {
            logForDebugging(`WebSocket client->proxy ${chunk.toString('hex')}`)
          })
          serverSocket.on('data', chunk => {
            logForDebugging(`WebSocket server->proxy ${chunk.toString('hex')}`)
          })
        }

        // Write any buffered data
        if (head.length > 0) {
          serverSocket.write(head)
        }
      })

      serverSocket.on('error', err => {
        logForDebugging(`WebSocket tunnel failed: ${err.message}`, {
          level: 'error',
        })
        socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')
      })

      socket.on('error', err => {
        logForDebugging(`WebSocket client socket error: ${err.message}`, {
          level: 'error',
        })
        serverSocket.destroy()
      })

      socket.on('end', () => serverSocket.end())
      serverSocket.on('end', () => socket.end())
    } catch (err) {
      logForDebugging(`Error handling WebSocket upgrade: ${err}`, {
        level: 'error',
      })
      socket.end('HTTP/1.1 500 Internal Server Error\r\n\r\n')
    }
  })

  // Handle regular HTTP requests
  server.on('request', async (req, res) => {
    try {
      const url = new URL(req.url!)
      const hostname = url.hostname
      const port = url.port
        ? parseInt(url.port, 10)
        : url.protocol === 'https:'
          ? 443
          : 80

      const allowed = await options.filter(port, hostname, req.socket)
      if (!allowed) {
        logForDebugging(`HTTP request blocked to ${hostname}:${port}`, {
          level: 'error',
        })
        res.writeHead(403, {
          'Content-Type': 'text/plain',
          'X-Proxy-Error': 'blocked-by-allowlist',
        })
        res.end('Connection blocked by network allowlist')
        return
      }

      // Choose http or https module
      const requestFn = url.protocol === 'https:' ? httpsRequest : httpRequest

      const proxyReq = requestFn(
        {
          hostname,
          port,
          path: url.pathname + url.search,
          method: req.method,
          headers: {
            ...req.headers,
            host: url.host,
          },
        },
        proxyRes => {
          res.writeHead(proxyRes.statusCode!, proxyRes.headers)
          proxyRes.pipe(res)
        },
      )

      proxyReq.on('error', err => {
        logForDebugging(`Proxy request failed: ${err.message}`, {
          level: 'error',
        })
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'text/plain' })
          res.end('Bad Gateway')
        }
      })

      req.pipe(proxyReq)
    } catch (err) {
      logForDebugging(`Error handling HTTP request: ${err}`, { level: 'error' })
      res.writeHead(500, { 'Content-Type': 'text/plain' })
      res.end('Internal Server Error')
    }
  })

  return server
}
