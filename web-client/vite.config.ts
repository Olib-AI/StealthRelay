import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import basicSsl from '@vitejs/plugin-basic-ssl'
import path from 'path'
import type { Plugin } from 'vite'
import { WebSocketServer, WebSocket as NodeWebSocket } from 'ws'

// Dev-only plugin: proxies wss:///ws-proxy/<encoded-target> to the target ws:// relay.
// This lets the HTTPS dev page talk to insecure local relays without mixed-content errors.
function wsProxyPlugin(): Plugin {
  return {
    name: 'ws-relay-proxy',
    configureServer(server) {
      const wss = new WebSocketServer({ noServer: true })

      server.httpServer?.on('upgrade', (req, socket, head) => {
        const prefix = '/ws-proxy/'
        if (!req.url?.startsWith(prefix)) return

        const target = decodeURIComponent(req.url.slice(prefix.length))
        if (!target.startsWith('ws://') && !target.startsWith('wss://')) {
          socket.destroy()
          return
        }

        // Let ws handle the client-side upgrade
        wss.handleUpgrade(req, socket, head, (clientWs) => {
          // Connect to the upstream relay
          const upstream = new NodeWebSocket(target)

          upstream.on('open', () => {
            console.log(`[ws-proxy] connected to ${target}`)
          })

          // Relay messages both directions
          upstream.on('message', (data, isBinary) => {
            if (clientWs.readyState === clientWs.OPEN) {
              clientWs.send(data, { binary: isBinary })
            }
          })

          clientWs.on('message', (data, isBinary) => {
            if (upstream.readyState === upstream.OPEN) {
              upstream.send(data, { binary: isBinary })
            }
          })

          // Clean up on close
          upstream.on('close', () => clientWs.close())
          upstream.on('error', (err) => {
            console.error('[ws-proxy] upstream error:', err.message)
            clientWs.close()
          })
          clientWs.on('close', () => upstream.close())
          clientWs.on('error', () => upstream.close())
        })
      })
    },
  }
}

export default defineConfig(({ command }) => ({
  plugins: [
    react(),
    tailwindcss(),
    // HTTPS for dev only — camera access requires secure context on mobile
    ...(command === 'serve' ? [basicSsl(), wsProxyPlugin()] : []),
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  worker: {
    format: 'es',
  },
  build: {
    target: 'es2023',
    rollupOptions: {
      output: {
        manualChunks(id: string) {
          if (id.includes('@noble/')) return 'crypto';
          if (id.includes('react') || id.includes('zustand')) return 'vendor';
          return undefined;
        },
      },
    },
  },
}))
