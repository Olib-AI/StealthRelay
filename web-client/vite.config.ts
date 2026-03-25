import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import basicSsl from '@vitejs/plugin-basic-ssl'
import path from 'path'

export default defineConfig(({ command }) => ({
  plugins: [
    react(),
    tailwindcss(),
    // HTTPS for dev only — camera access requires secure context on mobile
    ...(command === 'serve' ? [basicSsl()] : []),
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
