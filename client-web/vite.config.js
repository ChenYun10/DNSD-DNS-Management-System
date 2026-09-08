import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'

// 开发期默认端口 8082（避开 dnsd 前端 8081 与 apid 8080）。
// /api 由 Vite 反代到 apid，规避 CORS；生产由 nginx 托管静态文件并反代。
export default defineConfig({
  plugins: [vue(), tailwindcss()],
  server: {
    port: 8082,
    host: true,
    proxy: {
      '/api': {
        target: process.env.DNSD_API || 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
    },
  },
})
