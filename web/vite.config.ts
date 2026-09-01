import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  // Local development keeps shared API and Clerk settings in the repository root.
  // Vercel-provided environment variables continue to take precedence at build time.
  envDir: "..",
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8088",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
});
