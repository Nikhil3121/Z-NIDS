import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// In development the SPA and the API share one origin through this proxy, so the
// SameSite=Strict refresh cookie works without relaxing CORS or cookie settings.
const API = process.env.ZNIDS_API_ORIGIN ?? "http://127.0.0.1:8010";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
  server: {
    port: 5180,
    strictPort: true,
    proxy: {
      "/api/v1/ws": { target: API.replace(/^http/, "ws"), ws: true },
      "/api": { target: API },
      "/health": API,
      "/ready": API,
    },
  },
  build: {
    sourcemap: false,
    chunkSizeWarningLimit: 700,
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
