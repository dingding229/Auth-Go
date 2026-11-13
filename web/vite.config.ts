import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import { fileURLToPath } from "node:url";
import { devApiTarget, devRuntimePlugin } from "./scripts/dev-runtime.mjs";

export default defineConfig({
  plugins: [vue(), devRuntimePlugin()],
  server: {
    // The actual Vue route source lives in the server-owned shared manifest.
    fs: { allow: [fileURLToPath(new URL("..", import.meta.url))] },
    proxy: {
      "/api": { target: devApiTarget, changeOrigin: true },
    },
  },
  build: {
    emptyOutDir: true,
    manifest: true,
    // Keep Vite's dependency ordering. Splitting Element Plus / ECharts by
    // maxSize can create cyclic chunks and break production initialization.
    chunkSizeWarningLimit: 1200,
  },
});
