import { defineConfig } from "vitest/config";
import vue from "@vitejs/plugin-vue";
export default defineConfig({
  plugins: [vue()],
  test: {
    environment: "happy-dom",
    include: ["tests/**/*.test.ts"],
    clearMocks: true,
    testTimeout: 20000,
    // Whole Element Plus page suites share a 2 GiB validation container.
    // Bound file workers instead of extending individual test deadlines.
    maxWorkers: 1,
  },
});
