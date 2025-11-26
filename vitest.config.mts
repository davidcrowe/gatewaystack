// vitest.config.mts
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    globals: true,
    // tweak these patterns to match where your tests actually live
    include: [
      "tests/**/*.test.ts",
      "apps/**/__tests__/**/*.test.ts",
      "packages/**/__tests__/**/*.test.ts",
    ],
  },
});
