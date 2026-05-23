import tseslint from "typescript-eslint";

/**
 * Deliberately minimal: type-aware linting is slow, so we run only the two
 * rules that catch the bug class `tsc` can't — promises that are created but
 * never awaited or `.catch()`-ed, and async functions passed where a void
 * callback is expected. A floating promise that rejects can crash the process,
 * so these are errors, not warnings. `void somePromise.catch(() => {})`
 * documents an intentional fire-and-forget and satisfies both rules.
 *
 * Style/formatting is left to `tsc` (`bun run lint`) and review; this config
 * intentionally does not pull in the full recommended rule set.
 */
export default tseslint.config(
  {
    ignores: [
      "node_modules/**",
      "build/**",
      "dist/**",
      "bin/**",
      "src/content/sdk-variants/**",
      "src/content-bundle.json",
    ],
  },
  {
    files: ["src/**/*.ts", "scripts/**/*.ts", "build.ts"],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        project: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: {
      "@typescript-eslint": tseslint.plugin,
    },
    rules: {
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-misused-promises": "error",
    },
  },
);
