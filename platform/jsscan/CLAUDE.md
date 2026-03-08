# JSScan Development Guide

## Project Purpose

This project transforms minified/bundled JavaScript files to:

1. **Extract hidden API endpoints** - Discover URLs and API paths embedded in obfuscated code
2. **Extract request patterns** - Identify HTTP request patterns (fetch, XMLHttpRequest, jQuery AJAX, etc.)

The primary use case is security research and penetration testing - analyzing JavaScript bundles to find backend endpoints that may not be documented or visible in the UI.

### Core Capabilities

- **Deobfuscation** (`src/deobfuscate/`) - Essential transforms for endpoint extraction:
  - String merging (`"a" + "b"` → `"ab"`) - Reassembles fragmented URLs
  - Control flow object inlining - Reveals hidden strings in obfuscator dispatch tables
- **Request pattern detection** (`src/requestpattern/`) - Find all HTTP request patterns:
  - `fetch()` calls
  - `XMLHttpRequest` usage
  - jQuery `$.ajax()`, `$.get()`, `$.post()` methods
  - Generic URL patterns in variables and strings
- **Variable tracing** (`src/traceback/`) - Track variable assignments to resolve dynamic values

### Important things:

1. Fallback to `${X}` nếu không lấy được value (number, string, boolean, etc).
2. Khi viết unit tests, TRÁNH viết test theo kiểu "at least" hoặc "greater than" nếu có thể. Luôn phải expect chính xác value đó là gì.
3. **URL validation**: Sử dụng `isURLLike` từ `src/requestpattern/utils.ts` - đây là hàm duy nhất để check URL strings. KHÔNG tạo hàm mới.

## Build Commands

```bash
# Install dependencies (required before building)
bun install --linker isolated

# Development build (watch mode)
bun run dev

# Production build (library)
bun run build

# Build standalone executable (no dependencies required)
bun run build:bin

# Run tests
bun test
```

## Babel Module Imports

**CRITICAL**: This project uses `bun build --compile` to create standalone executables. Babel packages use CommonJS exports which cause ESM/CJS interop issues when bundled.

### DO NOT import directly from @babel/traverse or @babel/generator

```typescript
// WRONG - will fail with bun compile
import traverse from "@babel/traverse";
import generate from "@babel/generator";
```

### ALWAYS use the compatibility wrapper

```typescript
// CORRECT - works with both runtime and bun compile
import { traverse, visitors } from "../ast-utils/babel";
import { babelGenerate } from "../ast-utils/babel";

// For types, import from the wrapper
import type { NodePath, Binding, TraverseOptions } from "../ast-utils/babel";
import type { GeneratorOptions } from "../ast-utils/babel";
```

### Available exports from `ast-utils/babel`

| Export                                                                                          | Description                                        |
| ----------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| `traverse`                                                                                      | The traverse function                              |
| `visitors`                                                                                      | visitors.merge() for combining visitors            |
| `babelGenerate`                                                                                 | The generate function (renamed to avoid conflicts) |
| Types: `Node`, `NodePath`, `Scope`, `Binding`, `TraverseOptions`, `Visitor`, `GeneratorOptions` | Re-exported types                                  |

### Other @babel packages

These packages work fine with direct imports:

- `@babel/parser` - `import { parse } from '@babel/parser'`
- `@babel/types` - `import * as t from '@babel/types'`
- `@babel/template` - `import { statement, expression } from '@babel/template'`

## Project Structure

```
src/
├── ast-utils/          # AST utilities including babel wrapper
│   ├── babel.ts        # ESM/CJS compatibility wrapper
│   ├── transform.ts    # Transform infrastructure
│   ├── generator.ts    # Code generation helpers
│   └── ...
├── deobfuscate/        # Deobfuscation transforms (string merging, control flow)
├── mapping/            # Framework-aware function mapping (Angular, etc.)
├── requestpattern/     # Request pattern detection
├── traceback/          # Variable tracing
├── utils/              # Shared utilities
├── index.ts            # Main entry point
└── cli.ts              # CLI entry point
```

## Creating New Transforms

Example transform structure:

```typescript
import type { NodePath } from "../ast-utils/babel";
import { traverse } from "../ast-utils/babel";
import * as t from "@babel/types";
import type { Transform } from "../ast-utils";

export default {
  name: "my-transform",
  tags: ["safe"], // or ['unsafe']
  visitor() {
    return {
      CallExpression(path: NodePath<t.CallExpression>) {
        // transform logic
      },
    };
  },
} satisfies Transform;
```
