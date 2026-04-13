# tsup Build Guidelines — @bymax-one/nest-auth

> **Audience:** AI agents and developers working on this codebase.
> **Stack:** tsup ^8.x, TypeScript 5.8+, ESM + CJS dual output
> **Rule:** Follow these guidelines for all build configuration in this project.

---

## Table of Contents

1. [tsup Configuration](#1-tsup-configuration)
2. [Multi-Entry Point Setup](#2-multi-entry-point-setup)
3. [Dual Format Output](#3-dual-format-output)
4. [TypeScript Declarations](#4-typescript-declarations)
5. [External Dependencies](#5-external-dependencies)
6. [JSX Handling](#6-jsx-handling)
7. [Package.json Exports Map](#7-packagejson-exports-map)
8. [sideEffects and Tree-Shaking](#8-sideeffects-and-tree-shaking)
9. [Build Validation](#9-build-validation)
10. [Anti-Patterns](#10-anti-patterns)
11. [Quick Reference Checklist](#11-quick-reference-checklist)

---

## 1. tsup Configuration

### 1.1 Configuration File Location

The build is configured in `tsup.config.ts` at the project root. Always use the TypeScript configuration file (not `.js` or inline `package.json` config) for full type safety and IDE autocompletion.

```ts
// tsup.config.ts
import { defineConfig } from 'tsup';

export default defineConfig([
  // Server entry (main)
  {
    entry: { 'server/index': 'src/server/index.ts' },
    format: ['esm', 'cjs'],
    dts: true,
    outDir: 'dist',
    outExtension: ({ format }) => ({
      js: format === 'esm' ? '.mjs' : '.cjs',
    }),
    external: [
      /^@nestjs\//,
      'reflect-metadata',
      'class-transformer',
      'class-validator',
      'ioredis',
      'express',
    ],
    target: 'node24',
    clean: true,
    splitting: false,
    treeshake: true,
    sourcemap: false,
  },
  // Shared entry
  {
    entry: { 'shared/index': 'src/shared/index.ts' },
    format: ['esm', 'cjs'],
    dts: true,
    outDir: 'dist',
    outExtension: ({ format }) => ({
      js: format === 'esm' ? '.mjs' : '.cjs',
    }),
    external: [
      'class-transformer',
      'class-validator',
    ],
    target: 'node24',
    clean: false,
    splitting: false,
    treeshake: true,
    sourcemap: false,
  },
  // Client entry
  {
    entry: { 'client/index': 'src/client/index.ts' },
    format: ['esm', 'cjs'],
    dts: true,
    outDir: 'dist',
    outExtension: ({ format }) => ({
      js: format === 'esm' ? '.mjs' : '.cjs',
    }),
    external: [],
    target: 'es2022',
    clean: false,
    splitting: false,
    treeshake: true,
    sourcemap: false,
  },
  // React entry (has JSX)
  {
    entry: { 'react/index': 'src/react/index.ts' },
    format: ['esm', 'cjs'],
    dts: true,
    outDir: 'dist',
    outExtension: ({ format }) => ({
      js: format === 'esm' ? '.mjs' : '.cjs',
    }),
    external: ['react', 'react-dom'],
    target: 'es2022',
    clean: false,
    splitting: false,
    treeshake: true,
    sourcemap: false,
    esbuildOptions(options) {
      options.jsx = 'automatic';
    },
  },
  // Next.js entry
  {
    entry: { 'nextjs/index': 'src/nextjs/index.ts' },
    format: ['esm', 'cjs'],
    dts: true,
    outDir: 'dist',
    outExtension: ({ format }) => ({
      js: format === 'esm' ? '.mjs' : '.cjs',
    }),
    external: ['react', 'react-dom', 'next'],
    target: 'es2022',
    clean: false,
    splitting: false,
    treeshake: true,
    sourcemap: false,
    esbuildOptions(options) {
      options.jsx = 'automatic';
    },
  },
]);
```

### 1.2 Key Configuration Fields

| Field | Value | Purpose |
|---|---|---|
| `format` | `['esm', 'cjs']` | Dual-format output for maximum compatibility |
| `dts` | `true` | Generate `.d.ts` declaration files |
| `outDir` | `'dist'` | All output goes to `dist/` |
| `outExtension` | `.mjs` / `.cjs` | Explicit extensions avoid ambiguity |
| `target` | `'node24'` or `'es2022'` | Match the runtime environment of each entry |
| `clean` | `true` on first entry only | Wipe `dist/` before building, but not between entries |
| `splitting` | `false` | Not needed for library builds (see section 2.4) |
| `treeshake` | `true` | Remove dead code from output bundles |
| `sourcemap` | `false` | Not shipped in the npm package |

### 1.3 Why `defineConfig` Takes an Array

tsup supports passing an array of configuration objects to `defineConfig`. Each object produces an independent build pass. This is the correct approach for this project because each subpath entry has different `external` dependencies and `target` runtimes. Using an array guarantees clean separation between server-side Node.js code and browser/React code.

---

## 2. Multi-Entry Point Setup

### 2.1 The Five Entry Points

This package exposes five subpath entry points, each targeting a distinct runtime or consumer:

| Subpath | Entry Source | Target | Description |
|---|---|---|---|
| `.` (root) | `src/server/index.ts` | `node24` | NestJS guards, decorators, modules |
| `./shared` | `src/shared/index.ts` | `node24` | DTOs, types, constants shared across server and client |
| `./client` | `src/client/index.ts` | `es2022` | Framework-agnostic browser auth client |
| `./react` | `src/react/index.ts` | `es2022` | React hooks and AuthProvider (JSX) |
| `./nextjs` | `src/nextjs/index.ts` | `es2022` | Next.js middleware, server actions, RSC utilities |

### 2.2 Separate Build Passes per Entry

Each entry point is configured as a separate object in the `defineConfig` array. This is intentional and required because:

1. **Different externals.** The server entry externalizes `@nestjs/*` and `ioredis`, while the React entry externalizes `react` and `react-dom`. Combining them into a single entry array with shared externals would either bundle things that should be external or externalize things that should be bundled.

2. **Different targets.** Server code targets `node24` (allowing Node.js-specific syntax), while client/react/nextjs code targets `es2022` (browser-compatible baseline).

3. **JSX transform.** Only the `react` and `nextjs` entries need the JSX automatic transform via `esbuildOptions`.

### 2.3 Entry Key Naming Convention

Use the `{ 'subpath/index': 'src/subpath/index.ts' }` object syntax for `entry` rather than the array syntax. This gives explicit control over the output file path:

```ts
// CORRECT - produces dist/server/index.mjs and dist/server/index.cjs
entry: { 'server/index': 'src/server/index.ts' }

// WRONG - produces dist/index.mjs at the root, losing directory structure
entry: ['src/server/index.ts']
```

### 2.4 Why `splitting: false`

Code splitting creates shared chunks between entry points. For an npm library:

- Consumers import one subpath at a time; shared chunks add unnecessary complexity.
- Shared chunks break the clean `dist/<subpath>/index.mjs` structure.
- Each entry should be a self-contained bundle with only its own code.

Keep `splitting: false` for all entries. If a utility is used by multiple subpaths, it gets duplicated into each bundle. This is acceptable and preferred for library packages because it avoids import resolution issues for consumers.

### 2.5 Shared Code Between Entry Points

Code in `src/shared/` may be imported by `src/server/`, `src/client/`, `src/react/`, and `src/nextjs/`. With `splitting: false`, tsup inlines the shared code into each consuming bundle. This is the correct behavior because:

- Consumers may install only `@bymax-one/nest-auth/react` and never `@bymax-one/nest-auth/shared`.
- Each bundle must be self-contained so it works independently.
- The `./shared` subpath exists for consumers who need the types/DTOs directly, not as an internal shared chunk.

Do NOT try to configure tsup to deduplicate shared code across entry points. Let each bundle inline what it needs.

---

## 3. Dual Format Output

### 3.1 ESM (.mjs) and CJS (.cjs)

This package outputs both ESM and CJS for every entry point:

```
dist/
  server/
    index.mjs     # ESM
    index.cjs     # CJS
    index.d.ts    # Declarations
  shared/
    index.mjs
    index.cjs
    index.d.ts
  client/
    index.mjs
    index.cjs
    index.d.ts
  react/
    index.mjs
    index.cjs
    index.d.ts
  nextjs/
    index.mjs
    index.cjs
    index.d.ts
```

### 3.2 Why Both Formats

- **ESM** is the standard for modern Node.js (v16+), Next.js, Vite, and all modern bundlers.
- **CJS** is still required by legacy tooling, Jest (when not using `--experimental-vm-modules`), older Next.js configurations, and some NestJS setups that use `require()`.

Publishing both ensures this library works in all consumer environments without additional configuration.

### 3.3 Explicit File Extensions via `outExtension`

The `outExtension` callback is mandatory because this package has `"type": "module"` in `package.json`. Without explicit extensions:

- tsup would output `.js` files, which Node.js would interpret as ESM (because of `"type": "module"`).
- CJS output in `.js` files under `"type": "module"` causes `ERR_REQUIRE_ESM` errors.

The `.mjs` / `.cjs` extensions are unambiguous regardless of the `type` field:

```ts
outExtension: ({ format }) => ({
  js: format === 'esm' ? '.mjs' : '.cjs',
}),
```

### 3.4 CJS Interop Considerations

tsup handles CJS interop automatically. However, keep these rules in mind when writing source code:

1. **Always use named exports.** Default exports in CJS require consumers to use `.default`, which is a common source of bugs.

   ```ts
   // CORRECT
   export const AuthGuard = ...;
   export function createAuthModule() { ... }

   // AVOID for library public API
   export default class AuthModule { ... }
   ```

2. **No top-level `await`.** CJS does not support top-level `await`. If any entry point source uses it, the CJS build will fail at runtime.

3. **No `import.meta.url` in shared code.** This is ESM-only. If needed, isolate it behind a runtime check or limit it to ESM-only entry points.

### 3.5 The `"type": "module"` Interaction

Since `package.json` declares `"type": "module"`:

- All `.js` files in the package are treated as ESM by Node.js.
- The `.cjs` extension overrides this, telling Node.js to treat those files as CommonJS.
- The `.mjs` extension explicitly marks files as ESM (redundant with `"type": "module"` but clear and portable).

This is why `.mjs` / `.cjs` extensions are non-negotiable for this project.

---

## 4. TypeScript Declarations

### 4.1 Enabling Declarations

Set `dts: true` on every build configuration object. tsup uses its own TypeScript rollup process (via the `@microsoft/api-extractor` pipeline under the hood in tsup v8) to generate a single `.d.ts` file per entry point.

```ts
{
  entry: { 'server/index': 'src/server/index.ts' },
  dts: true,  // Always true for every entry
  // ...
}
```

### 4.2 Output Structure

Each entry produces a single declaration file alongside its JavaScript outputs:

```
dist/server/index.d.ts    # Types for both .mjs and .cjs consumers
dist/shared/index.d.ts
dist/client/index.d.ts
dist/react/index.d.ts
dist/nextjs/index.d.ts
```

A single `.d.ts` file (not `.d.mts` / `.d.cts`) is sufficient because TypeScript resolves the same declaration file for both `import` and `require` when the `"types"` condition is listed first in the exports map (see section 7).

### 4.3 Declaration-Only Builds

If you ever need to regenerate declarations without rebuilding JavaScript (for debugging type issues), you can use:

```ts
{
  entry: { 'server/index': 'src/server/index.ts' },
  dts: { only: true },
}
```

This is not part of the normal build but is useful for diagnosing type rollup problems.

### 4.4 Common Declaration Pitfalls

1. **Re-exported types from `node_modules`.** If a public API type extends or re-exports a type from a peer dependency (e.g., `@nestjs/common`), the declaration file will reference that package. This is correct behavior --- the consumer already has it as a peer dependency.

2. **Circular imports.** Circular imports between source files can cause tsup's DTS generation to fail silently or produce incomplete declarations. If declarations are missing types, check for import cycles first.

3. **Barrel file discipline.** Each `src/<subpath>/index.ts` barrel file should only re-export public API symbols. Internal utilities should not be exported. tsup rolls up only what is exported from the entry point, so unexported internals are stripped from `.d.ts` output.

### 4.5 `tsconfig.json` Requirements for DTS

tsup uses your project's `tsconfig.json` for type-checking during DTS generation. Ensure these compiler options are set:

```jsonc
{
  "compilerOptions": {
    "declaration": true,           // Required for tsup dts
    "declarationMap": false,       // Not needed; tsup handles mapping
    "emitDeclarationOnly": false,  // tsup handles emit
    "strict": true,                // Recommended for library correctness
    "moduleResolution": "bundler", // Works best with tsup
    "module": "ESNext",            // Source is ESM
    "target": "ES2022",            // Base target; tsup overrides per entry
    "jsx": "react-jsx",            // For .tsx files (react/nextjs entries)
    "esModuleInterop": true,       // CJS interop
    "skipLibCheck": true,          // Faster builds; peer deps may conflict
    "isolatedModules": true,       // Required for esbuild compatibility
  }
}
```

---

## 5. External Dependencies

### 5.1 The Golden Rule

**Every `peerDependency` must be listed as `external` in the tsup config for every entry that imports it.** Bundling a peer dependency into the output creates duplicate instances at runtime, which causes bugs (especially with NestJS dependency injection and React context).

### 5.2 External Map by Entry Point

| Entry | External Packages | Reason |
|---|---|---|
| `server` | `@nestjs/*`, `reflect-metadata`, `class-transformer`, `class-validator`, `ioredis`, `express` | All are peer deps or their transitive deps for the server runtime |
| `shared` | `class-transformer`, `class-validator` | DTOs may use decorators from these packages |
| `client` | (none or minimal) | Browser client should be self-contained |
| `react` | `react`, `react-dom` | React is always a peer dependency |
| `nextjs` | `react`, `react-dom`, `next` | Next.js and React are peer dependencies |

### 5.3 Using Regex Patterns for Externals

For packages with many subpath imports (like `@nestjs/*`), use a regex pattern instead of listing every subpath:

```ts
external: [
  /^@nestjs\//,   // Matches @nestjs/common, @nestjs/core, @nestjs/jwt, etc.
  'reflect-metadata',
  'ioredis',
]
```

This is cleaner than enumerating every `@nestjs/*` subpath and automatically covers any new NestJS package added in the future.

### 5.4 Node.js Built-in Externals

tsup automatically externalizes Node.js built-in modules (e.g., `crypto`, `path`, `fs`). You do NOT need to list them. However, if you import using the `node:` protocol prefix (e.g., `import { createHash } from 'node:crypto'`), tsup handles this correctly in v8.x.

Do not add `node:*` entries to the `external` array --- tsup does this for you.

### 5.5 What Happens If You Forget to Externalize

If a peer dependency is accidentally bundled:

- **NestJS modules:** Dependency injection breaks because the bundled `@nestjs/common` is a different instance from the one in the consumer's `node_modules`. Decorators like `@Injectable()` fail silently.
- **React:** Hooks throw "Invalid hook call" errors because bundled React is a different instance from the consumer's React.
- **Bundle size:** The output grows dramatically and unnecessarily.

If the build output is unexpectedly large (check with `du -sh dist/`), a missing external is the most likely cause.

### 5.6 Verifying Externals in Output

After building, inspect the output to confirm externals are not bundled:

```bash
# Should see require("@nestjs/common") or import from "@nestjs/common"
grep -r "@nestjs/common" dist/server/index.mjs

# Should NOT see the actual NestJS source code inlined
wc -l dist/server/index.mjs  # Should be reasonably small
```

---

## 6. JSX Handling

### 6.1 Which Entries Need JSX

Only the `react` and `nextjs` entry points contain JSX (`.tsx` files). The `server`, `shared`, and `client` entries are pure TypeScript (`.ts`).

### 6.2 Configuring the JSX Transform

Use esbuild's automatic JSX transform (React 17+ / React 19 compatible) via `esbuildOptions`:

```ts
{
  entry: { 'react/index': 'src/react/index.ts' },
  // ...
  esbuildOptions(options) {
    options.jsx = 'automatic';
  },
}
```

The `'automatic'` transform:
- Does NOT require `import React from 'react'` at the top of every `.tsx` file.
- Generates `import { jsx as _jsx } from 'react/jsx-runtime'` calls.
- Is the standard for React 19 and Next.js 16.

### 6.3 Why Not `jsxFactory` / `jsxFragment`

The older `'transform'` mode with explicit `jsxFactory: 'React.createElement'` is deprecated for modern React. Do not use it:

```ts
// WRONG - legacy transform
esbuildOptions(options) {
  options.jsx = 'transform';
  options.jsxFactory = 'React.createElement';
  options.jsxFragment = 'React.Fragment';
}

// CORRECT - automatic transform (React 17+)
esbuildOptions(options) {
  options.jsx = 'automatic';
}
```

### 6.4 Source File Extensions

- Files containing JSX syntax must use the `.tsx` extension.
- The entry barrel file (`src/react/index.ts`) can remain `.ts` if it only re-exports from `.tsx` files.
- tsup resolves `.ts` and `.tsx` extensions automatically; no additional configuration is needed.

### 6.5 Aligning with `tsconfig.json`

The `tsconfig.json` must also specify `"jsx": "react-jsx"` to match the automatic transform. This ensures TypeScript's type checker understands JSX without requiring a React import, and keeps tsup's esbuild behavior aligned with `tsc`.

---

## 7. Package.json Exports Map

### 7.1 The Complete Exports Map

The `"exports"` field in `package.json` is the primary mechanism for subpath resolution in Node.js 12.7+ and all modern bundlers:

```json
{
  "exports": {
    ".": {
      "types": "./dist/server/index.d.ts",
      "import": "./dist/server/index.mjs",
      "require": "./dist/server/index.cjs"
    },
    "./shared": {
      "types": "./dist/shared/index.d.ts",
      "import": "./dist/shared/index.mjs",
      "require": "./dist/shared/index.cjs"
    },
    "./client": {
      "types": "./dist/client/index.d.ts",
      "import": "./dist/client/index.mjs",
      "require": "./dist/client/index.cjs"
    },
    "./react": {
      "types": "./dist/react/index.d.ts",
      "import": "./dist/react/index.mjs",
      "require": "./dist/react/index.cjs"
    },
    "./nextjs": {
      "types": "./dist/nextjs/index.d.ts",
      "import": "./dist/nextjs/index.mjs",
      "require": "./dist/nextjs/index.cjs"
    }
  }
}
```

### 7.2 Field Order Matters

The order of conditions within each export is significant. Node.js and bundlers evaluate conditions top-to-bottom and use the first match:

1. **`"types"` must always be first.** TypeScript resolves types using this condition. If `"import"` comes first, TypeScript may fail to find declarations.
2. **`"import"` before `"require"`.** ESM consumers match `"import"`; CJS consumers match `"require"`.

```json
// CORRECT order
{
  "types": "./dist/server/index.d.ts",
  "import": "./dist/server/index.mjs",
  "require": "./dist/server/index.cjs"
}

// WRONG order - TypeScript cannot resolve types
{
  "import": "./dist/server/index.mjs",
  "require": "./dist/server/index.cjs",
  "types": "./dist/server/index.d.ts"
}
```

### 7.3 `typesVersions` Fallback

The `"typesVersions"` field is a fallback for older TypeScript versions (< 4.7) that do not support the `"types"` condition in `"exports"`:

```json
{
  "typesVersions": {
    "*": {
      "shared": ["./dist/shared/index.d.ts"],
      "client": ["./dist/client/index.d.ts"],
      "react": ["./dist/react/index.d.ts"],
      "nextjs": ["./dist/nextjs/index.d.ts"]
    }
  }
}
```

Notes:
- The root entry (`.`) does not need a `typesVersions` entry because it is resolved via the top-level `"types"` field (if present) or the `"exports"` map.
- The `"*"` key means "all TypeScript versions." This is the standard pattern.
- This field is only for TypeScript IDE resolution. It does not affect runtime module resolution.

### 7.4 Do NOT Add a Top-Level `"main"` or `"module"` Field

With a properly configured `"exports"` map, the legacy `"main"` and `"module"` fields are unnecessary and can cause confusion. Bundlers and Node.js versions that support `"exports"` ignore `"main"` entirely. Only add `"main"` if you need to support Node.js < 12.7, which is not a target for this package (minimum Node.js 24).

### 7.5 The `"files"` Field

The `"files"` array in `package.json` controls what gets published to npm:

```json
{
  "files": ["dist", "LICENSE", "README.md"]
}
```

Only `dist/` is needed for the build output. Never include `src/` in published files for a compiled library.

---

## 8. sideEffects and Tree-Shaking

### 8.1 Why `"sideEffects": false`

The `"sideEffects": false` declaration in `package.json` tells bundlers (webpack, Rollup, esbuild, Vite) that all modules in this package are side-effect-free. This enables aggressive tree-shaking: if a consumer imports only `AuthGuard` from `@bymax-one/nest-auth`, the bundler can safely eliminate all other exports from the bundle.

```json
{
  "sideEffects": false
}
```

### 8.2 What "Side-Effect-Free" Means

A module is side-effect-free if importing it (without using any of its exports) does not change observable program state. Specifically, module-level code must NOT:

- Modify global objects (e.g., `globalThis.X = ...`)
- Register polyfills
- Call `console.log()` or perform I/O at import time
- Mutate imported modules from other packages
- Assign to `module.exports` conditionally based on environment

If any module in the package does have side effects, you must either refactor it or use a granular `"sideEffects"` array:

```json
{
  "sideEffects": ["./dist/server/polyfills.mjs"]
}
```

For this project, `"sideEffects": false` is correct and must be maintained.

### 8.3 Barrel Export Implications

Each `src/<subpath>/index.ts` is a barrel file that re-exports from internal modules. With `"sideEffects": false`, bundlers can eliminate unused re-exports. However:

1. **Do NOT re-export entire namespaces.** `export * from './internal'` can defeat tree-shaking in some bundlers if the internal module has complex side effects or circular references.

   ```ts
   // PREFERRED - explicit named re-exports
   export { AuthGuard } from './guards/auth.guard';
   export { JwtStrategy } from './strategies/jwt.strategy';
   export type { AuthConfig } from './interfaces/auth-config';

   // ACCEPTABLE but less tree-shakeable
   export * from './guards/auth.guard';
   ```

2. **Type-only exports should use `export type`.** This ensures they are completely erased from JavaScript output and never interfere with tree-shaking:

   ```ts
   export type { AuthConfig, JwtPayload, UserSession } from './interfaces';
   ```

### 8.4 tsup's `treeshake` Option

The `treeshake: true` option in tsup config enables Rollup-based tree-shaking within the build itself (not just for downstream consumers). This removes dead code from the bundle output:

```ts
{
  treeshake: true,
}
```

This is a build-time optimization that reduces the size of the published artifacts. It is separate from (and complementary to) the `"sideEffects"` field, which is a hint for consumer-side bundlers.

### 8.5 Verifying Tree-Shaking Works

To verify that downstream tree-shaking works correctly for your package:

1. Create a minimal consumer project.
2. Import a single export from one subpath.
3. Bundle with webpack or Rollup in production mode.
4. Check the output bundle size --- it should include only the imported export and its dependencies, not the entire subpath.

If the entire subpath is included, check for:
- Side effects in module-level code
- Circular imports
- `export *` chains that the bundler cannot statically analyze

---

## 9. Build Validation

### 9.1 Post-Build Directory Structure Check

After running `npm run build`, verify the output matches this exact structure:

```
dist/
  server/
    index.mjs
    index.cjs
    index.d.ts
  shared/
    index.mjs
    index.cjs
    index.d.ts
  client/
    index.mjs
    index.cjs
    index.d.ts
  react/
    index.mjs
    index.cjs
    index.d.ts
  nextjs/
    index.mjs
    index.cjs
    index.d.ts
```

Every subpath must have exactly three files: `.mjs`, `.cjs`, and `.d.ts`. Missing files indicate a build configuration error.

### 9.2 Verifying ESM Output

```bash
# Check that ESM files use import/export syntax
head -20 dist/server/index.mjs
# Should contain: import { ... } from '...' or export { ... }

# Verify it can be imported
node --input-type=module -e "import('@bymax-one/nest-auth').then(m => console.log(Object.keys(m)))"
```

### 9.3 Verifying CJS Output

```bash
# Check that CJS files use require/module.exports
head -20 dist/server/index.cjs
# Should contain: require('...') or exports.X = ... or module.exports

# Verify it can be required
node -e "console.log(Object.keys(require('./dist/server/index.cjs')))"
```

### 9.4 Verifying Declarations

```bash
# Check that .d.ts files exist and export types
head -20 dist/server/index.d.ts
# Should contain: export declare ... or export { ... }

# Quick TypeScript check: ensure tsc can resolve the types
npx tsc --noEmit --module nodenext -e "import type { } from './dist/server/index'"
```

### 9.5 Checking Exports Map Resolution

Use the `resolve-exports` approach to verify Node.js resolves all subpaths correctly:

```bash
# Test each subpath resolution
node -e "
  const { resolve } = require('module');
  const pkg = require('./package.json');
  for (const [key, value] of Object.entries(pkg.exports)) {
    console.log(key, '->', JSON.stringify(value));
  }
"
```

Or use the `publint` tool for comprehensive validation:

```bash
npx publint        # Validates package.json exports, types, and build output
npx attw --pack .  # Validates TypeScript declaration resolution (arethetypeswrong)
```

### 9.6 Pre-Publish Validation Script

The project's `prepublishOnly` script runs the full validation pipeline:

```json
{
  "prepublishOnly": "npm run clean && npm run typecheck && npm run test && npm run build"
}
```

This ensures that types compile, tests pass, and the build succeeds before any publish attempt. Consider adding `publint` and `attw` checks to this pipeline:

```json
{
  "prepublishOnly": "npm run clean && npm run typecheck && npm run test && npm run build && npx publint && npx @arethetypeswrong/cli --pack ."
}
```

### 9.7 Checking Bundle Size

Monitor the output size to catch accidental bundling of externals:

```bash
du -sh dist/server/index.mjs dist/server/index.cjs
du -sh dist/react/index.mjs dist/react/index.cjs
```

Expected sizes for a library like this:
- Server entry: 10-100 KB (decorators, guards, modules --- no bundled dependencies)
- Shared entry: 5-50 KB (DTOs, types, constants)
- Client entry: 5-30 KB (HTTP client, token handling)
- React entry: 5-30 KB (hooks, context provider)
- Next.js entry: 5-30 KB (middleware, server actions)

If any file exceeds 500 KB, a dependency is almost certainly being bundled instead of externalized.

---

## 10. Anti-Patterns

### 10.1 Single Entry with All Subpaths

```ts
// WRONG - single entry array bundles everything together
export default defineConfig({
  entry: [
    'src/server/index.ts',
    'src/shared/index.ts',
    'src/client/index.ts',
    'src/react/index.ts',
    'src/nextjs/index.ts',
  ],
  format: ['esm', 'cjs'],
  external: [/^@nestjs\//, 'react', 'react-dom', 'next'],
});
```

**Why it is wrong:** All entries share the same `external` list and `target`. Server code gets `react` externalized (unnecessary), and React code gets `@nestjs/*` externalized (unnecessary). The `target` must be a compromise between `node24` and `es2022`.

```ts
// CORRECT - separate config per entry (see section 1.1)
export default defineConfig([
  { entry: { 'server/index': 'src/server/index.ts' }, target: 'node24', external: [/^@nestjs\//], ... },
  { entry: { 'react/index': 'src/react/index.ts' }, target: 'es2022', external: ['react'], ... },
  // ...
]);
```

### 10.2 Missing `outExtension`

```ts
// WRONG - outputs .js for both formats
export default defineConfig({
  format: ['esm', 'cjs'],
  // No outExtension
});
```

**Why it is wrong:** With `"type": "module"`, the CJS `.js` files are treated as ESM by Node.js, causing runtime errors. Always use explicit `.mjs` / `.cjs` extensions.

### 10.3 Using `splitting: true` for Library Builds

```ts
// WRONG for a library
export default defineConfig({
  splitting: true,
  format: ['esm', 'cjs'],
});
```

**Why it is wrong:** Splitting creates shared chunks (e.g., `chunk-XXXX.mjs`) that break the expected `dist/<subpath>/index.mjs` structure. Consumers cannot import chunks directly, and it complicates the exports map. Additionally, splitting only works with ESM format --- enabling it alongside CJS causes a build error.

### 10.4 Bundling Peer Dependencies

```ts
// WRONG - missing external for React
{
  entry: { 'react/index': 'src/react/index.ts' },
  external: [],  // React gets bundled!
}
```

**Why it is wrong:** Bundling React causes "invalid hook call" errors and doubles the bundle size. See section 5.5.

### 10.5 `clean: true` on Every Entry in an Array Config

```ts
// WRONG - each entry wipes the previous entry's output
export default defineConfig([
  { entry: { 'server/index': '...' }, clean: true, ... },
  { entry: { 'shared/index': '...' }, clean: true, ... },  // Deletes server output!
  { entry: { 'client/index': '...' }, clean: true, ... },  // Deletes shared output!
]);
```

**Why it is wrong:** tsup builds each config object sequentially. If every entry has `clean: true`, each build wipes the output of the previous build. Only the first entry should have `clean: true`.

```ts
// CORRECT
export default defineConfig([
  { entry: { 'server/index': '...' }, clean: true, ... },   // Cleans dist/
  { entry: { 'shared/index': '...' }, clean: false, ... },  // Keeps server output
  { entry: { 'client/index': '...' }, clean: false, ... },  // Keeps both
  // ...
]);
```

### 10.6 Using `dts: { resolve: true }` with Peer Dependencies

```ts
// WRONG - inlines peer dependency types into your .d.ts
{
  dts: { resolve: true },
}
```

**Why it is wrong:** `resolve: true` tells tsup to inline type declarations from external packages. This breaks TypeScript's type compatibility checking --- the consumer's `@nestjs/common` types would be a different copy from the inlined ones, causing type mismatches.

### 10.7 Outputting to Nested `dist/esm/` and `dist/cjs/` Directories

```ts
// WRONG - separate directories for formats
export default defineConfig([
  { format: ['esm'], outDir: 'dist/esm', ... },
  { format: ['cjs'], outDir: 'dist/cjs', ... },
]);
```

**Why it is wrong:** This doubles the directory structure and complicates the exports map. With explicit `.mjs` / `.cjs` extensions, both formats can coexist in the same directory without conflict.

### 10.8 Forgetting `"types"` First in Exports Conditions

```json
{
  "exports": {
    ".": {
      "import": "./dist/server/index.mjs",
      "require": "./dist/server/index.cjs",
      "types": "./dist/server/index.d.ts"
    }
  }
}
```

**Why it is wrong:** TypeScript reads conditions top-to-bottom. With `"types"` last, TypeScript may resolve the `.mjs` file instead of the `.d.ts` file, causing type resolution failures. Always put `"types"` first.

---

## Quick Reference Checklist

Use this checklist when modifying the build configuration or adding a new entry point:

### Build Configuration (`tsup.config.ts`)

- [ ] Each entry point has its own configuration object in the `defineConfig` array
- [ ] `format` is `['esm', 'cjs']` for every entry
- [ ] `dts` is `true` for every entry
- [ ] `outDir` is `'dist'` for every entry
- [ ] `outExtension` maps ESM to `.mjs` and CJS to `.cjs`
- [ ] `clean: true` is set on the FIRST entry only; all others use `clean: false`
- [ ] `splitting` is `false` for every entry
- [ ] `treeshake` is `true` for every entry
- [ ] Server/shared entries use `target: 'node24'`
- [ ] Client/react/nextjs entries use `target: 'es2022'`
- [ ] React and Next.js entries have `esbuildOptions` with `jsx: 'automatic'`

### External Dependencies

- [ ] Every `peerDependency` used by an entry is listed in that entry's `external`
- [ ] `@nestjs/*` packages use the regex pattern `/^@nestjs\//`
- [ ] `react` and `react-dom` are external for `react` and `nextjs` entries
- [ ] `next` is external for the `nextjs` entry
- [ ] Node.js built-ins are NOT listed (tsup handles them automatically)
- [ ] Build output size is reasonable (no accidental bundling)

### Package.json

- [ ] `"type": "module"` is set
- [ ] `"sideEffects": false` is set
- [ ] `"exports"` map has all five subpaths (`.`, `./shared`, `./client`, `./react`, `./nextjs`)
- [ ] Each export has `"types"` listed FIRST, then `"import"`, then `"require"`
- [ ] `"typesVersions"` includes entries for `shared`, `client`, `react`, `nextjs`
- [ ] `"files"` includes `"dist"` and does NOT include `"src"`

### Post-Build Verification

- [ ] `dist/` contains 5 subdirectories, each with `.mjs`, `.cjs`, and `.d.ts`
- [ ] ESM files contain `import`/`export` statements
- [ ] CJS files contain `require`/`exports` statements
- [ ] `.d.ts` files contain `export declare` statements
- [ ] No peer dependency source code is inlined in the output
- [ ] `npx publint` passes with no errors
- [ ] `npx @arethetypeswrong/cli --pack .` shows no resolution issues

### Adding a New Entry Point

When adding a sixth (or later) subpath entry:

1. Create `src/<name>/index.ts` with public API re-exports
2. Add a new configuration object to the `defineConfig` array in `tsup.config.ts`
3. Set the correct `target` and `external` for the new entry's runtime
4. Set `clean: false` (only the first entry cleans)
5. Add the JSX `esbuildOptions` if the entry contains `.tsx` files
6. Add the subpath to `"exports"` in `package.json` with `types`/`import`/`require`
7. Add the subpath to `"typesVersions"` in `package.json`
8. Run `npm run build` and verify the output structure
9. Run `npx publint` and `npx @arethetypeswrong/cli --pack .` to validate
