import { defineConfig } from 'tsup'

export default defineConfig([
  // Server entry (main) — Node.js only
  {
    entry: { 'server/index': 'src/server/index.ts' },
    format: ['esm', 'cjs'],
    dts: true,
    tsconfig: 'tsconfig.build.json',
    outDir: 'dist',
    outExtension: ({ format }) => ({
      js: format === 'esm' ? '.mjs' : '.cjs'
    }),
    external: [
      /^@nestjs\//,
      'reflect-metadata',
      'class-transformer',
      'class-validator',
      'ioredis',
      'express'
    ],
    target: 'node24',
    clean: true,
    splitting: false,
    treeshake: true,
    sourcemap: false
  },
  // Shared entry — types + constants (no peer deps)
  {
    entry: { 'shared/index': 'src/shared/index.ts' },
    format: ['esm', 'cjs'],
    dts: true,
    tsconfig: 'tsconfig.build.json',
    outDir: 'dist',
    outExtension: ({ format }) => ({
      js: format === 'esm' ? '.mjs' : '.cjs'
    }),
    external: ['class-transformer', 'class-validator'],
    target: 'node24',
    clean: false,
    splitting: false,
    treeshake: true,
    sourcemap: false
  },
  // Client entry — fetch-based auth client (depends on shared)
  {
    entry: { 'client/index': 'src/client/index.ts' },
    format: ['esm', 'cjs'],
    dts: true,
    tsconfig: 'tsconfig.build.json',
    outDir: 'dist',
    outExtension: ({ format }) => ({
      js: format === 'esm' ? '.mjs' : '.cjs'
    }),
    external: ['@bymax-one/nest-auth/shared'],
    target: 'es2022',
    clean: false,
    splitting: false,
    treeshake: true,
    sourcemap: false
  },
  // React entry — hooks + AuthProvider (depends on client + shared)
  {
    entry: { 'react/index': 'src/react/index.ts' },
    format: ['esm', 'cjs'],
    dts: true,
    tsconfig: 'tsconfig.build.json',
    outDir: 'dist',
    outExtension: ({ format }) => ({
      js: format === 'esm' ? '.mjs' : '.cjs'
    }),
    external: ['react', 'react-dom', '@bymax-one/nest-auth/shared', '@bymax-one/nest-auth/client'],
    target: 'es2022',
    clean: false,
    splitting: false,
    treeshake: true,
    sourcemap: false,
    esbuildOptions(options) {
      options.jsx = 'automatic'
    }
  },
  // Next.js entry — proxy factory + route handlers (depends on react + client + shared)
  {
    entry: { 'nextjs/index': 'src/nextjs/index.ts' },
    format: ['esm', 'cjs'],
    dts: true,
    tsconfig: 'tsconfig.build.json',
    outDir: 'dist',
    outExtension: ({ format }) => ({
      js: format === 'esm' ? '.mjs' : '.cjs'
    }),
    external: [
      'react',
      'react-dom',
      'next',
      '@bymax-one/nest-auth/shared',
      '@bymax-one/nest-auth/client',
      '@bymax-one/nest-auth/react'
    ],
    target: 'es2022',
    clean: false,
    splitting: false,
    treeshake: true,
    sourcemap: false,
    esbuildOptions(options) {
      options.jsx = 'automatic'
    }
  }
])
