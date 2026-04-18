import js from '@eslint/js'
import tsPlugin from '@typescript-eslint/eslint-plugin'
import tsParser from '@typescript-eslint/parser'
import prettierConfig from 'eslint-config-prettier'
import importPlugin from 'eslint-plugin-import'
import prettier from 'eslint-plugin-prettier'
import security from 'eslint-plugin-security'
import globals from 'globals'

export default [
  // Global ignores — only build artifacts and coverage, NOT config files
  {
    ignores: ['node_modules/**', 'dist/**', 'coverage/**']
  },

  // Base recommended config
  js.configs.recommended,

  // TypeScript production files
  {
    files: ['src/**/*.ts'],
    ignores: ['**/*.spec.ts', '**/*.spec.tsx'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        project: './tsconfig.json',
        tsconfigRootDir: import.meta.dirname,
        ecmaVersion: 2022,
        sourceType: 'module'
      },
      globals: {
        ...globals.node
      }
    },
    plugins: {
      '@typescript-eslint': tsPlugin,
      import: importPlugin,
      prettier,
      security
    },
    settings: {
      'import/resolver': {
        typescript: {
          alwaysTryTypes: true,
          project: './tsconfig.json'
        },
        node: {
          extensions: ['.js', '.ts']
        }
      }
    },
    rules: {
      // TypeScript — strict
      'no-undef': 'off',
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': [
        'warn',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_'
        }
      ],
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/explicit-function-return-type': 'error',
      '@typescript-eslint/explicit-module-boundary-types': 'error',
      '@typescript-eslint/no-non-null-assertion': 'error',
      '@typescript-eslint/consistent-type-imports': [
        'error',
        {
          prefer: 'type-imports',
          fixStyle: 'separate-type-imports'
        }
      ],
      '@typescript-eslint/no-empty-function': 'warn',

      // Code quality
      'prefer-const': 'error',
      'no-var': 'error',
      'no-empty': ['error', { allowEmptyCatch: true }],
      'no-console': ['warn', { allow: ['warn', 'error'] }],

      // Security — block dynamic code evaluation
      'no-eval': 'error',
      'no-new-func': 'error',
      'no-implied-eval': 'error',

      // Security — ban bare 'crypto' and external crypto packages (node:crypto only)
      'no-restricted-imports': [
        'error',
        {
          paths: [
            { name: 'crypto', message: "Use 'node:crypto' with the node: prefix instead." },
            { name: 'bcrypt', message: 'Use node:crypto scrypt instead.' },
            { name: 'argon2', message: 'Use node:crypto scrypt instead.' },
            { name: 'uuid', message: 'Use crypto.randomUUID() from node:crypto instead.' },
            { name: 'nanoid', message: 'Use crypto.randomBytes() from node:crypto instead.' },
            { name: 'crypto-js', message: 'Use node:crypto instead.' }
          ]
        }
      ],

      // Security plugin rules
      'security/detect-object-injection': 'warn',
      'security/detect-non-literal-regexp': 'warn',
      'security/detect-possible-timing-attacks': 'error',

      // Import ordering — node: → external → internal → parent/sibling
      'import/order': [
        'error',
        {
          groups: ['builtin', 'external', 'internal', ['parent', 'sibling'], 'index'],
          pathGroups: [
            {
              pattern: 'node:*',
              group: 'builtin',
              position: 'before'
            }
          ],
          pathGroupsExcludedImportTypes: ['builtin'],
          'newlines-between': 'always',
          alphabetize: {
            order: 'asc',
            caseInsensitive: true
          }
        }
      ],
      'import/no-cycle': 'error',
      'import/no-self-import': 'error',

      // Prettier — reads from .prettierrc (no inline options to avoid conflicts)
      'prettier/prettier': 'warn'
    }
  },

  // Config files (tsup.config.ts, jest.config.ts, etc.) — with TS parser, no type-aware project
  {
    files: ['*.config.ts', '*.config.mjs', '*.config.js'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module'
      },
      globals: {
        ...globals.node
      }
    },
    plugins: {
      security
    },
    rules: {
      'no-eval': 'error',
      'no-new-func': 'error',
      'no-restricted-imports': [
        'error',
        {
          paths: [
            { name: 'bcrypt', message: 'Use node:crypto scrypt instead.' },
            { name: 'argon2', message: 'Use node:crypto scrypt instead.' },
            { name: 'uuid', message: 'Use crypto.randomUUID() from node:crypto instead.' },
            { name: 'nanoid', message: 'Use crypto.randomBytes() from node:crypto instead.' },
            { name: 'crypto-js', message: 'Use node:crypto instead.' }
          ]
        }
      ],
      'security/detect-object-injection': 'warn'
    }
  },

  // Test files — TS parser, Jest + Node + browser globals, relaxed rules.
  // Browser globals are included because the client/react/nextjs subpaths
  // exercise DOM types (Response, fetch, Headers, AbortController) under
  // test, and the no-undef rule cannot resolve them otherwise.
  {
    files: ['**/*.spec.ts', '**/*.spec.tsx', '**/*.test.ts'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module'
      },
      globals: {
        ...globals.jest,
        ...globals.node,
        ...globals.browser
      }
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/explicit-module-boundary-types': 'off',
      '@typescript-eslint/no-unused-vars': 'off',
      'no-unused-vars': 'off',
      // TypeScript type names (RequestInit, Response, etc.) are erased at
      // compile time but flagged by the lint-only `no-undef` rule.
      // Disabling it is consistent with the production-files block above.
      'no-undef': 'off',
      'no-console': 'off',
      // Warn (not error) on banned imports in tests — normalizing bad patterns is still undesirable
      'no-restricted-imports': [
        'warn',
        {
          paths: [
            { name: 'crypto', message: "Use 'node:crypto' with the node: prefix instead." },
            { name: 'bcrypt', message: 'Use node:crypto scrypt instead.' },
            { name: 'argon2', message: 'Use node:crypto scrypt instead.' }
          ]
        }
      ]
    }
  },

  // Prettier disables conflicting formatting rules (must be last)
  prettierConfig
]
