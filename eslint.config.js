import globals from 'globals'
import pluginJs from '@eslint/js'
import tseslint from 'typescript-eslint'
import pluginNode from 'eslint-plugin-n'
import pluginImport from 'eslint-plugin-import'
import prettierRecommended from 'eslint-plugin-prettier/recommended'

export default [
  {
    ignores: ['node_modules/', 'dist/', '**/*.d.ts'],
  },
  {
    files: ['**/*.{js,ts}'],
  },
  { languageOptions: { globals: globals.node } },
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      parserOptions: {
        projectService: {
          allowDefaultProject: ['eslint.config.js'],
        },
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    files: ['test/**/*.ts'],
    languageOptions: {
      parserOptions: {
        project: './tsconfig.test.json',
        projectService: false,
      },
    },
  },
  {
    plugins: {
      'eslint-plugin-n': pluginNode,
      import: pluginImport,
    },
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          args: 'all',
          argsIgnorePattern: '^_',
          caughtErrors: 'all',
          caughtErrorsIgnorePattern: '^_',
          destructuredArrayIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          ignoreRestSiblings: true,
        },
      ],
      '@typescript-eslint/switch-exhaustiveness-check': [
        'error',
        {
          considerDefaultExhaustiveForUnions: true,
        },
      ],
      '@typescript-eslint/await-thenable': 'error',
      '@typescript-eslint/no-floating-promises': [
        'error',
        {
          ignoreVoid: true,
          ignoreIIFE: true,
        },
      ],
      '@typescript-eslint/consistent-type-imports': [
        'error',
        {
          prefer: 'type-imports',
          fixStyle: 'inline-type-imports',
        },
      ],
      eqeqeq: ['error', 'always'],
      'eslint-plugin-n/no-unsupported-features/es-builtins': [
        'error',
        {
          version: '>=18.0.0',
          ignores: [],
        },
      ],
      'eslint-plugin-n/no-unsupported-features/node-builtins': [
        'error',
        {
          version: '>=18.0.0',
          ignores: [],
        },
      ],
      'no-async-promise-executor': 'off',
      'import/no-cycle': [
        'warn',
        {
          maxDepth: 4,
          ignoreExternal: true,
          disableScc: true,
        },
      ],
    },
    settings: {
      'import/parsers': {
        '@typescript-eslint/parser': ['.ts'],
      },
      'import/resolver': {
        typescript: {
          project: './tsconfig.json',
        },
      },
    },
    linterOptions: {
      reportUnusedDisableDirectives: false,
    },
  },
  prettierRecommended,
]
