---
name: btc-network-conventions
description: Development conventions and patterns for btc-network. Rust project with conventional commits.
---

# Btc Network Conventions

> Generated from [iamseki/btc-network](https://github.com/iamseki/btc-network) on 2026-03-16

## Overview

This skill teaches Claude the development patterns and conventions used in btc-network.

## Tech Stack

- **Primary Language**: Rust
- **Architecture**: type-based module organization
- **Test Location**: mixed
- **Test Framework**: vitest

## When to Use This Skill

Activate this skill when:
- Making changes to this repository
- Adding new features following established patterns
- Writing tests that match project conventions
- Creating commits with proper message format

## Commit Conventions

Follow these commit message conventions based on 8 analyzed commits.

### Commit Style: Conventional Commits

### Prefixes Used

- `feat`
- `chore`
- `refactor`
- `fix`
- `test`

### Message Guidelines

- Average message length: ~60 characters
- Keep first line concise and descriptive
- Use imperative mood ("Add feature" not "Added feature")


*Commit message example*

```text
chore: improve documentation for agents and humans
```

*Commit message example*

```text
feat: adds design decision to use Clickhouse as the analytics database with benchmarking, improve design docs organization
```

*Commit message example*

```text
test: include testing for human services logging and download feature
```

*Commit message example*

```text
refactor: package name and imports
```

*Commit message example*

```text
fix: design doc statements
```

*Commit message example*

```text
feat: add log session in interface
```

*Commit message example*

```text
refactor: logging and observability
```

*Commit message example*

```text
refactor: tauri commands, including config.toml
```

## Architecture

### Project Structure: Monorepo

This project uses **type-based** module organization.

### Configuration Files

- `.github/workflows/ci.yml`
- `apps/desktop/package.json`
- `apps/web/package.json`
- `apps/web/tsconfig.json`
- `apps/web/vite.config.ts`
- `docs/design_docs/BNDD-0002/benchmark/docker-compose.yml`

### Guidelines

- Group code by type (components, services, utils)
- Keep related functionality in the same type folder
- Avoid circular dependencies between type folders

## Code Style

### Language: Rust

### Naming Conventions

| Element | Convention |
|---------|------------|
| Files | camelCase |
| Functions | camelCase |
| Classes | PascalCase |
| Constants | SCREAMING_SNAKE_CASE |

### Import Style: Path Aliases (@/, ~/)

### Export Style: Named Exports


*Preferred import style*

```typescript
// Use path aliases for imports
import { Button } from '@/components/Button'
import { useAuth } from '@/hooks/useAuth'
import { api } from '@/lib/api'
```

*Preferred export style*

```typescript
// Use named exports
export function calculateTotal() { ... }
export const TAX_RATE = 0.1
export interface Order { ... }
```

## Testing

### Test Framework: vitest

### File Pattern: `*.test.ts`

### Test Types

- **Unit tests**: Test individual functions and components in isolation
- **Integration tests**: Test interactions between multiple components/services

### Mocking: vi.mock


*Test file structure*

```typescript
import { describe, it, expect } from 'vitest'

describe('MyFunction', () => {
  it('should return expected result', () => {
    const result = myFunction(input)
    expect(result).toBe(expected)
  })
})
```

## Error Handling

### Error Handling Style: Try-Catch Blocks


*Standard error handling pattern*

```typescript
try {
  const result = await riskyOperation()
  return result
} catch (error) {
  console.error('Operation failed:', error)
  throw new Error('User-friendly message')
}
```

## Common Workflows

These workflows were detected from analyzing commit patterns.

### Database Migration

Database schema changes with migration files

**Frequency**: ~3 times per month

**Steps**:
1. Create migration file
2. Update schema definitions
3. Generate/update types

**Files typically involved**:
- `**/schema.*`
- `**/types.ts`

**Example commit sequence**:
```
feat: tauri desktop app handshake and ping implementation, including its own logo
fix: rust analyzer for tauri-app
fix: button hover behaviour, update tests trigerring to include the tauri and frontend
```

### Feature Development

Standard feature implementation workflow

**Frequency**: ~11 times per month

**Steps**:
1. Add feature implementation
2. Add tests for feature
3. Update documentation

**Files typically involved**:
- `apps/web/src/*`
- `apps/web/src/app/*`
- `apps/web/src/lib/api/*`
- `**/*.test.*`
- `**/api/**`

**Example commit sequence**:
```
feat: include frontend design decisions in documentation
feat: include scaffold and first structure with Tauri and Vite as an interface framework
feat: include shadcn and tailwind integration, updates documentation and instructions on token and context efficiency
```

### Test Driven Development

Test-first development workflow (TDD)

**Frequency**: ~3 times per month

**Steps**:
1. Write failing test
2. Implement code to pass test
3. Refactor if needed

**Files typically involved**:
- `**/*.test.*`
- `**/*.spec.*`
- `src/**/*`

**Example commit sequence**:
```
test: add tests for user validation
feat: implement user validation
```

### Refactoring

Code refactoring and cleanup workflow

**Frequency**: ~6 times per month

**Steps**:
1. Ensure tests pass before refactor
2. Refactor code structure
3. Verify tests still pass

**Files typically involved**:
- `src/**/*`

**Example commit sequence**:
```
refactor: ui should have a retro feeling
feat: tauri desktop app handshake and ping implementation, including its own logo
fix: rust analyzer for tauri-app
```

### Feature Development Frontend And Backend

Implements a new feature or capability, touching both backend (Rust, Tauri) and frontend (React/TypeScript) code, including tests and API integration.

**Frequency**: ~3 times per month

**Steps**:
1. Implement backend logic in Rust (e.g., crates/btc-network/src/client/peer.rs, apps/desktop/src-tauri/src/commands.rs)
2. Expose new command or capability in Tauri (apps/desktop/src-tauri/src/commands.rs, permissions/autogenerated/*.toml, gen/schemas/*.json)
3. Update or create frontend API client/types (apps/web/src/lib/api/*.ts, types.ts)
4. Update or create frontend UI components/pages (apps/web/src/pages/*.tsx, apps/web/src/components/*.tsx, App.tsx)
5. Write or update frontend and backend tests (apps/web/src/*.test.tsx, apps/web/src/lib/api/*.test.ts, crates/btc-network/src/client/peer.rs)
6. Update documentation if needed (README.md, AGENTS.md, docs/frontend-architecture.md)

**Files typically involved**:
- `apps/desktop/src-tauri/src/commands.rs`
- `apps/desktop/src-tauri/permissions/autogenerated/*.toml`
- `apps/desktop/src-tauri/gen/schemas/*.json`
- `crates/btc-network/src/client/peer.rs`
- `apps/web/src/lib/api/*.ts`
- `apps/web/src/lib/api/types.ts`
- `apps/web/src/pages/*.tsx`
- `apps/web/src/components/*.tsx`
- `apps/web/src/App.tsx`
- `apps/web/src/*.test.tsx`
- `apps/web/src/lib/api/*.test.ts`
- `README.md`
- `AGENTS.md`
- `docs/frontend-architecture.md`

**Example commit sequence**:
```
Implement backend logic in Rust (e.g., crates/btc-network/src/client/peer.rs, apps/desktop/src-tauri/src/commands.rs)
Expose new command or capability in Tauri (apps/desktop/src-tauri/src/commands.rs, permissions/autogenerated/*.toml, gen/schemas/*.json)
Update or create frontend API client/types (apps/web/src/lib/api/*.ts, types.ts)
Update or create frontend UI components/pages (apps/web/src/pages/*.tsx, apps/web/src/components/*.tsx, App.tsx)
Write or update frontend and backend tests (apps/web/src/*.test.tsx, apps/web/src/lib/api/*.test.ts, crates/btc-network/src/client/peer.rs)
Update documentation if needed (README.md, AGENTS.md, docs/frontend-architecture.md)
```

### Documentation And Guidelines Update

Improves or updates documentation for users, contributors, or AI agents, often in multiple markdown files and READMEs.

**Frequency**: ~4 times per month

**Steps**:
1. Edit or add content in documentation files (README.md, AGENTS.md, CLAUDE.md, CONTRIBUTING.md, docs/*.md)
2. Sometimes update related project files (apps/web/README.md, docs/frontend-architecture.md, docs/architecture-decisions.md)

**Files typically involved**:
- `README.md`
- `AGENTS.md`
- `CLAUDE.md`
- `CONTRIBUTING.md`
- `docs/*.md`
- `apps/web/README.md`

**Example commit sequence**:
```
Edit or add content in documentation files (README.md, AGENTS.md, CLAUDE.md, CONTRIBUTING.md, docs/*.md)
Sometimes update related project files (apps/web/README.md, docs/frontend-architecture.md, docs/architecture-decisions.md)
```

### Design Docs And Architecture Decisions

Adds or updates design documents, architecture decisions, and related benchmarks or context for major technical choices.

**Frequency**: ~2 times per month

**Steps**:
1. Create or update design doc markdown files (docs/design_docs/BNDD-*.md)
2. Add or update benchmarks, results, or supporting files (docs/design_docs/BNDD-*/benchmark/*)
3. Update architecture overview files (docs/architecture-decisions.md, docs/frontend-architecture.md, docs/design_docs/README.md)

**Files typically involved**:
- `docs/design_docs/BNDD-*.md`
- `docs/design_docs/BNDD-*/benchmark/*`
- `docs/architecture-decisions.md`
- `docs/frontend-architecture.md`
- `docs/design_docs/README.md`

**Example commit sequence**:
```
Create or update design doc markdown files (docs/design_docs/BNDD-*.md)
Add or update benchmarks, results, or supporting files (docs/design_docs/BNDD-*/benchmark/*)
Update architecture overview files (docs/architecture-decisions.md, docs/frontend-architecture.md, docs/design_docs/README.md)
```

### Refactor Multi Package Monorepo

Performs refactoring across multiple packages or crates, often to improve structure, naming, or observability, and may include updates to Cargo.toml, Makefile, or project configuration.

**Frequency**: ~2 times per month

**Steps**:
1. Edit Rust source files across multiple crates/apps (apps/*/src/*.rs, crates/*/src/*.rs)
2. Update Cargo.toml and/or Cargo.lock in affected packages
3. Update Makefile or scripts if build/test process changes
4. Update documentation if structure or usage changes

**Files typically involved**:
- `apps/*/src/*.rs`
- `crates/*/src/*.rs`
- `Cargo.toml`
- `Cargo.lock`
- `Makefile`
- `README.md`

**Example commit sequence**:
```
Edit Rust source files across multiple crates/apps (apps/*/src/*.rs, crates/*/src/*.rs)
Update Cargo.toml and/or Cargo.lock in affected packages
Update Makefile or scripts if build/test process changes
Update documentation if structure or usage changes
```

### Ui Component Or Page Enhancement

Adds or enhances a UI component or page in the frontend, often with associated tests and sometimes updates to styles.

**Frequency**: ~2 times per month

**Steps**:
1. Edit or create component/page file (apps/web/src/components/*.tsx, apps/web/src/pages/*.tsx)
2. Update or add corresponding test file (apps/web/src/pages/*.test.tsx, apps/web/src/components/*.test.tsx)
3. Update styles if needed (apps/web/src/styles.css)
4. Update App.tsx or page registry if navigation changes

**Files typically involved**:
- `apps/web/src/components/*.tsx`
- `apps/web/src/pages/*.tsx`
- `apps/web/src/pages/*.test.tsx`
- `apps/web/src/styles.css`
- `apps/web/src/App.tsx`

**Example commit sequence**:
```
Edit or create component/page file (apps/web/src/components/*.tsx, apps/web/src/pages/*.tsx)
Update or add corresponding test file (apps/web/src/pages/*.test.tsx, apps/web/src/components/*.test.tsx)
Update styles if needed (apps/web/src/styles.css)
Update App.tsx or page registry if navigation changes
```


## Best Practices

Based on analysis of the codebase, follow these practices:

### Do

- Use conventional commit format (feat:, fix:, etc.)
- Write tests using vitest
- Follow *.test.ts naming pattern
- Use camelCase for file names
- Prefer named exports

### Don't

- Don't use long relative imports (use aliases)
- Don't write vague commit messages
- Don't skip tests for new features
- Don't deviate from established patterns without discussion

---

*This skill was auto-generated by [ECC Tools](https://ecc.tools). Review and customize as needed for your team.*
