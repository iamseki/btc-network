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
chore: improve dd 01
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

### Add Or Update Design Doc

Adds or updates a design/architecture decision document, often with supporting benchmarks or context.

**Frequency**: ~2 times per month

**Steps**:
1. Create or update a markdown file in docs/design_docs/ (e.g., BNDD-XXXX.md)
2. Optionally add or update benchmark scripts, results, or supporting files in a subdirectory
3. Update docs/README.md or docs/design_docs/README.md for navigation/context

**Files typically involved**:
- `docs/design_docs/BNDD-*.md`
- `docs/design_docs/BNDD-*/benchmark/**`
- `docs/design_docs/README.md`

**Example commit sequence**:
```
Create or update a markdown file in docs/design_docs/ (e.g., BNDD-XXXX.md)
Optionally add or update benchmark scripts, results, or supporting files in a subdirectory
Update docs/README.md or docs/design_docs/README.md for navigation/context
```

### Feature Development Across Desktop And Web

Implements a new feature or improves an existing one, updating both the Rust backend (Tauri/CLI) and the React web frontend, including tests.

**Frequency**: ~4 times per month

**Steps**:
1. Update or add Rust backend logic (apps/desktop/src-tauri/src/commands.rs, models.rs, lib.rs, etc.)
2. Update or add frontend React components/pages (apps/web/src/...)
3. Update or add API client/types (apps/web/src/lib/api/...)
4. Update or add tests for frontend and/or backend (e.g., *.test.tsx, *.test.ts, peer.rs)
5. Update shared types or constants if needed

**Files typically involved**:
- `apps/desktop/src-tauri/src/commands.rs`
- `apps/desktop/src-tauri/src/models.rs`
- `apps/desktop/src-tauri/src/lib.rs`
- `apps/web/src/App.tsx`
- `apps/web/src/pages/*.tsx`
- `apps/web/src/lib/api/*.ts`
- `apps/web/src/lib/api/*.test.ts`
- `apps/web/src/pages/*.test.tsx`
- `crates/btc-network/src/client/peer.rs`

**Example commit sequence**:
```
Update or add Rust backend logic (apps/desktop/src-tauri/src/commands.rs, models.rs, lib.rs, etc.)
Update or add frontend React components/pages (apps/web/src/...)
Update or add API client/types (apps/web/src/lib/api/...)
Update or add tests for frontend and/or backend (e.g., *.test.tsx, *.test.ts, peer.rs)
Update shared types or constants if needed
```

### Add Or Update Frontend Component Or Page With Tests

Adds or updates a React component or page in the web frontend, along with corresponding test files.

**Frequency**: ~3 times per month

**Steps**:
1. Create or update a component/page in apps/web/src/components/ or apps/web/src/pages/
2. Create or update the corresponding test file (*.test.tsx)
3. Update styles or shared UI utilities if needed

**Files typically involved**:
- `apps/web/src/components/**/*.tsx`
- `apps/web/src/pages/*.tsx`
- `apps/web/src/pages/*.test.tsx`

**Example commit sequence**:
```
Create or update a component/page in apps/web/src/components/ or apps/web/src/pages/
Create or update the corresponding test file (*.test.tsx)
Update styles or shared UI utilities if needed
```

### Update Project Documentation And Guidelines

Updates project-level documentation, guidelines, or instructions for contributors and agents.

**Frequency**: ~3 times per month

**Steps**:
1. Edit AGENTS.md, CONTRIBUTING.md, README.md, or docs/frontend-architecture.md
2. Optionally update CLAUDE.md or other agent-specific docs

**Files typically involved**:
- `AGENTS.md`
- `CONTRIBUTING.md`
- `README.md`
- `docs/frontend-architecture.md`
- `CLAUDE.md`

**Example commit sequence**:
```
Edit AGENTS.md, CONTRIBUTING.md, README.md, or docs/frontend-architecture.md
Optionally update CLAUDE.md or other agent-specific docs
```

### Add Or Update Tauri Desktop Capability

Adds or updates a Tauri desktop command/capability, including permissions, schemas, and frontend integration.

**Frequency**: ~2 times per month

**Steps**:
1. Update or add Rust command in apps/desktop/src-tauri/src/commands.rs
2. Update or add permissions TOML in apps/desktop/src-tauri/permissions/autogenerated/
3. Update or add schemas in apps/desktop/src-tauri/gen/schemas/
4. Update capabilities in apps/desktop/src-tauri/capabilities/default.json
5. Update frontend API client/types (apps/web/src/lib/api/...)
6. Update or add frontend UI to use the new capability (apps/web/src/pages/, App.tsx, etc.)
7. Add or update tests for both backend and frontend

**Files typically involved**:
- `apps/desktop/src-tauri/src/commands.rs`
- `apps/desktop/src-tauri/permissions/autogenerated/*.toml`
- `apps/desktop/src-tauri/gen/schemas/*.json`
- `apps/desktop/src-tauri/capabilities/default.json`
- `apps/web/src/lib/api/*.ts`
- `apps/web/src/pages/*.tsx`
- `apps/web/src/App.tsx`

**Example commit sequence**:
```
Update or add Rust command in apps/desktop/src-tauri/src/commands.rs
Update or add permissions TOML in apps/desktop/src-tauri/permissions/autogenerated/
Update or add schemas in apps/desktop/src-tauri/gen/schemas/
Update capabilities in apps/desktop/src-tauri/capabilities/default.json
Update frontend API client/types (apps/web/src/lib/api/...)
Update or add frontend UI to use the new capability (apps/web/src/pages/, App.tsx, etc.)
Add or update tests for both backend and frontend
```

### Refactor Multi App Or Crate

Performs a cross-cutting refactor across multiple Rust apps/crates or frontend/backend, often to improve structure, naming, or observability.

**Frequency**: ~2 times per month

**Steps**:
1. Edit main.rs, lib.rs, or other core files in multiple Rust apps/crates
2. Update Cargo.toml or Cargo.lock as needed
3. Update related frontend files if relevant
4. Update documentation if structure changes

**Files typically involved**:
- `apps/cli/src/main.rs`
- `apps/crawler/src/main.rs`
- `apps/listener/src/main.rs`
- `apps/desktop/src-tauri/src/commands.rs`
- `crates/btc-network/src/**/*.rs`
- `Cargo.toml`
- `Cargo.lock`

**Example commit sequence**:
```
Edit main.rs, lib.rs, or other core files in multiple Rust apps/crates
Update Cargo.toml or Cargo.lock as needed
Update related frontend files if relevant
Update documentation if structure changes
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
