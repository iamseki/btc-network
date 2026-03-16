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
1. Create or edit a markdown file in docs/design_docs/ (e.g. BNDD-xxxx.md)
2. Optionally add supporting files (benchmarks, results, diagrams) in a subfolder
3. Update docs/design_docs/README.md or related index/context files

**Files typically involved**:
- `docs/design_docs/BNDD-*.md`
- `docs/design_docs/BNDD-*/**/*`
- `docs/design_docs/README.md`

**Example commit sequence**:
```
Create or edit a markdown file in docs/design_docs/ (e.g. BNDD-xxxx.md)
Optionally add supporting files (benchmarks, results, diagrams) in a subfolder
Update docs/design_docs/README.md or related index/context files
```

### Feature Development Desktop And Web

Implements a new feature or capability, updating both the Tauri desktop backend (Rust) and the web frontend (React/TS), plus API types and tests.

**Frequency**: ~4 times per month

**Steps**:
1. Implement/modify Rust commands in apps/desktop/src-tauri/src/commands.rs
2. Update or add Rust models or logic (e.g. apps/desktop/src-tauri/src/models.rs, crates/btc-network/src/client/peer.rs)
3. Update or add frontend React components/pages (apps/web/src/pages/*.tsx, apps/web/src/App.tsx)
4. Update or add frontend API client/types (apps/web/src/lib/api/*.ts)
5. Update or add tests for frontend and/or backend (apps/web/src/App.test.tsx, apps/web/src/pages/*.test.tsx, apps/web/src/lib/api/*.test.ts, crates/btc-network/src/client/peer.rs)
6. Update documentation if needed

**Files typically involved**:
- `apps/desktop/src-tauri/src/commands.rs`
- `apps/desktop/src-tauri/src/models.rs`
- `crates/btc-network/src/client/peer.rs`
- `apps/web/src/App.tsx`
- `apps/web/src/pages/*.tsx`
- `apps/web/src/pages/*.test.tsx`
- `apps/web/src/lib/api/*.ts`
- `apps/web/src/lib/api/*.test.ts`

**Example commit sequence**:
```
Implement/modify Rust commands in apps/desktop/src-tauri/src/commands.rs
Update or add Rust models or logic (e.g. apps/desktop/src-tauri/src/models.rs, crates/btc-network/src/client/peer.rs)
Update or add frontend React components/pages (apps/web/src/pages/*.tsx, apps/web/src/App.tsx)
Update or add frontend API client/types (apps/web/src/lib/api/*.ts)
Update or add tests for frontend and/or backend (apps/web/src/App.test.tsx, apps/web/src/pages/*.test.tsx, apps/web/src/lib/api/*.test.ts, crates/btc-network/src/client/peer.rs)
Update documentation if needed
```

### Add Or Update Tauri Capability

Adds or updates a Tauri desktop capability, including permissions, schemas, and frontend integration.

**Frequency**: ~2 times per month

**Steps**:
1. Add or update permission TOML files in apps/desktop/src-tauri/permissions/autogenerated/
2. Update or add schema JSON files in apps/desktop/src-tauri/gen/schemas/
3. Update capabilities in apps/desktop/src-tauri/capabilities/default.json
4. Update Rust commands in apps/desktop/src-tauri/src/commands.rs
5. Update frontend API client/types and UI (apps/web/src/lib/api/*.ts, apps/web/src/pages/*.tsx, apps/web/src/App.tsx)
6. Add or update tests (apps/web/src/lib/api/*.test.ts, apps/web/src/pages/*.test.tsx)

**Files typically involved**:
- `apps/desktop/src-tauri/permissions/autogenerated/*.toml`
- `apps/desktop/src-tauri/gen/schemas/*.json`
- `apps/desktop/src-tauri/capabilities/default.json`
- `apps/desktop/src-tauri/src/commands.rs`
- `apps/web/src/lib/api/*.ts`
- `apps/web/src/pages/*.tsx`
- `apps/web/src/App.tsx`

**Example commit sequence**:
```
Add or update permission TOML files in apps/desktop/src-tauri/permissions/autogenerated/
Update or add schema JSON files in apps/desktop/src-tauri/gen/schemas/
Update capabilities in apps/desktop/src-tauri/capabilities/default.json
Update Rust commands in apps/desktop/src-tauri/src/commands.rs
Update frontend API client/types and UI (apps/web/src/lib/api/*.ts, apps/web/src/pages/*.tsx, apps/web/src/App.tsx)
Add or update tests (apps/web/src/lib/api/*.test.ts, apps/web/src/pages/*.test.tsx)
```

### Ui Component Or Page Enhancement

Adds or refactors a frontend UI component or page, often with tests and style updates.

**Frequency**: ~3 times per month

**Steps**:
1. Add or update React component in apps/web/src/components/ui/ or apps/web/src/pages/
2. Update or add corresponding test file (*.test.tsx)
3. Update shared styles (apps/web/src/styles.css)
4. Update main app file if needed (apps/web/src/App.tsx)

**Files typically involved**:
- `apps/web/src/components/ui/*.tsx`
- `apps/web/src/pages/*.tsx`
- `apps/web/src/pages/*.test.tsx`
- `apps/web/src/styles.css`
- `apps/web/src/App.tsx`

**Example commit sequence**:
```
Add or update React component in apps/web/src/components/ui/ or apps/web/src/pages/
Update or add corresponding test file (*.test.tsx)
Update shared styles (apps/web/src/styles.css)
Update main app file if needed (apps/web/src/App.tsx)
```

### Documentation And Guidelines Update

Updates project documentation, guidelines, or agent instructions.

**Frequency**: ~4 times per month

**Steps**:
1. Edit markdown files in the root or docs/ (README.md, AGENTS.md, CONTRIBUTING.md, docs/frontend-architecture.md, docs/architecture-decisions.md, CLAUDE.md)
2. Optionally update related files in apps/web/README.md or apps/desktop/README.md

**Files typically involved**:
- `README.md`
- `AGENTS.md`
- `CONTRIBUTING.md`
- `docs/frontend-architecture.md`
- `docs/architecture-decisions.md`
- `CLAUDE.md`
- `apps/web/README.md`
- `apps/desktop/README.md`

**Example commit sequence**:
```
Edit markdown files in the root or docs/ (README.md, AGENTS.md, CONTRIBUTING.md, docs/frontend-architecture.md, docs/architecture-decisions.md, CLAUDE.md)
Optionally update related files in apps/web/README.md or apps/desktop/README.md
```

### Refactor Or Restructure Project

Performs codebase-wide refactoring, restructuring, or monorepo improvements.

**Frequency**: ~2 times per month

**Steps**:
1. Edit multiple Cargo.toml, Cargo.lock, Makefile, and/or package.json files
2. Move or rename Rust modules (crates/btc-network/src/*, apps/*/src/main.rs, etc.)
3. Update CI/CD configs or VSCode settings
4. Update documentation to reflect new structure

**Files typically involved**:
- `Cargo.toml`
- `Cargo.lock`
- `Makefile`
- `apps/*/Cargo.toml`
- `apps/*/src/main.rs`
- `crates/btc-network/src/**/*.rs`
- `.github/workflows/*.yml`
- `.vscode/settings.json`
- `README.md`

**Example commit sequence**:
```
Edit multiple Cargo.toml, Cargo.lock, Makefile, and/or package.json files
Move or rename Rust modules (crates/btc-network/src/*, apps/*/src/main.rs, etc.)
Update CI/CD configs or VSCode settings
Update documentation to reflect new structure
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
