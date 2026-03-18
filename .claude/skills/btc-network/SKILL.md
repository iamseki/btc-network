---
name: btc-network-conventions
description: Development conventions and patterns for btc-network. Rust project with conventional commits.
---

# Btc Network Conventions

> Generated from [iamseki/btc-network](https://github.com/iamseki/btc-network) on 2026-03-18

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
- `fix`
- `refactor`

### Message Guidelines

- Average message length: ~58 characters
- Keep first line concise and descriptive
- Use imperative mood ("Add feature" not "Added feature")


*Commit message example*

```text
feat: adding support page link, badge and button
```

*Commit message example*

```text
fix: session log responsiveness
```

*Commit message example*

```text
refactor: improve docs routing for agents, turn docs for human more concise
```

*Commit message example*

```text
chore: improve docs organization for humans and agents
```

*Commit message example*

```text
ci: deploy cloudflare pages project name should be more explict
```

*Commit message example*

```text
feat: improve SEO
```

*Commit message example*

```text
chore: include canonical status for design docs
```

*Commit message example*

```text
fix: ci/cd pipeline
```

## Architecture

### Project Structure: Monorepo

This project uses **type-based** module organization.

### Configuration Files

- `.github/workflows/ci.yml`
- `.github/workflows/deploy-web-pages.yml`
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

### File Pattern: `*.test.tsx`

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

### Feature Development

Standard feature implementation workflow

**Frequency**: ~9 times per month

**Steps**:
1. Add feature implementation
2. Add tests for feature
3. Update documentation

**Files typically involved**:
- `apps/web/src/components/ui/*`
- `apps/web/src/*`
- `apps/web/src/app/*`
- `**/*.test.*`
- `**/api/**`

**Example commit sequence**:
```
feat: tooltip on menu item when hover
feat: sidebar should be collapsed by default
chore: improve docs for agents
```

### Refactoring

Code refactoring and cleanup workflow

**Frequency**: ~5 times per month

**Steps**:
1. Ensure tests pass before refactor
2. Refactor code structure
3. Verify tests still pass

**Files typically involved**:
- `src/**/*`

**Example commit sequence**:
```
refactor: include more testing in new pages
chore: remove dead code, improve documentation
refactor: tauri testing, cli simplification
```

### Update Documentation And Readmes

Keeps project documentation, READMEs, and guidelines up to date for both humans and AI agents.

**Frequency**: ~6 times per month

**Steps**:
1. Edit one or more of AGENTS.md, CLAUDE.md, CONTRIBUTING.md, README.md, apps/web/README.md, docs/README.md, docs/frontend-architecture.md, docs/architecture-decisions.md.
2. Commit changes with a message referencing docs, documentation, or improvement for agents/humans.
3. Sometimes update related design docs or deployment docs.

**Files typically involved**:
- `AGENTS.md`
- `CLAUDE.md`
- `CONTRIBUTING.md`
- `README.md`
- `apps/web/README.md`
- `docs/README.md`
- `docs/frontend-architecture.md`
- `docs/architecture-decisions.md`
- `docs/deployment.md`

**Example commit sequence**:
```
Edit one or more of AGENTS.md, CLAUDE.md, CONTRIBUTING.md, README.md, apps/web/README.md, docs/README.md, docs/frontend-architecture.md, docs/architecture-decisions.md.
Commit changes with a message referencing docs, documentation, or improvement for agents/humans.
Sometimes update related design docs or deployment docs.
```

### Web Ui Feature Or Fix With Tests

Implements or fixes a web UI feature, always updating both the implementation and corresponding tests.

**Frequency**: ~5 times per month

**Steps**:
1. Edit or add implementation files in apps/web/src/App.tsx or apps/web/src/pages/*.tsx or apps/web/src/components/*.tsx.
2. Edit or add corresponding test files in apps/web/src/App.test.tsx or apps/web/src/pages/*.test.tsx or apps/web/src/components/*.test.tsx.
3. Commit both implementation and test changes together.

**Files typically involved**:
- `apps/web/src/App.tsx`
- `apps/web/src/App.test.tsx`
- `apps/web/src/pages/*.tsx`
- `apps/web/src/pages/*.test.tsx`
- `apps/web/src/components/*.tsx`
- `apps/web/src/components/*.test.tsx`

**Example commit sequence**:
```
Edit or add implementation files in apps/web/src/App.tsx or apps/web/src/pages/*.tsx or apps/web/src/components/*.tsx.
Edit or add corresponding test files in apps/web/src/App.test.tsx or apps/web/src/pages/*.test.tsx or apps/web/src/components/*.test.tsx.
Commit both implementation and test changes together.
```

### Design Docs Proposal And Update

Creates or updates design decision documents (BNDD-xxxx), including benchmarks, context, and index updates.

**Frequency**: ~4 times per month

**Steps**:
1. Edit or add docs/design_docs/BNDD-xxxx/BNDD-xxxx.md or docs/design_docs/BNDD-xxxx.md.
2. Optionally add benchmarks, results, or related files under docs/design_docs/BNDD-xxxx/benchmark/.
3. Update docs/design_docs/README.md to reflect the new or updated proposal.
4. Sometimes update .codex/config.toml or related config files.

**Files typically involved**:
- `docs/design_docs/BNDD-*/BNDD-*.md`
- `docs/design_docs/BNDD-*.md`
- `docs/design_docs/README.md`
- `docs/design_docs/BNDD-*/benchmark/*`
- `.codex/config.toml`

**Example commit sequence**:
```
Edit or add docs/design_docs/BNDD-xxxx/BNDD-xxxx.md or docs/design_docs/BNDD-xxxx.md.
Optionally add benchmarks, results, or related files under docs/design_docs/BNDD-xxxx/benchmark/.
Update docs/design_docs/README.md to reflect the new or updated proposal.
Sometimes update .codex/config.toml or related config files.
```

### Ci Cd Pipeline Update

Updates CI/CD pipeline configuration, typically for deployment or naming changes, often with README updates.

**Frequency**: ~3 times per month

**Steps**:
1. Edit .github/workflows/deploy-web-pages.yml.
2. Optionally update README.md and/or apps/web/README.md to reflect CI/CD changes.
3. Commit all changes together.

**Files typically involved**:
- `.github/workflows/deploy-web-pages.yml`
- `README.md`
- `apps/web/README.md`

**Example commit sequence**:
```
Edit .github/workflows/deploy-web-pages.yml.
Optionally update README.md and/or apps/web/README.md to reflect CI/CD changes.
Commit all changes together.
```

### Add Or Update Tauri Desktop Command

Adds or updates Tauri desktop commands and related models, often with corresponding web API/types and tests.

**Frequency**: ~3 times per month

**Steps**:
1. Edit apps/desktop/src-tauri/src/commands.rs and/or apps/desktop/src-tauri/src/models.rs.
2. Edit or add related files: apps/web/src/lib/api/tauri-client.ts, apps/web/src/lib/api/types.ts, apps/web/src/lib/api/client.ts.
3. Update or add tests: apps/web/src/lib/api/web-client.test.ts, apps/web/src/App.test.tsx.
4. Optionally update crates/btc-network/src/client/peer.rs for backend logic.

**Files typically involved**:
- `apps/desktop/src-tauri/src/commands.rs`
- `apps/desktop/src-tauri/src/models.rs`
- `apps/web/src/lib/api/tauri-client.ts`
- `apps/web/src/lib/api/types.ts`
- `apps/web/src/lib/api/client.ts`
- `apps/web/src/lib/api/web-client.test.ts`
- `apps/web/src/App.test.tsx`
- `crates/btc-network/src/client/peer.rs`

**Example commit sequence**:
```
Edit apps/desktop/src-tauri/src/commands.rs and/or apps/desktop/src-tauri/src/models.rs.
Edit or add related files: apps/web/src/lib/api/tauri-client.ts, apps/web/src/lib/api/types.ts, apps/web/src/lib/api/client.ts.
Update or add tests: apps/web/src/lib/api/web-client.test.ts, apps/web/src/App.test.tsx.
Optionally update crates/btc-network/src/client/peer.rs for backend logic.
```


## Best Practices

Based on analysis of the codebase, follow these practices:

### Do

- Use conventional commit format (feat:, fix:, etc.)
- Write tests using vitest
- Follow *.test.tsx naming pattern
- Use camelCase for file names
- Prefer named exports

### Don't

- Don't use long relative imports (use aliases)
- Don't write vague commit messages
- Don't skip tests for new features
- Don't deviate from established patterns without discussion

---

*This skill was auto-generated by [ECC Tools](https://ecc.tools). Review and customize as needed for your team.*
