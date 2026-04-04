# Troubleshooting Template

Use this for short, scan-friendly runbooks.

- Prefer one guide per issue
- Keep only issue-specific context
- Link to generic safety or architecture docs instead of repeating them
- Add separate human/agent notes only when their steps differ

## Template

```md
# Troubleshooting: <issue name>

Short description of the symptom and why this guide exists.

## Use When

- <signal 1>
- <signal 2>

## Quick Checks

1. Run or inspect <check 1>.
2. Run or inspect <check 2>.
3. If needed, inspect <code path, log source, or metric>.

Expected result:

- <what confirms the likely cause>

## Interpretation

- `<observation A>` usually means <cause A>
- `<observation B>` usually means <cause B>
- `<observation C>` usually means <cause C>

## Deeper Checks

### <question this check answers>

```sql
<query or command>
```

Use this when <why this check matters>.

### <second question>

```bash
<command>
```

Use this when <why this check matters>.

## Next Steps

- If the issue is <pattern A>, do <next action A>
- If the issue is <pattern B>, do <next action B>
- If the fix changes behavior or retention, verify <test, query, or invariant>

## References

- <relevant doc>
- <relevant code path>
```
