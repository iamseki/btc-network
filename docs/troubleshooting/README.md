# Troubleshooting

Runbooks and troubleshooting guides for humans and agents.

Start with the shared template when authoring a new guide, then add concrete issue-focused documents in this folder.

## Available Guides

- [Template](./template.md)
- [Crawler Checkpoint Storage Growth (ClickHouse legacy)](./crawler-checkpoint-storage.md)
- [Crawler Checkpoint Storage Growth (PostgreSQL legacy)](./crawler-checkpoint-storage-postgres.md)

## Notes

- Prefer one guide per distinct failure mode or operational question
- Keep guides short and biased toward scanability
- Prefer `what to check`, `what it means`, and `what to do next`
- Link to generic safety or architecture docs instead of repeating them
- Keep historical runbooks available when they document removed designs that may still matter for branch recovery or legacy analysis
