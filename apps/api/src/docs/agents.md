# btc-network Agent Guide

Use this guide when you are an AI agent or automation client calling the btc-network public API.

OpenAPI remains the source of truth for exact endpoints, schemas, parameters, status codes, and error bodies:

```text
GET /api/openapi.json
```

Do not infer fields from this guide. Use OpenAPI for contract details.

## Start Here

1. Call `GET /api/v1/network/historical/runs?limit=1` first.
   This finds the newest crawler run cheaply, even when it is still crawling.
2. Call `GET /api/v1/network/historical/runs/{run_id}` only when you need run detail, checkpoints, failure counts, or network outcomes for a specific run.
3. Add `phase=any` or a comma-separated `phase=finished,crawling` filter to last-run distribution endpoints when a live view needs the newest matching run instead of only the latest finished run.
4. Use last-run distribution endpoints without `phase` for compact analytics pinned to the latest finished run:
   - `GET /api/v1/network/last-run/asns?limit=10`
   - `GET /api/v1/network/last-run/asn-organizations?limit=10`
   - `GET /api/v1/network/last-run/countries?limit=10`
   - `GET /api/v1/network/last-run/network-types?limit=10`
   - `GET /api/v1/network/last-run/protocol-versions?limit=10`
   - `GET /api/v1/network/last-run/services?limit=10`
   - `GET /api/v1/network/last-run/start-heights?limit=10`
   - `GET /api/v1/network/last-run/user-agents?limit=10`
5. Use `GET /api/v1/network/historical/asns?start=<RFC3339>&end=<RFC3339>&limit=10` only when a bounded historical ASN window is needed.
6. Use `GET /api/nodes/status` for curated DNS seeder and public endpoint health.

## Cheap Workflow

For most summaries:

1. Fetch latest run with `limit=1`.
2. Fetch only the distribution endpoints needed for the question.
3. Fetch run detail by `run_id` only for drill-down analysis.
4. Fetch verified nodes only when endpoint-level inventory is required.

Prefer compact distribution endpoints over broad node inventory reads.

## Pagination And Limits

Most compact endpoints use bounded `limit` query parameters only.

Start with low limits such as `5`, `10`, or `20`. Increase only when the task needs more rows.

Use `/api/openapi.json` for endpoint-specific defaults and maximums. Do not guess them.

Use `pageToken` only on row-level inventory scans:

```text
GET /api/v1/network/last-run/nodes?limit=1000
```

Follow `nextPageToken` only when endpoint-level inventory is required. Do not auto-scan all pages for summaries.

Use explicit `start` and `end` bounds on historical aggregate endpoints. Keep windows small; the current maximum historical ASN window is 31 days.

## Caching

Cache these aggressively until deployment changes:

- `GET /agents.md`
- `GET /api/openapi.json`

Cache historical run detail by `run_id`; finished runs are stable historical snapshots.

Cache latest-run and last-run distribution responses briefly. Refresh them only after `GET /api/v1/network/historical/runs?limit=1` shows a newer `runId` or newer checkpoint time.

Treat `GET /api/nodes/status` as short-lived status data.

## Avoid

- Do not use frontend pages as API contracts.
- Do not scrape Scalar docs. Use `/api/openapi.json`.
- Do not guess fields not present in OpenAPI.
- Do not call desktop-only single-peer workflows from browser or public API integrations.
- Do not poll multiple distribution endpoints faster than the crawler snapshot cadence.

## When To Use OpenAPI

Use `GET /api/openapi.json` whenever you need:

- full request and response schemas
- query parameter defaults and maximums
- status codes
- error response shape
- exact endpoint paths

This guide tells you how to behave. OpenAPI tells you the exact contract.
