# Crawler Local Development

The preferred local crawler path now uses:

- Docker Compose for the shared local PostgreSQL service used by the crawler and API
- host-managed MMDB files under `.dev-data/mmdb/`
- explicit migrations before host-run crawler startup, or the profiled `postgres-migrate` container path

There are now two supported local paths:

- host-run binaries with explicit `make postgres-migrate`
- Docker Compose profiles where `postgres-migrate` runs as a one-shot dependency

## Typical Local Flow

1. Run `make crawler-mmdb-update`.
2. Run `make infra-postgres-up`.
3. Run `make postgres-migrate`.
4. Run `make crawler ARGS="--mmdb-asn-path .dev-data/mmdb/GeoLite2-ASN.mmdb --mmdb-country-path .dev-data/mmdb/GeoLite2-Country.mmdb"`.

## Local Paths

- PostgreSQL data: `.dev-data/postgres/`
- ASN MMDB: `.dev-data/mmdb/GeoLite2-ASN.mmdb`
- country MMDB: `.dev-data/mmdb/GeoLite2-Country.mmdb`

## Download Or Refresh MMDB Files

From the repository root:

```bash
make crawler-mmdb-update
```

That command downloads the current ASN and country MMDB tarballs without running package install scripts and writes the extracted `.mmdb` files under `.dev-data/mmdb/`.

## Start PostgreSQL

From the repository root:

```bash
make infra-postgres-up
```

The local development container uses:

- database URL: `postgresql://btc_network_dev:btc_network_dev@localhost:5432/btc_network`
- user: `btc_network_dev`
- password: `btc_network_dev`
- data root mount: `.dev-data/postgres/` -> `/var/lib/postgresql`
- active PGDATA: `/var/lib/postgresql/18/btc-network`

Stop it with:

```bash
make infra-postgres-down
```

Reset local data with:

```bash
make infra-postgres-reset
```

If your local `.dev-data/postgres/` was created by an older PostgreSQL image or
the old `/var/lib/postgresql/data` mount layout, run `make infra-postgres-reset`
once before bringing the service back up. That clears incompatible dev data and
lets PostgreSQL 18 initialize the new versioned data directory layout.

## Compose Profiles

The repository root `docker-compose.yml` keeps `postgres` unprofiled so it can
act as the shared base service, then layers app services behind Docker
profiles:

- `crawler` profile: `postgres` + `postgres-migrate` + `crawler`
- `api` profile: `postgres` + `postgres-migrate` + `api`
- both profiles together: `postgres` + `postgres-migrate` + `crawler` + `api`

Useful commands from the repository root:

```bash
docker compose up postgres
docker compose --profile crawler up
docker compose --profile crawler --profile api up
docker compose down
```

Equivalent `make` wrappers:

```bash
make infra-postgres-up
make infra-crawler-up
make infra-crawler-api-up
make infra-compose-down
```

The profiled crawler services now build a local multi-stage Docker image from
`apps/crawler/Dockerfile` and run optimized binaries directly instead of
invoking `cargo run` inside a generic Rust toolchain container.

That means the runtime containers:

- do not bind-mount the full repository
- do not compile on every start
- only mount the host-managed MMDB directory read-only when the crawler needs it

The image includes both binaries used by the crawler stack:

- `btc-network-crawler`
- `btc-network-postgres-migrate`

The profiled crawler service also sets default runtime tuning through
environment variables in `compose/crawler.yml`, including:

- `BTC_NETWORK_CRAWLER_MAX_CONCURRENCY=10000`
- `BTC_NETWORK_CRAWLER_MAX_IN_FLIGHT_CONNECTS=512`
- `BTC_NETWORK_CRAWLER_MAX_TRACKED_NODES=500000`
- `BTC_NETWORK_POSTGRES_MAX_CONNECTIONS=16`
- `BTC_NETWORK_CRAWLER_CONNECT_MAX_ATTEMPTS=5`
- `BTC_NETWORK_CRAWLER_CONNECT_RETRY_BACKOFF_MS=250`
- `BTC_NETWORK_CRAWLER_CONNECT_TIMEOUT_SECS=30`
- `BTC_NETWORK_CRAWLER_IO_TIMEOUT_SECS=20`
- `BTC_NETWORK_MMDB_ASN_PATH=/data/mmdb/GeoLite2-ASN.mmdb`
- `BTC_NETWORK_MMDB_COUNTRY_PATH=/data/mmdb/GeoLite2-Country.mmdb`

Compose resource defaults are also set there:

- `BTC_NETWORK_CRAWLER_CPUS=6.0`
- `BTC_NETWORK_CRAWLER_MEM_LIMIT=12g`
- `BTC_NETWORK_CRAWLER_NOFILE_SOFT=1024`
- `BTC_NETWORK_CRAWLER_NOFILE_HARD=1024`

Override any of these by exporting them in your shell or by adding them to a
repository-root `.env` file before running `docker compose`.

High crawler concurrency still needs enough open-file headroom. Each in-flight
peer visit consumes at least one socket file descriptor, and the process also
needs descriptors for PostgreSQL, epoll/event-loop state, MMDB files, and
stdio. For local development, the Compose crawler service now uses a more
conservative `ulimits.nofile=1024` default instead of assuming laptop and local
Docker environments should run at `65536`.

That conservative default is intentional:

- many local shells still report `ulimit -n = 1024`
- a very high container `nofile` does not mean the host, router, or upstream network path can safely support equivalent connect pressure
- the crawler now has a separate `max_in_flight_connects` budget, so local defaults should favor realism over headline maximums

If your environment is stronger and you have validated higher safe values, raise
`BTC_NETWORK_CRAWLER_NOFILE_SOFT` and `BTC_NETWORK_CRAWLER_NOFILE_HARD`
explicitly rather than assuming the repository default should be very high.

The crawler only has a small number of concurrent PostgreSQL writers, so the
Compose default also keeps `BTC_NETWORK_POSTGRES_MAX_CONNECTIONS` modest at
`16`. That preserves file descriptors for peer sockets instead of reserving an
oversized database pool that the crawler does not use.

Worker concurrency and connect concurrency are now separate controls:

- `max_concurrency` bounds total worker throughput across dequeue, handshake, peer discovery, and persistence handoff
- `max_in_flight_connects` bounds only the outbound TCP connect phase, which is the part most likely to saturate local routers or upstream NAT state

That means you can keep a high worker count for overall crawl throughput while
holding active connect pressure to a lower, environment-specific budget.

## Troubleshooting Network Pressure

If the crawler makes your local network unstable, the first thing to determine
is whether the bottleneck is outbound peer-connect pressure or PostgreSQL.

The crawler's periodic progress summary now includes:

- `open_fd_count`
- `tcp_established`
- `tcp_syn_sent`
- `tcp_time_wait`
- `connect_slots_in_use`
- `connectable_tasks_started`
- `connect_retries_started`
- `delayed_retry_backlog`
- `connect_timeout_failures`
- `connect_refused_failures`
- `connect_unreachable_failures`
- `connect_other_failures`
- `postgres_pool_size`
- `postgres_pool_idle`
- `postgres_pool_acquired`

Interpret them like this:

- high `tcp_syn_sent` with low PostgreSQL acquisition means outbound connects are saturating the network path
- high `open_fd_count` means the process has already created many live kernel objects, usually sockets
- low `tcp_established` plus high `tcp_syn_sent` means most connect attempts are stuck before the TCP handshake finishes
- `connect_slots_in_use` near the configured limit means the admission gate is actively capping new outbound connects
- `connectable_tasks_started` counts connect-eligible endpoints that workers started processing; it is broader than raw TCP syscall count
- rising `connect_retries_started` and `delayed_retry_backlog` mean the crawler is deferring retryable connect failures instead of hammering them inline
- failure counters help distinguish timeout-heavy runs from refusal-heavy or unreachable-heavy runs
- high `writer_backlog` with high PostgreSQL acquisition would suggest persistence pressure instead

Useful local checks:

```bash
# host shell open-file limit
ulimit -n

# crawler container open-file limit
docker exec btc-network-crawler sh -lc 'ulimit -n'

# host conntrack table capacity
sysctl -n net.netfilter.nf_conntrack_max

# host ephemeral port range
sysctl -n net.ipv4.ip_local_port_range

# kernel SYN retry budget
sysctl -n net.ipv4.tcp_syn_retries

# optional, if conntrack tooling is installed
conntrack -S
```

Important caveat:

- these commands tell you about the Linux host and container limits
- they do not reveal the effective NAT or conntrack budget of a home router or ISP CPE upstream from the host

That means the host may look healthy while the upstream network path is already
overloaded. If you see very high `tcp_syn_sent`, try lowering connect pressure
first by reducing concurrency, retry count, or connect timeout.

## Peer Reliability Assumptions

Broad Bitcoin P2P crawling naturally encounters many bad or unhelpful peers.

Normal failure modes include:

- TCP endpoints that no longer accept inbound connections
- peers that time out or drop during handshake
- peers that accept the connection but return no useful discovery data
- stale, unroutable, or rate-limited addresses learned from peer gossip

That means low handshake success is not automatically a crawler bug. The more
important question is whether the crawler keeps pressure bounded while sampling
the network effectively. If retries and concurrent connects are too aggressive,
the crawler can overload the local network path even when many failures are
simply normal peer behavior.

## Apply Migrations

Migrations stay explicit. They are not tied to crawler startup.

```bash
make postgres-migrate
```

That uses the preferred local PostgreSQL defaults automatically.

This explicit migration step applies to the host-run workflow above. When you
use the Compose profiles, `postgres-migrate` runs automatically before the
`crawler` or `api` service starts.

## Run The Crawler

```bash
make crawler ARGS="--mmdb-asn-path .dev-data/mmdb/GeoLite2-ASN.mmdb --mmdb-country-path .dev-data/mmdb/GeoLite2-Country.mmdb"
```

Optional PostgreSQL overrides:

- `--postgres-url`
- `--postgres-max-connections`

Optional crawler tuning overrides:

- `--max-concurrency`
- `--max-in-flight-connects`
- `--max-tracked-nodes`
- `--max-runtime-minutes`
- `--idle-timeout-minutes`
- `--checkpoint-interval-secs`
- `--connect-timeout-secs`
- `--connect-max-attempts`
- `--connect-retry-backoff-ms`
- `--io-timeout-secs`
- `--shutdown-grace-period-secs`

The crawler still runs without MMDB files, but enrichment will be unavailable and ASN/country data will not be persisted.

The profiled `crawler` container now defaults to `/data/mmdb/*.mmdb`, backed by
a read-only bind mount from the checked-out `.dev-data/mmdb/` directory. Run
`make crawler-mmdb-update` before starting the Compose crawler stack so those
files exist on the host.

Do not bake MMDB files into a crawler image for this local workflow. They are
host-managed datasets refreshed on a weekly cadence, so bind-mounting the
checked-out repository data is simpler and avoids rebuilding an image just to
pick up fresh GeoLite files.

## Inspect Data

If you have `psql` installed locally:

```bash
psql postgresql://btc_network_dev:btc_network_dev@localhost:5432/btc_network
```

Useful first queries:

```sql
SELECT
    run_id,
    phase,
    checkpointed_at,
    frontier_size,
    scheduled_tasks,
    successful_handshakes,
    failed_tasks,
    persisted_observation_rows
FROM crawler_run_checkpoints
ORDER BY checkpointed_at DESC, checkpoint_sequence DESC
LIMIT 10;
```

```sql
SELECT
    endpoint,
    network_type,
    failure_classification,
    enrichment_status,
    asn,
    country
FROM node_observations
ORDER BY observed_at DESC, observation_id DESC
LIMIT 20;
```

`crawler_run_checkpoints` is crawler runtime history and operator progress history.
The crawler now always starts fresh after a crash or manual restart.
