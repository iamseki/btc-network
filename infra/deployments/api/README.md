# API Deployment

Deployment ownership for the public API/crawler host.

This role owns:

- Rust API release artifact under `/opt/btc-network/api/releases/<version>/`
- `/opt/btc-network/api/current` symlink
- `/etc/btc-network/api.env` references
- nginx site config for `api.btcnetwork.info`
- `btc-network-api.service`
- crawler artifact and `btc-network-crawler` service/timer when the crawler runs
  on the API/crawler host

This role does not own:

- PostgreSQL server config
- PostgreSQL backup timers
- database snapshots
- direct database firewall exposure

## Operator Commands

```bash
make infra-aws-api-status API_SSM_INSTANCE_ID=i-...
make infra-aws-crawler-status API_SSM_INSTANCE_ID=i-...
make infra-aws-crawler-timer-status API_SSM_INSTANCE_ID=i-...
make infra-aws-crawler-run API_SSM_INSTANCE_ID=i-...
```

## Rollout Stance

Start with a direct systemd restart while traffic is modest. Move to same-host
blue/green on the API host before adding an API fleet or load balancer.

