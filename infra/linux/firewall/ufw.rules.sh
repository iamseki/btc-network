#!/usr/bin/env bash
set -euo pipefail

ufw --force reset

ufw default deny incoming
ufw default allow outgoing

host_role="${BTC_NETWORK_HOST_ROLE:-api}"

case "${host_role}" in
    api)
        ufw allow 80/tcp
        ufw allow 443/tcp
        ;;
    postgres)
        if [[ -z "${BTC_NETWORK_API_PRIVATE_CIDR:-}" ]]; then
            echo "BTC_NETWORK_API_PRIVATE_CIDR is required for postgres host firewall rules" >&2
            exit 1
        fi

        ufw allow from "${BTC_NETWORK_API_PRIVATE_CIDR}" to any port 5432 proto tcp
        ;;
    *)
        echo "Unknown BTC_NETWORK_HOST_ROLE: ${host_role}" >&2
        exit 1
        ;;
esac

# Prefer AWS Systems Manager for administration. Do not open SSH broadly by default.
# ufw allow from <trusted-admin-ip>/32 to any port 22 proto tcp

# Never expose PostgreSQL publicly. For the postgres role, 5432 must be limited
# to the API/crawler private CIDR.

ufw --force enable
ufw status verbose
