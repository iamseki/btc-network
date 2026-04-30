#!/usr/bin/env bash
set -euo pipefail

bin_dir="${BTC_NETWORK_CRAWLER_BIN_DIR:-/opt/btc-network/crawler/current}"
binary="${bin_dir}/btc-network-crawler"

if [[ ! -x "${binary}" ]]; then
    echo "crawler binary not found: ${binary}" >&2
    exit 1
fi

exec "${binary}"

