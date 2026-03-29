#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MMDB_DIR="${ROOT_DIR}/.dev-data/mmdb"
TMP_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "${TMP_DIR}"
}

trap cleanup EXIT

mkdir -p "${MMDB_DIR}"

download_and_extract() {
  local package_name="$1"
  local source_file="$2"
  local target_file="$3"
  local package_readme_target="$4"

  pushd "${TMP_DIR}" >/dev/null
  local archive_name
  archive_name="$(npm pack --silent "${package_name}")"

  tar -xzf "${archive_name}" "package/${source_file}" -O > "${MMDB_DIR}/${target_file}"
  tar -xzf "${archive_name}" "package/README.md" -O > "${MMDB_DIR}/${package_readme_target}"
  tar -xzf "${archive_name}" "package/GEOLITE2_LICENSE" -O > "${MMDB_DIR}/GEOLITE2_LICENSE"
  tar -xzf "${archive_name}" "package/GEOLITE2_EULA" -O > "${MMDB_DIR}/GEOLITE2_EULA"
  popd >/dev/null
}

download_and_extract \
  "@ip-location-db/geolite2-asn-mmdb" \
  "geolite2-asn.mmdb" \
  "GeoLite2-ASN.mmdb" \
  "GeoLite2-ASN.upstream-README.md"

download_and_extract \
  "@ip-location-db/geolite2-country-mmdb" \
  "geolite2-country.mmdb" \
  "GeoLite2-Country.mmdb" \
  "GeoLite2-Country.upstream-README.md"

cat > "${MMDB_DIR}/SOURCE.txt" <<'EOF'
Source: sapics/ip-location-db
Repository: https://github.com/sapics/ip-location-db
Packages:
- @ip-location-db/geolite2-asn-mmdb
- @ip-location-db/geolite2-country-mmdb

These files were fetched with `npm pack` to avoid running install scripts.
Re-run `make crawler-mmdb-update` to refresh the local development copies.
EOF

echo "Updated local crawler MMDB files in ${MMDB_DIR}"
