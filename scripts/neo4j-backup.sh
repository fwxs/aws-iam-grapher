#!/usr/bin/env bash
# Offline backup of the Neo4j data volume (Neo4j Community has no hot/online backup).
# Stops the container, tars the named data volume out to a timestamped file, restarts.
#
# Usage: scripts/neo4j-backup.sh [-o output_dir] [-s compose_service] [-v volume_name]
#
# Downtime: the neo4j container is stopped for the full duration of the tar copy
# (proportional to graph size; a few seconds for typical dev snapshots).
set -euo pipefail

output_dir="./backups"
service="neo4j"
volume="aws-iam-grapher_neo4j_data"

while getopts "o:s:v:h" opt; do
  case "$opt" in
    o) output_dir="$OPTARG" ;;
    s) service="$OPTARG" ;;
    v) volume="$OPTARG" ;;
    h)
      echo "Usage: $0 [-o output_dir] [-s compose_service] [-v volume_name]"
      exit 0
      ;;
    *)
      exit 1
      ;;
  esac
done

mkdir -p "$output_dir"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
archive="$output_dir/neo4j-backup-${timestamp}.tar.gz"

echo "Stopping '$service' (downtime starts now)..."
docker compose stop "$service"

echo "Archiving volume '$volume' to $archive..."
docker run --rm \
  -v "${volume}:/data:ro" \
  -v "$(cd "$output_dir" && pwd):/backup" \
  alpine:3 \
  tar czf "/backup/$(basename "$archive")" -C /data .

echo "Restarting '$service'..."
docker compose start "$service"

echo "Backup complete: $archive"
