#!/usr/bin/env bash
# Restore a Neo4j data volume from a backup produced by neo4j-backup.sh.
# Stops the container, wipes and repopulates the named data volume, restarts.
#
# Usage: scripts/neo4j-restore.sh -f backup.tar.gz [-s compose_service] [-v volume_name]
#
# WARNING: this replaces all current data in the target volume. Existing
# snapshots not in the backup archive are lost.
set -euo pipefail

archive=""
service="neo4j"
volume="aws-iam-grapher_neo4j_data"

while getopts "f:s:v:h" opt; do
  case "$opt" in
    f) archive="$OPTARG" ;;
    s) service="$OPTARG" ;;
    v) volume="$OPTARG" ;;
    h)
      echo "Usage: $0 -f backup.tar.gz [-s compose_service] [-v volume_name]"
      exit 0
      ;;
    *)
      exit 1
      ;;
  esac
done

if [[ -z "$archive" ]]; then
  echo "Error: -f backup.tar.gz is required" >&2
  exit 1
fi
if [[ ! -f "$archive" ]]; then
  echo "Error: backup file not found: $archive" >&2
  exit 1
fi
archive="$(cd "$(dirname "$archive")" && pwd)/$(basename "$archive")"

echo "Stopping '$service' (downtime starts now)..."
docker compose stop "$service"

echo "Wiping and restoring volume '$volume' from $archive..."
docker run --rm \
  -v "${volume}:/data" \
  -v "$(dirname "$archive"):/backup:ro" \
  alpine:3 \
  sh -c "rm -rf /data/* /data/.[!.]* 2>/dev/null; tar xzf /backup/$(basename "$archive") -C /data"

echo "Restarting '$service'..."
docker compose start "$service"

echo "Restore complete from: $archive"
