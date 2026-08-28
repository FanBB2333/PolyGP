#!/usr/bin/env bash
# Build the polygp image with its git provenance baked in, and tag it so the
# docker tag always matches the git tag:
#
#     scripts/build.sh          # polygp:latest + polygp:<version>, labelled
#     scripts/build.sh --up     # same, then (re)start the container
#
# The version is `git describe`: exactly "v0.1.1" on a tagged commit,
# "v0.1.1-3-g1234567" three commits later, with "-dirty" appended when the
# working tree has uncommitted changes. `docker inspect` shows both labels:
#
#     docker inspect polygp:latest \
#       --format '{{index .Config.Labels "org.opencontainers.image.version"}}'
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(git describe --tags --always --dirty)
REVISION=$(git rev-parse HEAD)

POLYGP_VERSION="$VERSION" POLYGP_REVISION="$REVISION" docker compose build polygp
# Image tags follow the existing 0.1.0 convention: no leading "v".
docker tag polygp:latest "polygp:${VERSION#v}"
echo "built polygp:latest = polygp:${VERSION#v}  (${REVISION})"

if [ "${1:-}" = "--up" ]; then
    docker compose up -d polygp
fi
