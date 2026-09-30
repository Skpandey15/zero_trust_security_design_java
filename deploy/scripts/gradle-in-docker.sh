#!/usr/bin/env bash
# Run Gradle in a container on JDK 25 (the toolchain fetches 27), so a laptop
# needs no local JDK: deploy/scripts/gradle-in-docker.sh bff test
set -euo pipefail
cd "$(dirname "$0")/../.."
project="$1"; shift
docker run --rm -v "$PWD:/src" -v zt-gradle-cache:/root/.gradle -w "/src/${project}" \
  bellsoft/liberica-openjdk-debian:25 sh -c "sed -i 's/\r\$//' gradlew && sh ./gradlew --no-daemon $*"
