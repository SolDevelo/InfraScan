#!/bin/bash
set -e

DEFAULT_TARGETS="3.227.205.188,3.228.157.76,98.94.237.180,35.168.139.127"
DEFAULT_PORTS="T:862,2181,2281,2888,3000,3001,3011,3012,3013,3443,3888,4000,4443,5020,5021,5432,5601,5801,6010,6020,6021,7010,7011,7012,7020,7021,8000,8080,8081,8082,8091,8192,9000,9002,9092,9093,9095,9102,9900,10000,27017,U:862,2181,2281,2888,3000,3001,3011,3012,3013,3443,3888,4000,4443,5020,5021,5432,5601,5801,6010,6020,6021,7010,7011,7012,7020,7021,8000,8080,8081,8082,8091,8192,9000,9002,9092,9093,9095,9102,9900,10000,27017"
TARGETS="${OPENVAS_TARGETS:-$DEFAULT_TARGETS}"
PORT_RANGE="${OPENVAS_PORT_RANGE:-$DEFAULT_PORTS}"

echo "Resolving targets to a single IPv4 each..."
RESOLVED_TARGETS=""
IFS=',' read -ra TARGET_LIST <<< "$TARGETS"
for raw in "${TARGET_LIST[@]}"; do
    t="${raw// /}"
    [ -z "$t" ] && continue
    ip=$(getent ahostsv4 "$t" 2>/dev/null | awk '/STREAM/ {print $1; exit}')
    if [ -z "$ip" ]; then
        ip="$t"
        echo "  $t -> (unresolved, passing through as-is)"
    else
        echo "  $t -> $ip"
    fi
    if [ -z "$RESOLVED_TARGETS" ]; then
        RESOLVED_TARGETS="$ip"
    else
        RESOLVED_TARGETS="${RESOLVED_TARGETS},${ip}"
    fi
done
TARGETS="$RESOLVED_TARGETS"
echo "Final target list: $TARGETS"
OPENVAS_IMAGE="${OPENVAS_IMAGE:-immauss/openvas:latest}"
CONTAINER_NAME="${OPENVAS_CONTAINER:-vpim-openvas}"
GMP_PORT="${OPENVAS_GMP_PORT:-9390}"
GMP_USER="${OPENVAS_USERNAME:-admin}"
GMP_PASSWORD="${OPENVAS_PASSWORD:-admin}"
REPORT_DIR="$(pwd)/openvas-reports"
READY_TIMEOUT_SECONDS="${OPENVAS_READY_TIMEOUT:-3600}"

mkdir -p "$REPORT_DIR"
chmod 777 "$REPORT_DIR"

cleanup() {
    echo "Stopping OpenVAS container..."
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Pulling OpenVAS image: ${OPENVAS_IMAGE}"
docker pull "$OPENVAS_IMAGE"

echo "Starting OpenVAS container (GMP on port ${GMP_PORT})..."
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
docker run -d \
    --name "$CONTAINER_NAME" \
    -p "${GMP_PORT}:9390" \
    -e "USERNAME=${GMP_USER}" \
    -e "PASSWORD=${GMP_PASSWORD}" \
    -e "GMP=9390" \
    "$OPENVAS_IMAGE"

echo "Waiting for OpenVAS to become ready (feed sync may take up to $((READY_TIMEOUT_SECONDS/60)) minutes)..."
DEADLINE=$(( $(date +%s) + READY_TIMEOUT_SECONDS ))
READY_MARKER="container is now ready to use"
LAST_PROGRESS=""
while true; do
    if docker logs "$CONTAINER_NAME" 2>&1 | grep -q "$READY_MARKER"; then
        if timeout 5 bash -c "</dev/tcp/127.0.0.1/${GMP_PORT}" >/dev/null 2>&1; then
            echo "OpenVAS reports ready and GMP is reachable on port ${GMP_PORT}."
            break
        fi
    fi
    if [ "$(date +%s)" -ge "$DEADLINE" ]; then
        echo "ERROR: OpenVAS did not become ready within ${READY_TIMEOUT_SECONDS}s."
        docker logs --tail 200 "$CONTAINER_NAME" || true
        exit 1
    fi
    PROGRESS_LINE=$(docker logs --tail 1 "$CONTAINER_NAME" 2>&1 | tr -d '\r')
    if [ -n "$PROGRESS_LINE" ] && [ "$PROGRESS_LINE" != "$LAST_PROGRESS" ]; then
        echo "  [openvas] $PROGRESS_LINE"
        LAST_PROGRESS="$PROGRESS_LINE"
    fi
    sleep 20
done

echo "Installing LaTeX inside the OpenVAS container for native PDF report generation..."
docker exec "$CONTAINER_NAME" bash -c "apt-get update -qq && apt-get install --no-install-recommends -y texlive-latex-recommended texlive-fonts-recommended >/dev/null"

echo "Running scan against: ${TARGETS}"
python3 "$(dirname "$0")/run_scan.py" \
    --host 127.0.0.1 \
    --port "$GMP_PORT" \
    --username "$GMP_USER" \
    --password "$GMP_PASSWORD" \
    --targets "$TARGETS" \
    --port-range "$PORT_RANGE" \
    --xml-output "${REPORT_DIR}/openvas-report.xml" \
    --pdf-output "${REPORT_DIR}/openvas-report.pdf"

echo "OpenVAS scan finished. Reports saved to ${REPORT_DIR}/"
