#!/bin/bash
set -e

# Use the following cron for this command
# 0 */12 * * * cd /path/to/infra-scan && ./renew-cert.sh

docker compose run --rm certbot renew
docker compose exec -T nginx nginx -s reload
