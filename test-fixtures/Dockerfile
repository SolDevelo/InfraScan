# Test fixture: intentionally misconfigured Dockerfile.
# This file exists solely to produce Checkov CKV_DOCKER_* violations in
# InfraScan CI output (requires --framework dockerfile or --framework all).
# DO NOT build or deploy this image.

# Uses nginx:alpine so the Dockerfile base matches the docker-compose service
# and doesn't independently pull a second large vulnerable image.
FROM nginx:alpine

# CKV_DOCKER_9: ADD used instead of COPY — ADD has implicit URL/tar semantics
ADD nginx.conf /etc/nginx/conf.d/default.conf

# CKV_DOCKER_2: no USER instruction → container runs as root
# CKV_DOCKER_1: no HEALTHCHECK instruction

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
