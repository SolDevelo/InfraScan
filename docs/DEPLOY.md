# Deployment Guide for AWS EC2

This guide deploys the web app to an AWS EC2 instance with Docker Compose. [docker-compose.yml](../docker-compose.yml) runs three containers: the app (`backend`, gunicorn on port 5000, internal only), `nginx` (ports 80 and 443) and `certbot` (Let's Encrypt certificates).

## 1. Launch an EC2 instance
- **AMI**: Amazon Linux 2023 or Ubuntu 22.04 LTS.
- **Instance type**: t3.small
- **Security group**: allow inbound traffic on:
    - Port 22 (SSH)
    - Port 80 (HTTP; redirects to HTTPS and serves ACME challenges)
    - Port 443 (HTTPS)

## 2. Install Docker and Docker Compose
Connect to the instance over SSH and run:

### Amazon Linux 2023
```bash
sudo dnf update -y
sudo dnf install -y docker
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
# Log out and back in for the group change to take effect
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### Ubuntu
```bash
sudo apt update
sudo apt install -y docker.io docker-compose
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
# Apply the group change without logging out:
newgrp docker
```

## 3. Configure
1. Clone the repository:
   ```bash
   git clone <your-repo-url>
   cd InfraScan
   ```
2. Create `.env` from the sample and fill in the values you need (see [WEBAPP.md](WEBAPP.md#configuration)). Docker Compose passes `DOCKER_HUB_USERNAME`, `DOCKER_HUB_PASSWORD`, `SLACK_WEBHOOK_URL`, `GOOGLE_TAG_ID`, `CONTAINER_SCANNER` and `CLEANUP_SCANNED_IMAGES` to the app:
   ```bash
   cp .env.sample .env
   ```
3. TLS: [nginx/nginx.conf](../nginx/nginx.conf) sets `server_name infrascan.soldevelo.com` and loads the certificate from `certbot/conf/live/infrascan.soldevelo.com/` (mounted at `/etc/letsencrypt`). For another domain, change `server_name` and the certificate paths. nginx does not start until the certificate files exist.

## 4. Start the application
```bash
docker-compose up -d --build
```

The app container mounts the host's Docker socket (`/var/run/docker.sock`) to pull and scan container images, and keeps its data in `./data`, `./scan_results` and `./static`.

## 5. Access the application
Open `https://<your-domain>` in a browser. HTTP requests are redirected to HTTPS.

## 6. Certificate renewal
[renew-cert.sh](../renew-cert.sh) renews the certificates and reloads nginx. Run it from cron, for example twice a day:

```
0 */12 * * * cd /path/to/InfraScan && ./renew-cert.sh
```

The script calls `docker compose` (the Compose v2 plugin), not the standalone `docker-compose` binary installed above.

## 7. Updating the application
To deploy new changes:

1. Connect to the EC2 instance over SSH.
2. Go to the project directory:
   ```bash
   cd InfraScan
   ```
3. Pull the latest changes:
   ```bash
   git pull origin main
   ```
4. Rebuild and restart the containers (`--build` rebuilds the image with the new code):
   ```bash
   docker-compose up -d --build
   ```

---

### Useful commands
- **View logs**: `docker-compose logs -f`
- **Stop the application**: `docker-compose down`
- **Rebuild and restart**: `docker-compose up -d --build`
