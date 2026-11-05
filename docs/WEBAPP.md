# InfraScan Web App

InfraScan includes a web app with a graphical interface for scanning publicly available repositories.

## Installation

Requires Python 3.8+ (the Docker image uses Python 3.9).

```bash
git clone <repo-url>
cd InfraScan

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install container scanners (optional): Docker Scout and Grype, into ~/.local/bin
chmod +x install_scanners.sh
./install_scanners.sh
```

`install_scanners.sh` requires Docker to be installed. Checkov is installed by `requirements.txt`.

## Configuration

Settings are read from environment variables or from a `.env` file in the project root. Start from the sample:

```bash
cp .env.sample .env
```

| Variable | Default | Description |
|---|---|---|
| `CONTAINER_SCANNER` | `docker-scout` | Container scanner: `docker-scout` or `grype`. Without Docker Hub credentials, Grype is used when it is installed |
| `DOCKER_HUB_USERNAME` / `DOCKER_HUB_PASSWORD` | _(none)_ | Docker Hub login, required by Docker Scout |
| `CLEANUP_SCANNED_IMAGES` | `true` | Remove images pulled for a Docker Scout scan afterwards (images that existed before the scan are kept) |
| `SLACK_WEBHOOK_URL` | _(none)_ | Slack Incoming Webhook URL for notifications |
| `GITHUB_TOKEN` | _(none)_ | Optional token for GitHub API requests; required to download artifacts of GitHub Actions projects |
| `GOOGLE_TAG_ID` | _(none)_ | Google Analytics tag ID (`G-XXXXXXXXXX`) |
| `SITE_DOMAIN` | `https://infrascan.soldevelo.com` | Domain used in canonical URLs and meta tags |
| `SHOW_GRADES_PUBLICLY` | `True` | Show grades in the public project listings |

Container scanning is optional: if no container scanner is installed, it is skipped. Docker Scout requires Docker.

## Usage

```bash
python3 app.py
```

Then open `http://localhost:5000`. `app.py` starts Flask's development server in debug mode; for a production setup see [DEPLOY.md](DEPLOY.md).

The Docker image also runs the web app (with gunicorn) when started with the `web` command:

```bash
docker run -p 5000:5000 soldevelo/infrascan:latest web
```
