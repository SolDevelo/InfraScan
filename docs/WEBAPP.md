# InfraScan Webapp

InfraScan can run a standalone webapp with a graphical user interface, that allows scanning of publicly available repositories.

## 📦 Installation

Requires Python 3.8+

```bash
git clone <repo-url>
cd InfraScan

# Create virtual environment
python3 -m venv venv
source venv/bin/activate 

# Install Python dependencies
pip install -r requirements.txt

# Install security scanners (optional but recommended)
chmod +x install_scanners.sh
./install_scanners.sh
```

**Configuration**: Copy and edit the `.env` file (see `.env.example`) to choose container scanner:
```bash
# Copy the example file
cp .env.example .env

# Edit to select container scanner: docker-scout (default) or grype
CONTAINER_SCANNER=docker-scout
```

**Note**: The app works without container scanning - it will be skipped if not installed. Docker must be installed for Docker Scout to work.

## Usage

```bash
python3 app.py
```
Open browser at `http://localhost:5000`