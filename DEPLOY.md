# Deployment Guide for AWS EC2

This guide explains how to deploy the application to an AWS EC2 instance using Docker and Nginx.

## 1. Launch an EC2 Instance
- **AMI**: Amazon Linux 2023 or Ubuntu 22.04 LTS.
- **Instance Type**: t3.small
- **Security Group**: Allow inbound traffic on:
    - Port 22 (SSH)
    - Port 80 (HTTP)

## 2. Install Docker and Docker Compose
Connect to your instance via SSH and run:

### For Amazon Linux 2023:
```bash
sudo dnf update -y
sudo dnf install -y docker
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
# Log out and log back in for group changes to take effect
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### For Ubuntu:
```bash
sudo apt update
sudo apt install -y docker.io docker-compose
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
# Apply group changes without logging out:
newgrp docker
```

## 3. Deploy the Application
1. Clone the repository:
   ```bash
   git clone <your-repo-url>
   cd mvp-infra-scan
   ```
2. Start the containers:
   ```bash
   docker-compose up -d --build
   ```

## 4. Access the Application
Open your browser and navigate to the Public IP of your EC2 instance.

## 5. Updating the Application
When you push new changes to your Git repository, follow these steps to update the production server:

1. Connect to your EC2 instance via SSH.
2. Navigate to the project directory:
   ```bash
   cd mvp-infra-scan
   ```
3. Pull the latest changes:
   ```bash
   git pull origin main
   ```
4. Rebuild and restart the containers:
   ```bash
   docker-compose up -d --build
   ```
   *Note: Using `--build` ensures that Docker rebuilds the image with your new code.*

---

### Useful Commands
- **View logs**: `docker-compose logs -f`
- **Stop application**: `docker-compose down`
- **Rebuild and restart**: `docker-compose up -d --build`
