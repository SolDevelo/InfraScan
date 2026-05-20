import os
import re
import subprocess
from typing import List, Dict, Any

def find_compose_files(directory_path: str) -> List[str]:
    """Find Docker Compose files in the directory."""
    compose_files = []
    compose_patterns = ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml']
    
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.endswith(('.yml', '.yaml')):
                if file in compose_patterns or file.startswith('docker-compose') or file.startswith('compose'):
                    compose_files.append(os.path.join(root, file))
    
    return compose_files

def find_kubernetes_files(directory_path: str) -> List[str]:
    """Find Kubernetes manifest files in the directory."""
    k8s_files = []
    
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.endswith(('.yml', '.yaml')):
                full_path = os.path.join(root, file)
                try:
                    # Quick check if it's likely a K8s file without full parsing
                    with open(full_path, 'r', encoding='utf-8') as f:
                        # Read first 1024 bytes and check for common K8s indicators
                        head = f.read(1024)
                        if 'apiVersion:' in head and 'kind:' in head:
                            k8s_files.append(full_path)
                except Exception:
                    continue
                    
    return k8s_files

def filter_container_files(files: List[str]) -> tuple[List[str], List[str]]:
    """Filter a list of files into Docker Compose and Kubernetes files."""
    compose_patterns = ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml']
    compose_files = [
        f for f in files 
        if f.endswith(('.yml', '.yaml')) and (
            os.path.basename(f) in compose_patterns 
            or os.path.basename(f).startswith('docker-compose') 
            or os.path.basename(f).startswith('compose')
        )
    ]
    
    potential_k8s = [f for f in files if f.endswith(('.yml', '.yaml')) and f not in compose_files]
    k8s_files = []
    for f in potential_k8s:
        try:
            with open(f, 'r', encoding='utf-8') as fh:
                head = fh.read(1024)
                if 'apiVersion:' in head and 'kind:' in head:
                    k8s_files.append(f)
        except Exception:
            continue
    return compose_files, k8s_files

def extract_images_from_compose(compose_file: str) -> List[str]:
    """Extract Docker image names from a compose file with environment variable expansion."""
    images = []
    
    try:
        import yaml
        with open(compose_file, 'r') as f:
            compose_data = yaml.safe_load(f)
        
        if compose_data and 'services' in compose_data:
            for service_name, service_config in compose_data['services'].items():
                if isinstance(service_config, dict) and 'image' in service_config:
                    image_name = str(service_config['image'])
                    
                    # 1. Expand standard $VAR and ${VAR} using os.path.expandvars
                    expanded_image = os.path.expandvars(image_name)
                    
                    # 2. Expand ${VAR:-default} style strings which os.path.expandvars doesn't handle well
                    # This regex matches ${VAR:-DEFAULT} where VAR is letters/numbers/underscores and DEFAULT is anything but }
                    expanded_image = re.sub(
                        r'\$\{([a-zA-Z_][a-zA-Z0-9_]*):-([^}]*)\}', 
                        lambda m: os.getenv(m.group(1), m.group(2)), 
                        expanded_image
                    )
                    
                    images.append(expanded_image)
    except Exception as e:
        print(f"Warning: Could not parse {compose_file}: {e}")
    
    return images

def extract_images_from_kubernetes(k8s_file: str) -> List[str]:
    """Extract Docker image names from a Kubernetes manifest file."""
    images = []
    
    try:
        import yaml
        with open(k8s_file, 'r') as f:
            # K8s files can have multiple documents separated by ---
            docs = yaml.safe_load_all(f)
            for doc in docs:
                if not doc or not isinstance(doc, dict):
                    continue
                
                # Recursive function to find 'image' keys in any container spec
                def find_images(obj):
                    if isinstance(obj, dict):
                        if 'image' in obj and isinstance(obj['image'], str):
                            images.append(obj['image'])
                        for v in obj.values():
                            find_images(v)
                    elif isinstance(obj, list):
                        for item in obj:
                            find_images(item)
                
                find_images(doc)
    except Exception as e:
        print(f"Warning: Could not parse {k8s_file}: {e}")
    
    return images

def ecr_login(image_name: str) -> bool:
    """
    Authenticate with AWS ECR if the image is an ECR image.
    Format: <account-id>.dkr.ecr.<region>.amazonaws.com/repo:tag
    """
    if ".dkr.ecr." not in image_name or ".amazonaws.com" not in image_name:
        return False
    
    match = re.search(r'([0-9]+\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com)', image_name)
    if not match:
        return False
        
    registry_url = match.group(1)
    region = match.group(2)
    
    print(f"  Detected ECR image, attempting login to {registry_url} in {region}...")
    
    try:
        # Check if 'aws' command is available
        try:
            subprocess.run(["aws", "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("  Warning: AWS CLI not found. Please install 'aws' or pre-authenticate manually.")
            return False
            
        # Perform login using aws ecr get-login-password
        login_cmd = f"aws ecr get-login-password --region {region} | docker login --username AWS --password-stdin {registry_url}"
        result = subprocess.run(login_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"  ✓ Successfully authenticated with ECR: {registry_url}")
            return True
        else:
            print(f"  Warning: ECR authentication failed: {result.stderr.strip()}")
            return False
            
    except Exception as e:
        print(f"  Warning: Error during ECR login: {e}")
        return False

def docker_hub_login() -> bool:
    """Authenticate with Docker Hub if credentials are provided."""
    username = os.getenv('DOCKER_HUB_USERNAME', '').strip()
    password = os.getenv('DOCKER_HUB_PASSWORD', '').strip()
    
    if not username or not password:
        return False
    
    try:
        result = subprocess.run(
            ["docker", "login", "-u", username, "--password-stdin"],
            input=password,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            print("✓ Docker Hub authentication successful")
            return True
        else:
            print(f"Warning: Docker Hub login failed: {result.stderr[:200]}")
            return False
    except Exception as e:
        print(f"Warning: Docker Hub login error: {e}")
        return False

def perform_all_logins(images: List[str]):
    """Perform logins for all required registries based on a list of images."""
    # Docker Hub (from env vars)
    docker_hub_login()
    
    # ECR (dynamic based on images)
    ecr_registries_handled = set()
    for image in images:
        if ".dkr.ecr." in image:
            match = re.search(r'([0-9]+\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com)', image)
            if match:
                registry = match.group(1)
                if registry not in ecr_registries_handled:
                    ecr_login(image)
                    ecr_registries_handled.add(registry)
