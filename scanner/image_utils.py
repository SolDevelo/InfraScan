import json
import os
import re
import subprocess
from typing import List, Dict, Any, Optional

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

def _image_line_loader():
    """A yaml.SafeLoader subclass that also records the source line of each
    mapping's 'image:' key, keyed by id(mapping) -- lets callers recover
    "which line declared this image" without a second, line-aware parse.
    """
    import yaml

    image_lines: Dict[int, int] = {}  # id(mapping) -> 1-indexed line of its 'image' key

    class _Loader(yaml.SafeLoader):
        pass

    def _construct_mapping(loader, node, deep=False):
        mapping = yaml.SafeLoader.construct_mapping(loader, node, deep=deep)
        for key_node, _value_node in node.value:
            if getattr(key_node, 'value', None) == 'image':
                image_lines[id(mapping)] = key_node.start_mark.line + 1
        return mapping

    _Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)
    return _Loader, image_lines

DEFAULT_IMAGE_SCAN_TIMEOUT = 300
DEFAULT_ENV_FILES = ('.env', '.env.example', '.env.sample')
_env_file_cache: Dict[str, Dict[str, str]] = {}


def image_scan_timeout() -> int:
    """Per-image scan timeout in seconds: CONTAINER_SCAN_TIMEOUT, default 300.

    Covers the pull *and* the analysis -- the latter dominates for large
    images (e.g. grafana/grafana: ~40s pull, ~3 min in syft's binary
    cataloger), so a tight limit throws away work that was nearly done.
    """
    raw = os.getenv('CONTAINER_SCAN_TIMEOUT', '').strip()
    if not raw:
        return DEFAULT_IMAGE_SCAN_TIMEOUT
    try:
        value = int(raw)
        if value > 0:
            return value
    except ValueError:
        pass
    print(f"[warn] Ignoring CONTAINER_SCAN_TIMEOUT={raw!r}: not a positive number of seconds "
          f"-- using {DEFAULT_IMAGE_SCAN_TIMEOUT}")
    return DEFAULT_IMAGE_SCAN_TIMEOUT


def compose_env_files() -> List[str]:
    """Env files used to expand compose image variables, highest priority
    first: CONTAINER_ENV_FILES (comma-separated), default .env,.env.example,
    .env.sample. A bare name is looked for next to each compose file and in
    its parent directories; an entry with a '/' is a path relative to the
    scanned directory, used for every compose file."""
    raw = os.getenv('CONTAINER_ENV_FILES', '').strip()
    if not raw:
        return list(DEFAULT_ENV_FILES)
    return [e.strip() for e in raw.split(',') if e.strip()]


def _read_env_file(path: str) -> Dict[str, str]:
    """Parse a .env file the way docker compose does, for the common cases:
    KEY=VALUE lines, optional `export `, quoted values, `#` comments."""
    if path in _env_file_cache:
        return _env_file_cache[path]
    values: Dict[str, str] = {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith('export '):
                    line = line[len('export '):].lstrip()
                key, sep, value = line.partition('=')
                key = key.strip()
                if not sep or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key):
                    continue
                value = value.strip()
                if value[:1] in ('"', "'") and value.endswith(value[0]) and len(value) > 1:
                    value = value[1:-1]
                else:
                    value = re.split(r'\s+#', value, 1)[0]
                values[key] = value
    except OSError:
        pass
    _env_file_cache[path] = values
    return values


def compose_variables(compose_file: str, root: Optional[str] = None) -> tuple:
    """Variables `docker compose` would interpolate into *compose_file*.

    Compose reads the environment plus the project's .env. In a checkout .env
    is usually absent (it's gitignored), but .env.example / .env.sample --
    the committed template, typically holding the pinned image versions --
    is there, so those are lower-priority fallbacks (see compose_env_files()).
    Bare names are looked for from the compose file's directory up to
    *root*, nearer files winning; the environment beats every file.
    Returns (variables, [env files used]).

    These values are only ever used to expand image names -- never exported
    -- so a placeholder like SLACK_WEBHOOK_URL in .env.example has no effect.
    """
    root = os.path.abspath(root or os.path.dirname(compose_file))
    directory = os.path.abspath(os.path.dirname(compose_file))
    chain = []
    while True:
        chain.append(directory)
        if directory == root or os.path.dirname(directory) == directory \
                or not directory.startswith(root + os.sep):
            break
        directory = os.path.dirname(directory)
    variables: Dict[str, str] = {}
    used: List[str] = []
    # Lowest priority first: the last listed file (farthest directory first,
    # then nearer), up to the first listed, then the environment on top.
    for name in reversed(compose_env_files()):
        if '/' in name:
            candidates = [name if os.path.isabs(name) else os.path.join(root, name)]
        else:
            candidates = [os.path.join(d, name) for d in reversed(chain)]
        for path in candidates:
            if os.path.isfile(path):
                values = _read_env_file(path)
                if values:
                    variables.update(values)
                    used.append(path)
    variables.update(os.environ)
    return variables, used


_VAR_RE = re.compile(
    r'\$\$'                                             # escaped $
    r'|\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-?+])([^}]*))?\}'  # ${VAR}, ${VAR:-d}, ${VAR-d}, ${VAR:?e}, ${VAR:+a}
    r'|\$([A-Za-z_][A-Za-z0-9_]*)'                       # $VAR
)


def interpolate(value: str, variables: Dict[str, str]) -> tuple:
    """Compose-style variable interpolation. Returns (result, [unresolved names])."""
    unresolved: List[str] = []

    def _sub(m):
        if m.group(0) == '$$':
            return '$'
        name = m.group(1) or m.group(4)
        op, arg = m.group(2), m.group(3) or ''
        current = variables.get(name)
        is_set = current is not None
        non_empty = bool(current)
        if op in (':-', '-'):
            if (non_empty if op == ':-' else is_set):
                return current
            expanded, missing = interpolate(arg, variables)
            unresolved.extend(missing)
            return expanded
        if op in (':+', '+'):
            if (non_empty if op == ':+' else is_set):
                expanded, missing = interpolate(arg, variables)
                unresolved.extend(missing)
                return expanded
            return ''
        # plain, or ${VAR:?err} / ${VAR?err}: needs a value
        if (non_empty if op == ':?' else is_set):
            return current
        unresolved.append(name)
        return m.group(0)

    return _VAR_RE.sub(_sub, value), unresolved


def unresolved_image_reason(image: str) -> Optional[str]:
    """Why *image* can't be scanned if it still has an unexpanded variable."""
    names = sorted(set(re.findall(r'\$\{?([A-Za-z_][A-Za-z0-9_]*)', image)))
    if not names:
        return None
    listed = ', '.join('${%s}' % n for n in names)
    return (f"unresolved {listed} -- set it in the environment or in one of "
            f"{', '.join(compose_env_files())} next to the compose file or in a parent "
            f"directory (CONTAINER_ENV_FILES)")


def extract_images_from_compose(compose_file: str, root: Optional[str] = None) -> List[tuple]:
    """Extract (image, line) pairs from a compose file, with compose-style
    variable interpolation (see compose_variables()). An image whose
    variables can't be resolved is returned as written; check it with
    unresolved_image_reason() before scanning.

    *line* is the 1-indexed source line of the service's 'image:' key, or 0
    if it couldn't be determined -- callers should treat 0 as "no line".
    """
    images = []

    try:
        import yaml
        Loader, image_lines = _image_line_loader()
        with open(compose_file, 'r') as f:
            compose_data = yaml.load(f, Loader=Loader)

        if compose_data and 'services' in compose_data:
            variables, used_files = None, []
            for service_name, service_config in compose_data['services'].items():
                if isinstance(service_config, dict) and 'image' in service_config:
                    image_name = str(service_config['image'])
                    line_no = image_lines.get(id(service_config), 0)
                    if '$' in image_name:
                        if variables is None:
                            variables, used_files = compose_variables(compose_file, root)
                        image_name, _ = interpolate(image_name, variables)
                    images.append((image_name, line_no))
            if used_files:
                base = root or os.path.dirname(compose_file)
                print(f"[i] {os.path.relpath(compose_file, base)}: image variables from "
                      + ', '.join(os.path.relpath(p, base) for p in used_files))
    except Exception as e:
        print(f"Warning: Could not parse {compose_file}: {e}")

    return images

def extract_images_from_kubernetes(k8s_file: str) -> List[tuple]:
    """Extract (image, line) pairs from a Kubernetes manifest file.

    *line* is the 1-indexed source line of the 'image:' key, or 0 if it
    couldn't be determined -- callers should treat 0 as "no line".
    """
    images = []

    try:
        import yaml
        Loader, image_lines = _image_line_loader()
        with open(k8s_file, 'r') as f:
            # K8s files can have multiple documents separated by ---
            docs = yaml.load_all(f, Loader=Loader)
            for doc in docs:
                if not doc or not isinstance(doc, dict):
                    continue

                # Recursive function to find 'image' keys in any container spec
                def find_images(obj):
                    if isinstance(obj, dict):
                        if 'image' in obj and isinstance(obj['image'], str):
                            images.append((obj['image'], image_lines.get(id(obj), 0)))
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

def image_registry(image: str) -> str:
    """Registry host an image reference resolves to, per Docker's own rule:
    the first path component is a registry only if it contains '.' or ':'
    or is 'localhost' -- anything else (e.g. `vcem/core:1.4`) is Docker Hub."""
    first, sep, _ = image.partition('/')
    if sep and ('.' in first or ':' in first or first == 'localhost'):
        return first
    return 'docker.io'


def drop_ignored_images(all_images_map: dict) -> dict:
    """Remove images matching the CONTAINER_IGNORE_IMAGES regex, if set.

    Meant for images the repo builds itself and only publishes after merge
    (e.g. `-SNAPSHOT` tags): on a PR the registry only has the previous
    build, so scanning it reports stale results -- or nothing, if the tag
    was never pushed.
    """
    raw = os.getenv('CONTAINER_IGNORE_IMAGES', '').strip()
    if not raw:
        return all_images_map
    try:
        pattern = re.compile(raw)
    except re.error as e:
        print(f"[warn] Ignoring invalid CONTAINER_IGNORE_IMAGES regex {raw!r}: {e}")
        return all_images_map
    skipped = [img for img in all_images_map if pattern.search(img)]
    if skipped:
        print(f"[i] Skipping {len(skipped)} image(s) matching CONTAINER_IGNORE_IMAGES={raw!r}: {', '.join(skipped)}")
    return {img: refs for img, refs in all_images_map.items() if img not in skipped}


def docker_hub_credentials_available() -> bool:
    """Whether Docker Scout can plausibly authenticate.

    Scout needs a Docker Hub login even on a free account; without one every
    `docker scout cves` call fails, so callers can go straight to Grype.
    """
    for user_var, pass_var in (('DOCKER_HUB_USERNAME', 'DOCKER_HUB_PASSWORD'),
                               ('DOCKER_SCOUT_HUB_USER', 'DOCKER_SCOUT_HUB_PASSWORD')):
        if os.getenv(user_var, '').strip() and os.getenv(pass_var, '').strip():
            return True
    config_dir = os.getenv('DOCKER_CONFIG') or os.path.expanduser('~/.docker')
    try:
        with open(os.path.join(config_dir, 'config.json'), 'r', encoding='utf-8') as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        return False
    hub_keys = ('https://index.docker.io/v1/', 'index.docker.io', 'docker.io', 'registry-1.docker.io')
    if any(k in cfg.get('auths', {}) for k in hub_keys):
        return True
    return bool(cfg.get('credsStore')) or any(k in cfg.get('credHelpers', {}) for k in hub_keys)


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
