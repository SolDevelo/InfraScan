import os
import shutil
import tempfile
import uuid
import json
import time
import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for
from urllib.parse import urlparse
import requests
from dotenv import load_dotenv
from git import Repo, cmd
from scanner.parser import scan_directory, get_container_scanner, is_container_scanner_available
from scanner.checkov_scanner import CheckovScanner
from scanner.docker_scout_scanner import DockerScoutScanner
from scanner.grype_scanner import GrypeScanner
from scanner.openvas_scanner import OpenvasScanner
from reporter.grading import ReportGenerator
import traceback

load_dotenv()

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['RESULTS_DIR'] = os.path.join(os.getcwd(), 'scan_results')
app.config['DATA_DIR'] = os.path.join(os.getcwd(), 'data')
app.config['FEEDBACK_FILE'] = os.path.join(app.config['DATA_DIR'], 'feedback.json')
app.config['SUBSCRIBERS_FILE'] = os.path.join(app.config['DATA_DIR'], 'subscribers.json')
app.config['MONITORED_PROJECTS_FILE'] = os.path.join(app.config['DATA_DIR'], 'monitored_projects.json')
app.config['GITHUB_ACTIONS_PROJECTS_FILE'] = os.path.join(app.config['DATA_DIR'], 'github_actions_projects.json')
app.config['SHOW_GRADES_PUBLICLY'] = os.getenv('SHOW_GRADES_PUBLICLY', 'True').lower() in ('true', '1', 'yes')

# Create directories if they don't exist
os.makedirs(app.config['RESULTS_DIR'], exist_ok=True)
os.makedirs(app.config['DATA_DIR'], exist_ok=True)
app.config['SLACK_WEBHOOK_URL'] = os.getenv('SLACK_WEBHOOK_URL', '')

# Ensure monitored projects config exists
if not os.path.exists(app.config['MONITORED_PROJECTS_FILE']):
    with open(app.config['MONITORED_PROJECTS_FILE'], 'w') as f:
        json.dump([], f)

if not os.path.exists(app.config['GITHUB_ACTIONS_PROJECTS_FILE']):
    with open(app.config['GITHUB_ACTIONS_PROJECTS_FILE'], 'w') as f:
        json.dump([], f)

# Cache busting - changes on each deployment/restart
STATIC_VERSION = str(int(time.time()))

# Ensure results and feedback directories exist
os.makedirs(app.config['RESULTS_DIR'], exist_ok=True)
os.makedirs(os.path.dirname(app.config['FEEDBACK_FILE']), exist_ok=True)

@app.context_processor
def inject_global_vars():
    """Make global variables available in all templates."""
    return {
        'static_version': STATIC_VERSION,
        'google_tag_id': os.getenv('GOOGLE_TAG_ID', ''),
        'site_domain': os.getenv('SITE_DOMAIN', 'https://infrascan.soldevelo.com')
    }

def get_slack_webhook_url() -> str:
    return os.getenv('SLACK_WEBHOOK_URL', '').strip()

def build_share_url(result_id: str, req, metadata=None) -> str:
    clean_repo = "report"
    if metadata and 'repository_name' in metadata:
        import re
        clean_repo = re.sub(r'[^a-z0-9]+', '-', metadata['repository_name'].lower()).strip('-')
        if not clean_repo:
            clean_repo = "report"
    
    scan_path = f"report/{clean_repo}-{result_id}"

    if req and req.host_url:
        return f"{req.host_url.rstrip('/')}/{scan_path}"

    return f"/{scan_path}"


def load_monitored_projects():
    try:
        with open(app.config['MONITORED_PROJECTS_FILE'], 'r') as f:
            items = json.load(f) or []
    except Exception:
        return []

    monitored = []
    for item in items:
        if isinstance(item, str):
            monitored.append({
                'repo_url': item,
                'branch': 'main',
                'scanner': 'comprehensive',
                'is_private': False,
            })
        elif isinstance(item, dict) and item.get('repo_url'):
            monitored.append({
                'repo_url': item['repo_url'],
                'branch': item.get('branch', 'main'),
                'scanner': item.get('scanner', 'comprehensive'),
                'is_private': item.get('is_private', False),
            })
    return monitored


def load_github_actions_projects():
    try:
        with open(app.config['GITHUB_ACTIONS_PROJECTS_FILE'], 'r') as f:
            items = json.load(f) or []
    except Exception:
        return []

    projects = []
    for item in items:
        if isinstance(item, str):
            projects.append({'repo_url': item})
        elif isinstance(item, dict) and item.get('repo_url'):
            projects.append({'repo_url': item['repo_url']})
    return projects


def save_scan_result(report_dict):
    if 'metadata' not in report_dict or report_dict['metadata'] is None:
        report_dict['metadata'] = {}
    result_id = str(uuid.uuid4())
    file_path = os.path.join(app.config['RESULTS_DIR'], f"{result_id}.json")
    with open(file_path, 'w') as f:
        json.dump(report_dict, f)
    return result_id


def send_slack_notification(message: str) -> None:
    webhook_url = get_slack_webhook_url()
    if not webhook_url:
        return

    payload = {
        'text': message
    }

    try:
        response = requests.post(webhook_url, json=payload, timeout=5)
        if response.status_code >= 400:
            print(f"Slack notification failed: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Slack notification error: {e}")

@app.route('/')
def index():
    scan_id = request.args.get('scan_id')
    if scan_id:
        import re
        match = re.search(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$', scan_id.lower())
        real_uuid = match.group(1) if match else scan_id
        
        file_path = os.path.join(app.config['RESULTS_DIR'], f"{real_uuid}.json")
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                metadata = data.get('metadata', {})
                clean_repo = "report"
                if 'repository_name' in metadata:
                    clean_repo = re.sub(r'[^a-z0-9]+', '-', metadata['repository_name'].lower()).strip('-') or "report"
                return redirect(url_for('report_view', scan_id=f"{clean_repo}-{real_uuid}"), code=301)
            except Exception:
                pass
        return redirect(url_for('report_view', scan_id=scan_id), code=301)
        
    return render_template('index.html')

@app.route('/robots.txt')
def static_from_root():
    return send_from_directory(app.static_folder, request.path[1:])

@app.route('/sitemap.xml')
def sitemap():
    results_dir = app.config['RESULTS_DIR']
    try:
        files = [f for f in os.listdir(results_dir) if f.endswith('.json')]
    except FileNotFoundError:
        files = []

    urls = []
    host_url = request.host_url.rstrip('/')
    urls.append(f"{host_url}/")
    
    import re
    for filename in files:
        file_path = os.path.join(results_dir, filename)
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            metadata = data.get('metadata', {})
            if not metadata.get('is_private', False):
                real_uuid = filename.replace('.json', '')
                clean_repo = "report"
                if 'repository_name' in metadata:
                    clean_repo = re.sub(r'[^a-z0-9]+', '-', metadata['repository_name'].lower()).strip('-') or "report"
                urls.append(f"{host_url}/report/{clean_repo}-{real_uuid}")
        except Exception:
            continue
            
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    for url in urls:
        xml += f'  <url><loc>{url}</loc></url>\n'
    xml += '</urlset>'
    
    return app.response_class(xml, mimetype='application/xml')

@app.route('/report/<path:scan_id>')
def report_view(scan_id):
    import re
    match = re.search(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$', scan_id.lower())
    real_uuid = match.group(1) if match else scan_id

    if '..' in real_uuid or '/' in real_uuid or '\\' in real_uuid or not real_uuid.replace('-', '').isalnum():
        return "Invalid scan ID", 400

    file_path = os.path.join(app.config['RESULTS_DIR'], f"{real_uuid}.json")
    if not os.path.exists(file_path):
        return "Report not found", 404
        
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
    except Exception:
        return "Error reading report", 500

    metadata = data.get('metadata', {})
    clean_repo = "report"
    if 'repository_name' in metadata:
        clean_repo = re.sub(r'[^a-z0-9]+', '-', metadata['repository_name'].lower()).strip('-') or "report"
    canonical_scan_id = f"{clean_repo}-{real_uuid}"
    
    return render_template('report.html', 
                           data=data, 
                           report_json=json.dumps(data).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026').replace("'", '\\u0027'), 
                           current_scan_id=canonical_scan_id,
                           metadata=metadata,
                           summary=data.get('summary', {}),
                           grade_report={
                               'overall': data.get('overall', {}),
                               'cost': data.get('cost', {}),
                               'security': data.get('security', {}),
                               'container': data.get('container', {}),
                           })

@app.route('/api/scanner/status')
def scanner_status():
    """Return information about available scanners."""
    checkov_available = CheckovScanner().is_available()
    container_scanner = get_container_scanner()
    container_scanner_available = is_container_scanner_available()

    # For backwards compatibility, also expose individual scanner status
    docker_scout_available = DockerScoutScanner().is_available()
    grype_available = GrypeScanner().is_available()
    openvas_available = OpenvasScanner().is_available()

    return jsonify({
        'regex': True,  # Always available
        'checkov': checkov_available,
        'container_scanner': container_scanner,  # Which scanner is configured
        'containers': container_scanner_available,  # Is the configured scanner available
        'docker_scout': docker_scout_available,
        'grype': grype_available,
        'openvas': openvas_available,  # Opt-in only, requires explicit target IPs
        'comprehensive': checkov_available or container_scanner_available  # Can run comprehensive if any security scanner available
    })

@app.route('/api/repo/branches', methods=['POST'])
def get_branches():
    """Fetch branches for a given repository URL.
    
    For GitHub repositories, also returns the default_branch as reported
    by the GitHub REST API so the UI can pre-select it.
    """
    data = request.get_json()
    repo_url = data.get('url')
    
    if not repo_url:
        return jsonify({'error': 'No URL provided'}), 400
    
    # Strip query parameters and hash fragments from URL
    repo_url = repo_url.split('?')[0].split('#')[0]

    # --- Detect GitHub URL and fetch default branch via the GitHub API ---
    default_branch = None
    import re as _re
    github_match = _re.match(
        r'https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$',
        repo_url,
        _re.IGNORECASE
    )
    if github_match:
        owner, repo_name = github_match.group(1), github_match.group(2)
        try:
            gh_headers = {'Accept': 'application/vnd.github+json'}
            gh_token = os.getenv('GITHUB_TOKEN', '').strip()
            if gh_token:
                gh_headers['Authorization'] = f'Bearer {gh_token}'
            gh_resp = requests.get(
                f'https://api.github.com/repos/{owner}/{repo_name}',
                headers=gh_headers,
                timeout=10
            )
            if gh_resp.status_code == 200:
                default_branch = gh_resp.json().get('default_branch')
        except Exception:
            pass  # Non-fatal – fall back to ls-remote ordering
    # --- End GitHub detection ---
    
    try:
        g = cmd.Git()
        # ls-remote --heads returns lines like "hash\trefs/heads/branchname"
        output = g.ls_remote('--heads', repo_url)
        branches = []
        for line in output.splitlines():
            if '\trefs/heads/' in line:
                branches.append(line.split('\trefs/heads/')[-1])
        
        # Sort branches alphabetically
        if branches:
            branches.sort()
            # Promote the actual default branch to the top
            top_branch = default_branch if default_branch and default_branch in branches else None
            if top_branch is None:
                # Fallback: prefer 'main', then 'master'
                for primary in ['main', 'master']:
                    if primary in branches:
                        top_branch = primary
                        break
            if top_branch and top_branch in branches:
                branches.remove(top_branch)
                branches.insert(0, top_branch)
        else:
            # If no heads found, return common defaults as a fallback
            branches = ['main', 'master']
            if default_branch and default_branch not in branches:
                branches.insert(0, default_branch)
            
        return jsonify({'branches': branches, 'default_branch': default_branch})
    except Exception as e:
        print(f"Error: {e}")
        error_msg = str(e).lower()
        if 'could not read' in error_msg or 'not found' in error_msg or 'does not exist' in error_msg:
            return jsonify({'error': 'Unable to access repository. Please verify the URL.'}), 400
        return jsonify({'error': f'Failed to fetch branches: {str(e)}'}), 500


@app.route('/api/scan/github', methods=['POST'])
def scan_github():
    data = request.get_json()
    repo_url = data.get('url')
    branch = data.get('branch', 'main')  # Default to main if not provided
    scanner_type = data.get('scanner', 'regex')  # Default to regex scanner

    is_private = data.get('is_private', False)  # Optional private scan flag
    
    if not repo_url:
        return jsonify({'error': 'No URL provided'}), 400
    
    # Strip query parameters and hash fragments from URL
    repo_url = repo_url.split('?')[0].split('#')[0]
    
    # Validate scanner type(s)
    valid_scanners = ['regex', 'fast', 'checkov', 'containers', 'comprehensive', 'both']
    incoming_scanners = [s.strip() for s in scanner_type.split(',')]
    for s in incoming_scanners:
        if s not in valid_scanners:
            return jsonify({'error': f'Invalid scanner: {s}. Must be one of: {valid_scanners}'}), 400
    
    # Normalize 'both' to 'comprehensive' for backwards compatibility
    if scanner_type == 'both':
        scanner_type = 'comprehensive'
    
    # Check if Checkov is requested but not available
    if scanner_type in ['checkov', 'comprehensive'] and not CheckovScanner().is_available():
        return jsonify({
            'error': 'Checkov scanner is not installed. Install with: pip install checkov',
            'hint': 'You can still use the regex scanner by setting scanner=regex'
        }), 400
    
    # Create a temporary directory for the repo
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Clone with timeout and shallow clone (only latest commit)
        from threading import Thread, Event
        import time
        
        clone_error = None
        clone_success = Event()
        
        def clone_repo():
            nonlocal clone_error
            try:
                # Shallow clone - only latest commit to reduce size and time
                # Use specified branch
                Repo.clone_from(repo_url, temp_dir, branch=branch, depth=1)
                clone_success.set()
            except Exception as e:
                # If specified branch fails (e.g. 'main' doesn't exist and we defaulted to it)
                # try to clone without branch (gets default branch)
                try:
                    # Clean temp_dir and retry without branch
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    os.makedirs(temp_dir, exist_ok=True)
                    Repo.clone_from(repo_url, temp_dir, depth=1)
                    clone_success.set()
                except Exception as retry_error:
                    clone_error = retry_error
                    clone_success.set()
        
        # Start clone in separate thread
        clone_thread = Thread(target=clone_repo)
        clone_thread.daemon = True
        clone_thread.start()
        
        # Wait for clone with timeout (90 seconds)
        clone_thread.join(timeout=90)
        
        # Check if clone completed
        if clone_thread.is_alive():
            # Timeout occurred
            return jsonify({
                'error': 'Repository access timed out. The repository may be too large or unavailable. Please try a smaller repository.'
            }), 408
        
        # Check if clone had an error
        if clone_error:
            raise clone_error
        
        # Scan directory and get results with resource count
        results, resource_count, recommendations = scan_directory(temp_dir, scanner_type=scanner_type, framework='smart')
        
        # Generate comprehensive report with grades
        report_generator = ReportGenerator()
        report = report_generator.generate_report(
            findings=results,
            resource_count=resource_count,
            scanner_type=scanner_type,
            extra_recommendations=recommendations,
            scan_path=temp_dir
        )
        
        # Extract repository name from URL for display
        repo_name = repo_url.rstrip('/').split('/')[-1] if '/' in repo_url else repo_url
        
        # Get current timestamp
        from datetime import datetime, timezone
        scan_timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        
        # Build response with report data
        report_dict = report.to_dict()
        report_dict['metadata'].update({
            'repository_url': repo_url,
            'repository_name': repo_name,
            'scan_source': 'web_app',

            'scan_timestamp': scan_timestamp,
            'is_private': is_private,
            'branch': branch
        })

        # Send Slack notification if enabled
        total_findings = len(results)
        cost_findings = len(report.cost_findings)
        security_findings = len(report.security_findings)
        container_findings = len(report.container_findings)
        overall_grade = report.overall_grade
        cost_grade = report.cost_grade
        security_grade = report.security_grade
        container_grade = report.container_grade

        
        # Build findings summary
        findings_parts = [f"Cost {cost_findings}", f"Security {security_findings}"]
        if container_findings > 0:
            findings_parts.append(f"Containers {container_findings}")
        findings_summary = ", ".join(findings_parts)
        
        # Build grades summary
        grades_parts = []

        if overall_grade:
            grades_parts.append(
                f"Overall {overall_grade.letter} ({overall_grade.percentage}%)"
            )
        
        if cost_grade:
            grades_parts.append(
                f"Cost {cost_grade.letter} ({cost_grade.percentage}%)"
            )
        
        if security_grade:
            grades_parts.append(
                f"Security {security_grade.letter} ({security_grade.percentage}%)"
            )
        
        if container_grade:
            grades_parts.append(
                f"Containers {container_grade.letter} ({container_grade.percentage}%)"
            )
        grades_summary = " ".join(grades_parts)
        
        slack_message = (
            "🔔 InfraScan completed | "
            f"Repo: {repo_url} | "
            f"Grades: {grades_summary} | "
            f"Findings: {total_findings} ({findings_summary}) | "
            f"Resource count: {resource_count} | "
            f"Scanner: {scanner_type} | "
            f"Time: {scan_timestamp}"
        )
        send_slack_notification(slack_message)
        
        # Legacy compatibility: keep old format fields
        regex_results = [r for r in results if r.get('scanner') == 'regex']
        checkov_results = [r for r in results if r.get('scanner') == 'checkov']
        container_results = [r for r in results if r.get('scanner') in ['docker-scout', 'grype']]
        
        report_dict['results'] = results
        report_dict['summary'] = {
            'total': len(results),
            'unique_rules': report.metrics.get('unique_rules_triggered', 0),
            'regex_findings': len(regex_results),
            'checkov_findings': len(checkov_results),
            'grype_findings': len(container_results),  # For backwards compatibility
            'container_findings': len(container_results),
            'scanner_used': scanner_type
        }
        
        return jsonify(report_dict)
    except Exception as e:
        print(f"Error: {e}")
        # User-friendly error message without exposing technical details
        error_msg = str(e).lower()
        if 'could not read' in error_msg or 'not found' in error_msg or 'does not exist' in error_msg:
            return jsonify({
                'error': 'Unable to access repository. Please verify the URL format (https://github.com/username/repo) and ensure the repository is public.'
            }), 400
        else:
            return jsonify({
                'error': 'Unable to process repository. Please check the URL and try again.'
            }), 500
    finally:
        # Clean up
        shutil.rmtree(temp_dir, ignore_errors=True)
        

def scan_repository(repo_url, branch='main', scanner_type='comprehensive', is_private=False, scan_source='monitored_scan'):
    temp_dir = tempfile.mkdtemp()
    try:
        Repo.clone_from(repo_url, temp_dir, branch=branch, depth=1)
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise RuntimeError(f"Unable to clone repository: {e}")

    try:
        results, resource_count, recommendations = scan_directory(temp_dir, scanner_type=scanner_type, framework='smart')
        report_generator = ReportGenerator()
        report = report_generator.generate_report(
            findings=results,
            resource_count=resource_count,
            scanner_type=scanner_type,
            extra_recommendations=recommendations,
            scan_path=temp_dir
        )

        repo_name = repo_url.rstrip('/').split('/')[-1] if '/' in repo_url else repo_url
        scan_timestamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

        report_dict = report.to_dict()
        report_dict['metadata'] = report_dict.get('metadata', {})
        report_dict['metadata'].update({
            'repository_url': repo_url,
            'repository_name': repo_name,
            'scan_source': scan_source,
            'scan_timestamp': scan_timestamp,
            'is_private': is_private,
            'branch': branch
        })

        report_dict['results'] = results
        report_dict['summary'] = {
            'total': len(results),
            'unique_rules': report.metrics.get('unique_rules_triggered', 0),
            'scanner_used': scanner_type
        }

        scan_id = save_scan_result(report_dict)
        return scan_id, report_dict
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.route('/api/scans/monitored/refresh', methods=['POST'])
def refresh_monitored_scans():
    monitored = load_monitored_projects()
    if not monitored:
        return jsonify({'error': 'No monitored repositories configured.', 'monitored_projects': []}), 400

    refresh_results = []
    for project in monitored:
        try:
            scan_id, report_dict = scan_repository(
                project['repo_url'],
                branch=project.get('branch', 'main'),
                scanner_type=project.get('scanner', 'comprehensive'),
                is_private=project.get('is_private', False),
                scan_source='monitored_project'
            )
            refresh_results.append({
                'repo_url': project['repo_url'],
                'scan_id': scan_id,
                'status': 'ok',
                'grade': report_dict.get('overall', {}).get('letter', '?'),
                'scan_timestamp': report_dict['metadata'].get('scan_timestamp')
            })
        except Exception as e:
            refresh_results.append({
                'repo_url': project['repo_url'],
                'status': 'error',
                'message': str(e)
            })

    return jsonify({
        'results': refresh_results,
        'refreshed_at': datetime.datetime.now(datetime.timezone.utc).isoformat()
    })


def is_run_already_saved(run_id):
    results_dir = app.config['RESULTS_DIR']
    try:
        files = [f for f in os.listdir(results_dir) if f.endswith('.json')]
        for filename in files:
            file_path = os.path.join(results_dir, filename)
            with open(file_path, 'r') as f:
                data = json.load(f)
                if str(data.get('metadata', {}).get('github_run_id', '')) == str(run_id):
                    return True
    except Exception:
        pass
    return False

def fetch_latest_github_actions_result(repo_url, github_token=None):
    import re
    match = re.search(r'github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$', repo_url)
    if not match:
        return None, "Not a valid GitHub URL"
    owner, repo = match.groups()
    
    headers = {'Accept': 'application/vnd.github+json'}
    if github_token:
        headers['Authorization'] = f'Bearer {github_token}'
        
    runs_url = f"https://api.github.com/repos/{owner}/{repo}/actions/runs?status=success&per_page=10"
    resp = requests.get(runs_url, headers=headers, timeout=10)
    if resp.status_code != 200:
        return None, f"Failed to fetch runs: {resp.text}"
        
    runs = resp.json().get('workflow_runs', [])
    if not runs:
        return None, "No successful runs found"
        
    # Sort runs from newest to oldest
    runs.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
    import zipfile
    import io
    
    for run in runs:
        run_id = str(run['id'])
        print(f"[DEBUG] Checking run {run_id}")
        
        # If saved, continue checking older runs instead of returning
        if is_run_already_saved(run_id):
            print(f"[DEBUG] Run {run_id} is already saved, skipping...")
            continue
            
        artifacts_url = run['artifacts_url']
        art_resp = requests.get(artifacts_url, headers=headers, timeout=10)
        if art_resp.status_code != 200:
            print(f"[DEBUG] Failed to fetch artifacts for run {run_id}: {art_resp.status_code}")
            continue
            
        artifacts = art_resp.json().get('artifacts', [])
        print(f"[DEBUG] Found {len(artifacts)} artifacts for run {run_id}")
        
        target_artifact = None
        for a in artifacts:
            name_lower = a['name'].lower()
            if 'infrascan' in name_lower or 'report' in name_lower or 'scan' in name_lower:
                target_artifact = a
                break
                
        if not target_artifact:
            print(f"[DEBUG] No matching artifact in run {run_id}")
            continue
            
        print(f"[DEBUG] Found artifact: {target_artifact['name']} (ID: {target_artifact['id']})")
            
        dl_url = target_artifact['archive_download_url']
        # Explicitly allow redirects for GitHub API -> AWS S3 redirect
        dl_resp = requests.get(dl_url, headers=headers, timeout=20, allow_redirects=True)
        if dl_resp.status_code == 401:
            return None, "GitHub Token is required to download artifacts. Please set GITHUB_TOKEN in .env"
        if dl_resp.status_code != 200:
            print(f"[DEBUG] Failed to download artifact: {dl_resp.status_code}")
            continue
            
        try:
            with zipfile.ZipFile(io.BytesIO(dl_resp.content)) as z:
                all_files = z.namelist()
                json_files = [f for f in all_files if f.endswith('.json')]
                html_files = [f for f in all_files if f.endswith('.html')]
                
                report_data = None
                
                if json_files:
                    for json_file in json_files:
                        with z.open(json_file) as jf:
                            try:
                                report_data = json.loads(jf.read().decode('utf-8'))
                                break
                            except Exception as e:
                                print(f"[DEBUG] Error parsing JSON {json_file}: {e}")
                                continue
                elif html_files:
                    print(f"[DEBUG] Found HTML report instead of JSON, parsing fallback...")
                    for html_file in html_files:
                        with z.open(html_file) as jf:
                            try:
                                html_content = jf.read().decode('utf-8')
                                import re
                                
                                # 1. Try to extract injected JSON data directly (Base64)
                                import base64
                                match_b64 = re.search(r'window\.CLI_INJECTED_DATA_B64\s*=\s*[\'"]([A-Za-z0-9+/=]+)[\'"]', html_content)
                                if match_b64:
                                    try:
                                        b64_data = match_b64.group(1)
                                        json_str = base64.b64decode(b64_data).decode('utf-8')
                                        report_data = json.loads(json_str)
                                        print(f"[DEBUG] Extracted JSON data from HTML report via CLI_INJECTED_DATA_B64")
                                        break
                                    except Exception as e:
                                        print(f"[DEBUG] Error decoding B64 data: {e}")

                                # 1b. Try to extract injected JSON data directly (Raw)
                                match = re.search(r'window\.CLI_INJECTED_DATA\s*=\s*(\{.*?\});', html_content, re.DOTALL)
                                if match:
                                    report_data = json.loads(match.group(1))
                                    print(f"[DEBUG] Extracted JSON data from HTML report via CLI_INJECTED_DATA")
                                    break
                                    
                                # 2. Fallback to BeautifulSoup parsing
                                from bs4 import BeautifulSoup
                                soup = BeautifulSoup(html_content, 'html.parser')
                                
                                fallback_data = {
                                    "metadata": {},
                                    "summary": {"total": 0, "scanner_used": "unknown"},
                                    "overall": {"letter": "?", "percentage": 0},
                                    "cost": {"letter": "?", "percentage": 0},
                                    "security": {"letter": "?", "percentage": 0},
                                    "container": {"letter": "?", "percentage": 0},
                                    "results": []
                                }
                                
                                def extract_grade(grade_name, text):
                                    m = re.search(fr'{grade_name}.*?([A-F\?])\s*\(?(\d+)%?\)?', text, re.IGNORECASE | re.DOTALL)
                                    if m:
                                        return {"letter": m.group(1).upper(), "percentage": int(m.group(2))}
                                    m2 = re.search(fr'{grade_name}.*?([A-F\?])\s+(\d+)', text, re.IGNORECASE | re.DOTALL)
                                    if m2:
                                        return {"letter": m2.group(1).upper(), "percentage": int(m2.group(2))}
                                    return {"letter": "?", "percentage": 0}

                                full_text = soup.get_text(separator=' ', strip=True)
                                
                                fallback_data["overall"] = extract_grade('Overall', full_text)
                                fallback_data["security"] = extract_grade('Security', full_text)
                                fallback_data["cost"] = extract_grade('Cost', full_text)
                                fallback_data["container"] = extract_grade('Container', full_text)
                                
                                m_total = re.search(r'(?:Total\s*(?:findings|issues|vulnerabilities)[:\s]+)(\d+)', full_text, re.IGNORECASE)
                                if m_total:
                                    fallback_data["summary"]["total"] = int(m_total.group(1))
                                
                                title = soup.title.string if soup.title else "HTML Report"
                                fallback_data["metadata"]["title"] = title
                                
                                report_data = fallback_data
                                print(f"[DEBUG] Extracted 4 sections from HTML report")
                                print(f"[DEBUG] Converted HTML report to InfraScan JSON")
                                break
                            except Exception as e:
                                print(f"[DEBUG] Error parsing HTML {html_file}: {e}")
                                continue
                
                if report_data is not None:
                    if 'metadata' not in report_data:
                        report_data['metadata'] = {}
                    report_data['metadata']['github_run_id'] = run_id
                    report_data['metadata']['scan_source'] = 'github_actions'
                    report_data['metadata']['repository_url'] = repo_url
                    
                    if 'scan_timestamp' not in report_data['metadata']:
                        from datetime import datetime, timezone
                        created_at = run.get('created_at')
                        if created_at:
                            try:
                                dt = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                                report_data['metadata']['scan_timestamp'] = dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                            except Exception:
                                report_data['metadata']['scan_timestamp'] = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
                        else:
                            report_data['metadata']['scan_timestamp'] = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
                            
                    if 'is_private' not in report_data['metadata']:
                        report_data['metadata']['is_private'] = False
                        
                    print(f"[DEBUG] Successfully parsed artifact from run {run_id}")
                    return report_data, None
                else:
                    print(f"[DEBUG] Artifact zip does not contain parsable .json or .html files! Contents: {all_files}")
                    continue
                    
        except zipfile.BadZipFile:
            print(f"[DEBUG] Downloaded file is not a valid ZIP archive")
            continue
                        
    return None, "No valid artifact found in recent runs"


@app.route('/api/scans/github-actions/refresh', methods=['POST'])
def refresh_github_actions_scans():
    projects = load_github_actions_projects()
    if not projects:
        return jsonify({'error': 'No GitHub Actions projects configured.', 'projects': []}), 400
        
    github_token = os.getenv('GITHUB_TOKEN', '').strip()
    
    refresh_results = []
    for project in projects:
        repo_url = project['repo_url']
        try:
            report_data, error = fetch_latest_github_actions_result(repo_url, github_token)
            if error == "already_saved":
                refresh_results.append({'repo_url': repo_url, 'status': 'skipped', 'message': 'Run already saved'})
                continue
            if error:
                refresh_results.append({'repo_url': repo_url, 'status': 'error', 'message': error})
                continue
                
            scan_id = save_scan_result(report_data)
            refresh_results.append({'repo_url': repo_url, 'status': 'ok', 'scan_id': scan_id})
        except Exception as e:
            refresh_results.append({'repo_url': repo_url, 'status': 'error', 'message': str(e)})
            
    return jsonify({
        'results': refresh_results,
        'refreshed_at': datetime.datetime.now(datetime.timezone.utc).isoformat()
    })


@app.route('/api/results/save', methods=['POST'])
def save_results():
    data = request.get_json()
    if not data or 'results' not in data:
        return jsonify({'error': 'No results provided'}), 400
    
    result_id = str(uuid.uuid4())
    file_path = os.path.join(app.config['RESULTS_DIR'], f"{result_id}.json")
    
    # Store results with summary and metadata
    save_data = {
        'results': data.get('results'),
        'summary': data.get('summary'),
        'metadata': data.get('metadata', {}),
        'overall': data.get('overall'),
        'cost': data.get('cost'),
        'security': data.get('security'),
        'container': data.get('container'),
        'analysis': data.get('analysis'),
        'metrics': data.get('metrics'),
    }
    
    # Ensure is_private is preserved in metadata
    if 'metadata' not in save_data or save_data['metadata'] is None:
        save_data['metadata'] = {}
    
    if 'is_private' in data:
        save_data['metadata']['is_private'] = data.get('is_private')
    
    with open(file_path, 'w') as f:
        json.dump(save_data, f)

    metadata = data.get('metadata', {}) or {}
    repo_url = metadata.get('repository_url', 'unknown')


    share_url = build_share_url(result_id, request, metadata)

    slack_message = (
        "🔗 InfraScan results shared | "
        f"Repo: {repo_url} | "
        f"Share: {share_url}"
    )
    send_slack_notification(slack_message)
    
    return jsonify({'id': result_id, 'share_url': share_url})

@app.route('/api/results/<scan_id>', methods=['GET'])
def get_results(scan_id):
    # Security: basic path traversal protection
    if '..' in scan_id or '/' in scan_id or '\\' in scan_id or not scan_id.replace('-', '').isalnum():
        return jsonify({'error': 'Invalid scan ID'}), 400
        
    file_path = os.path.join(app.config['RESULTS_DIR'], f"{scan_id}.json")
    
    if not os.path.exists(file_path):
        return jsonify({'error': 'Results not found'}), 404
    
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    return jsonify(data)


def _extract_grade(grade_obj):
    """Safely extract grade letter and percentage from a grade dict."""
    if not grade_obj:
        return None
    return {
        'letter': grade_obj.get('letter', '?'),
        'percentage': grade_obj.get('percentage', 0)
    }


@app.route('/api/scans/recent', methods=['GET'])
def get_recent_scans():
    """Return a list of the most recent saved scans, newest first."""
    results_dir = app.config['RESULTS_DIR']
    scans = []

    try:
        files = [
            f for f in os.listdir(results_dir)
            if f.endswith('.json')
        ]
    except FileNotFoundError:
        return jsonify({'scans': []})

    for filename in files:
        file_path = os.path.join(results_dir, filename)
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            metadata = data.get('metadata', {}) or {}
            repo_url = metadata.get('repository_url')
            scan_timestamp = metadata.get('scan_timestamp')
            is_private = metadata.get('is_private', False)

            # Skip entries without essential data or private scans
            if not repo_url or not scan_timestamp or is_private:
                continue

            result_id = filename.replace('.json', '')

            scan_entry = {
                'id': result_id,
                'repository_url': repo_url,
                'repository_name': metadata.get('repository_name') or repo_url.rstrip('/').split('/')[-1],
                'branch': metadata.get('branch'),
                'scan_timestamp': scan_timestamp,
                'scanner_type': data.get('summary', {}).get('scanner_used', '') if data.get('summary') else '',
                'total_findings': data.get('summary', {}).get('total', 0) if data.get('summary') else 0,
                'overall_grade': _extract_grade(data.get('overall')),
                'cost_grade': _extract_grade(data.get('cost')),
                'security_grade': _extract_grade(data.get('security')),
                'container_grade': _extract_grade(data.get('container')),
            }
            scans.append(scan_entry)
        except Exception as e:
            print(f"Error reading scan file {filename}: {e}")
            continue

    # Sort by scan_timestamp descending, newest first
    scans.sort(key=lambda s: s['scan_timestamp'], reverse=True)

    # Return only the 500 most recent
    return jsonify({'scans': scans[:500]})


def normalize_repository_url(repo_url):
    import re
    if not repo_url:
        return repo_url

    url = repo_url.strip()
    if url.startswith('git@'):
        match = re.match(r'^git@([^:]+):(.+)$', url)
        if match:
            host = match.group(1)
            path = match.group(2)
            path = path.rstrip('/')
            if path.endswith('.git'):
                path = path[:-4]
            return f'https://{host}/{path}'

    if '://' not in url:
        url = f'https://{url}'

    parsed = urlparse(url)
    path = parsed.path.rstrip('/')
    if path.endswith('.git'):
        path = path[:-4]

    return f'{parsed.scheme}://{parsed.netloc}{path}'


def extract_project_name(repo_url):
    import re
    if not repo_url:
        return 'Unknown'

    url = repo_url.strip()

    # Normalize SSH-style URLs to a path-like string
    if url.startswith('git@') or '://git@' in url:
        if '://' in url:
            url = url.split('://', 1)[1]
        url = url.replace(':', '/')

    try:
        parsed = urlparse(url if '://' in url else f'https://{url}')
        path = parsed.path.strip('/')
    except Exception:
        path = url.strip('/')

    if path.endswith('.git'):
        path = path[:-4]

    parts = [p for p in path.split('/') if p]
    if parts:
        # Use repo name (last segment) when available
        return parts[-1]

    # Fallback: remove common host segments and return last remaining piece
    parts = [p for p in re.split(r'[:/]', url) if p and p.lower() not in ['github.com', 'gitlab.com', 'bitbucket.org', 'https', 'http', 'git']]
    return parts[-1] if parts else 'Unknown'


def get_display_name(proj_name):
    if not proj_name:
        return 'Unknown'

    if proj_name.islower():
        return proj_name.replace('-', ' ').replace('_', ' ').title()

    if '-' in proj_name or '_' in proj_name:
        import re
        parts = re.split(r'[-_]', proj_name)
        return ' '.join(part.capitalize() if part.islower() else part for part in parts)

    return proj_name


@app.route('/supported-projects')
def supported_projects():
    """Render the Supported Projects page."""
    return render_template('supported_projects.html')


@app.route('/project-scans')
def project_scans():
    """Render the project scans page."""
    repo_url = request.args.get('url')
    if not repo_url:
        return redirect(url_for('supported_projects'))
    
    project_name = extract_project_name(repo_url)
    display_name = get_display_name(project_name)
        
    return render_template('project_scans.html', 
                           repo_url=repo_url, 
                           project_name=display_name)


@app.route('/api/scans/project', methods=['GET'])
def get_project_scans():
    """Return all scans for a specific project URL."""
    repo_url = request.args.get('url')
    if not repo_url:
        return jsonify({'error': 'Missing repo_url'}), 400

    normalized_target_url = normalize_repository_url(repo_url)
    results_dir = app.config['RESULTS_DIR']
    project_scans = []
    
    try:
        files = [f for f in os.listdir(results_dir) if f.endswith('.json')]
    except FileNotFoundError:
        files = []

    for filename in files:
        file_path = os.path.join(results_dir, filename)
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            metadata = data.get('metadata', {}) or {}
            scan_repo_url = metadata.get('repository_url')
            if not scan_repo_url:
                continue

            if normalize_repository_url(scan_repo_url) == normalized_target_url:
                scan_timestamp = metadata.get('scan_timestamp')
                is_private = metadata.get('is_private', False)
                if is_private:
                    continue

                summary = data.get('summary', {})
                project_scans.append({
                    'scan_id': data.get('scan_id') or filename.replace('.json', ''),
                    'scan_timestamp': scan_timestamp,
                    'grade': summary.get('grade', '?'),
                    'total_issues': summary.get('total_issues', 0),
                    'scan_source': metadata.get('scan_source', 'unknown'),
                })
        except Exception as e:
            continue
            
    # Sort scans by timestamp descending
    project_scans.sort(key=lambda x: x['scan_timestamp'], reverse=True)
    return jsonify({'scans': project_scans})


@app.route('/api/scans/supported-projects', methods=['GET'])
def get_supported_projects():
    """Return an aggregated list of infrastructure projects using InfraScan in the last 12 months."""
    results_dir = app.config['RESULTS_DIR']
    projects_map = {}
    
    try:
        files = [f for f in os.listdir(results_dir) if f.endswith('.json')]
    except FileNotFoundError:
        files = []

    now = datetime.datetime.now(datetime.timezone.utc)
    twelve_months_ago = now - datetime.timedelta(days=365)

    import re
    for filename in files:
        file_path = os.path.join(results_dir, filename)
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            metadata = data.get('metadata', {}) or {}
            repo_url = metadata.get('repository_url')
            scan_timestamp = metadata.get('scan_timestamp')
            is_private = metadata.get('is_private', False)

            # Skip entries without essential data or private scans
            if not repo_url or not scan_timestamp or is_private:
                continue

            # Parse scan_timestamp
            scan_dt = None
            clean_ts = scan_timestamp.replace(' UTC', '').split('.')[0]
            for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d'):
                try:
                    scan_dt = datetime.datetime.strptime(clean_ts, fmt).replace(tzinfo=datetime.timezone.utc)
                    break
                except ValueError:
                    continue

            if not scan_dt:
                continue

            proj_name = extract_project_name(repo_url)
            normalized_repo_url = normalize_repository_url(repo_url)
            # Use the full normalized URL as the unique key (owner + repo)
            # This ensures forks from different users are separate projects
            proj_key = normalized_repo_url.lower()
            
            # Build a display name that includes owner for disambiguation:
            # e.g. "olszewskiigor / openmrs-contrib-cluster"
            try:
                from urllib.parse import urlparse as _urlparse
                _parsed = _urlparse(normalized_repo_url)
                _parts = [p for p in _parsed.path.strip('/').split('/') if p]
                if len(_parts) >= 2:
                    display_name = f"{_parts[-2]} / {proj_name}"
                else:
                    display_name = proj_name
            except Exception:
                display_name = proj_name
            
            # Check rolling 12-month window
            in_window = scan_dt >= twelve_months_ago

            latest_scan_letter = data.get('overall', {}).get('letter') if data.get('overall') else None
            latest_scan_pct = data.get('overall', {}).get('percentage') if data.get('overall') else None
            latest_scan_source = metadata.get('scan_source') or 'unknown'

            # Extract scan ID from filename (remove .json extension)
            scan_id = filename.replace('.json', '')
            
            if proj_key not in projects_map:
                projects_map[proj_key] = {
                    'raw_name': display_name,
                    'repository_url': normalized_repo_url,
                    'scans_in_window': 0,
                    'latest_scan_dt': scan_dt,
                    'latest_scan_id': scan_id,
                    'latest_scan_letter': latest_scan_letter,
                    'latest_scan_pct': latest_scan_pct,
                    'latest_scan_source': latest_scan_source,
                    'web_scans': 0,
                    'github_actions_scans': 0,
                    'other_scans': 0,
                    'pct_sum': 0,
                    'pct_count': 0,
                }
            else:
                if scan_dt > projects_map[proj_key]['latest_scan_dt']:
                    projects_map[proj_key]['latest_scan_dt'] = scan_dt
                    projects_map[proj_key]['latest_scan_id'] = scan_id
                    projects_map[proj_key]['latest_scan_letter'] = latest_scan_letter
                    projects_map[proj_key]['latest_scan_pct'] = latest_scan_pct
                    projects_map[proj_key]['latest_scan_source'] = latest_scan_source
                    projects_map[proj_key]['repository_url'] = normalized_repo_url

            if in_window:
                projects_map[proj_key]['scans_in_window'] += 1
                if latest_scan_source == 'github_actions':
                    projects_map[proj_key]['github_actions_scans'] += 1
                elif latest_scan_source == 'web_app':
                    projects_map[proj_key]['web_scans'] += 1
                else:
                    projects_map[proj_key]['other_scans'] += 1
                pct = latest_scan_pct
                if pct is not None:
                    try:
                        projects_map[proj_key]['pct_sum'] += float(pct)
                        projects_map[proj_key]['pct_count'] += 1
                    except (TypeError, ValueError):
                        pass

        except Exception as e:
            print(f"Error reading scan file {filename}: {e}")
            continue
    
    def pct_to_letter(pct):
        if pct >= 90: return 'A'
        if pct >= 75: return 'B'
        if pct >= 60: return 'C'
        if pct >= 45: return 'D'
        return 'F'

    projects_list = []
    for key, info in projects_map.items():
        if info['scans_in_window'] > 0:
            latest_grade = info.get('latest_scan_letter')
            if not latest_grade and info.get('latest_scan_pct') is not None:
                try:
                    latest_grade = pct_to_letter(float(info['latest_scan_pct']))
                except (TypeError, ValueError):
                    latest_grade = None
            if not latest_grade:
                latest_grade = '?'
            projects_list.append({
                'project_name': get_display_name(info['raw_name']),
                'repository_url': info.get('repository_url'),
                'scan_count': info['scans_in_window'],
                'latest_scan': info['latest_scan_dt'].strftime('%Y-%m-%d'),
                'latest_scan_id': info.get('latest_scan_id'),
                'latest_scan_source': info.get('latest_scan_source', 'unknown'),
                'web_scans': info.get('web_scans', 0),
                'github_actions_scans': info.get('github_actions_scans', 0),
                'other_scans': info.get('other_scans', 0),
                'grade': latest_grade
            })

    # Sort descending by scan count, then latest scan date descending, then alphabetically by project name
    projects_list.sort(key=lambda p: p['project_name'].lower())
    projects_list.sort(key=lambda p: p['latest_scan'], reverse=True)
    projects_list.sort(key=lambda p: p['scan_count'], reverse=True)

    # Filter grade output if grade visibility is disabled
    show_grades = app.config['SHOW_GRADES_PUBLICLY']
    for p in projects_list:
        if not show_grades:
            p['grade'] = None

    return jsonify({
        'projects': projects_list,
        'show_grades': show_grades
    })


@app.route('/api/feedback', methods=['POST'])
def submit_feedback():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    rating = data.get('rating')
    review = data.get('review')
    contact = data.get('contact', 'Not provided')
    
    if not rating or not review:
        return jsonify({'error': 'Rating and review are required'}), 400
    
    feedback_entry = {
        'id': str(uuid.uuid4()),
        'timestamp': os.popen('date -u +"%Y-%m-%dT%H:%M:%SZ"').read().strip(),
        'rating': rating,
        'review': review,
        'contact': contact
    }

    try:
        reviews = []
        if os.path.exists(app.config['FEEDBACK_FILE']):
            with open(app.config['FEEDBACK_FILE'], 'r') as f:
                try:
                    reviews = json.load(f)
                except json.JSONDecodeError:
                    reviews = []
        
        reviews.append(feedback_entry)
        
        with open(app.config['FEEDBACK_FILE'], 'w') as f:
            json.dump(reviews, f, indent=4)
        
        return jsonify({'message': 'Feedback saved successfully'}), 200
    except Exception as e:
        print(f"Error saving feedback: {str(e)}")
        return jsonify({'error': f"Failed to save feedback: {str(e)}"}), 500

@app.route('/api/subscribe', methods=['POST'])
def subscribe_newsletter():
    data = request.get_json()
    if not data or not data.get('email'):
        return jsonify({'error': 'Email is required'}), 400
    
    email = data.get('email').strip()
    
    subscriber_node = {
        'id': str(uuid.uuid4()),
        'email': email,
        'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
        'subscribed_via': 'web-modal'
    }

    try:
        subscribers = []
        if os.path.exists(app.config['SUBSCRIBERS_FILE']):
            with open(app.config['SUBSCRIBERS_FILE'], 'r') as f:
                try:
                    subscribers = json.load(f)
                except json.JSONDecodeError:
                    subscribers = []
        
        # Check if email already exists
        if any(s['email'] == email for s in subscribers):
             return jsonify({'message': 'Already subscribed!'}), 200

        subscribers.append(subscriber_node)
        
        with open(app.config['SUBSCRIBERS_FILE'], 'w') as f:
            json.dump(subscribers, f, indent=4)
        
        # Send Slack notification if configured
        if app.config['SLACK_WEBHOOK_URL']:
            send_slack_notification(f"✉️ New Newsletter Subscriber: *{email}*")

        return jsonify({'message': 'Subscribed successfully'}), 200
    except Exception as e:
        print(f"Error in subscription: {str(e)}")
        return jsonify({'error': 'Failed to complete subscription'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)