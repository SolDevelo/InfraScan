import os
import shutil
import tempfile
import uuid
import json
import time
from flask import Flask, render_template, request, jsonify, send_from_directory
from urllib.parse import urlparse
import requests
from dotenv import load_dotenv
from git import Repo
from scanner.parser import scan_directory, get_container_scanner, is_container_scanner_available
from scanner.checkov_scanner import is_checkov_available
from scanner.docker_scout_scanner import is_docker_scout_available
from scanner.grype_scanner import is_grype_available
from reporter.grading import ReportGenerator

load_dotenv()

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['RESULTS_DIR'] = os.path.join(os.getcwd(), 'scan_results')
app.config['FEEDBACK_FILE'] = os.path.join(os.getcwd(), 'feedback', 'reviews.json')
app.config['SLACK_WEBHOOK_URL'] = os.getenv('SLACK_WEBHOOK_URL', '')

# Cache busting - changes on each deployment/restart
STATIC_VERSION = str(int(time.time()))

# Ensure results and feedback directories exist
os.makedirs(app.config['RESULTS_DIR'], exist_ok=True)
os.makedirs(os.path.dirname(app.config['FEEDBACK_FILE']), exist_ok=True)

@app.context_processor
def inject_static_version():
    """Make static version available in all templates for cache busting."""
    return {'static_version': STATIC_VERSION}

def get_slack_webhook_url() -> str:
    return os.getenv('SLACK_WEBHOOK_URL', '').strip()

def build_share_url(result_id: str, req) -> str:
    referer = req.headers.get('Referer') if req else None
    if referer:
        parsed = urlparse(referer)
        origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""
        path = parsed.path or ""
        if origin:
            return f"{origin}{path}?scan_id={result_id}"

    origin = req.headers.get('Origin') if req else None
    if origin:
        return f"{origin}/?scan_id={result_id}"

    if req and req.host_url:
        return f"{req.host_url.rstrip('/')}/?scan_id={result_id}"

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
    return render_template('index.html')

@app.route('/robots.txt')
@app.route('/sitemap.xml')
def static_from_root():
    return send_from_directory(app.static_folder, request.path[1:])

@app.route('/api/scanner/status')
def scanner_status():
    """Return information about available scanners."""
    checkov_available = is_checkov_available()
    container_scanner = get_container_scanner()
    container_scanner_available = is_container_scanner_available()
    
    # For backwards compatibility, also expose individual scanner status
    docker_scout_available = is_docker_scout_available()
    grype_available = is_grype_available()
    
    return jsonify({
        'regex': True,  # Always available
        'checkov': checkov_available,
        'container_scanner': container_scanner,  # Which scanner is configured
        'containers': container_scanner_available,  # Is the configured scanner available
        'docker_scout': docker_scout_available,
        'grype': grype_available,
        'comprehensive': checkov_available or container_scanner_available  # Can run comprehensive if any security scanner available
    })

@app.route('/api/scan/github', methods=['POST'])
def scan_github():
    data = request.get_json()
    repo_url = data.get('url')
    scanner_type = data.get('scanner', 'regex')  # Default to regex scanner
    recipient = data.get('recipient', '')  # Optional recipient field
    is_private = data.get('is_private', False)  # Optional private scan flag
    
    if not repo_url:
        return jsonify({'error': 'No URL provided'}), 400
    
    # Strip query parameters and hash fragments from URL
    repo_url = repo_url.split('?')[0].split('#')[0]
    
    # Validate scanner type
    valid_scanners = ['regex', 'fast', 'checkov', 'containers', 'comprehensive', 'both']  # 'both' for backwards compatibility
    if scanner_type not in valid_scanners:
        return jsonify({'error': f'Invalid scanner type. Must be one of: {valid_scanners}'}), 400
    
    # Normalize 'both' to 'comprehensive' for backwards compatibility
    if scanner_type == 'both':
        scanner_type = 'comprehensive'
    
    # Check if Checkov is requested but not available
    if scanner_type in ['checkov', 'comprehensive'] and not is_checkov_available():
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
                Repo.clone_from(repo_url, temp_dir, depth=1)
                clone_success.set()
            except Exception as e:
                clone_error = e
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
        results, resource_count, recommendations = scan_directory(temp_dir, scanner_type=scanner_type, framework='terraform')
        
        # Generate comprehensive report with grades
        report_generator = ReportGenerator()
        report = report_generator.generate_report(
            findings=results,
            resource_count=resource_count,
            scanner_type=scanner_type,
            extra_recommendations=recommendations
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
            'recipient': recipient,
            'scan_timestamp': scan_timestamp,
            'is_private': is_private
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
        recipient_line = f" | Recipient: {recipient}" if recipient else ""
        
        # Build findings summary
        findings_parts = [f"Cost {cost_findings}", f"Security {security_findings}"]
        if container_findings > 0:
            findings_parts.append(f"Containers {container_findings}")
        findings_summary = ", ".join(findings_parts)
        
        # Build grades summary
        grades_parts = [f"Overall {overall_grade.letter} ({overall_grade.percentage}%)"]
        grades_parts.append(f"Cost {cost_grade.letter} ({cost_grade.percentage}%)")
        grades_parts.append(f"Security {security_grade.letter} ({security_grade.percentage}%)")
        if container_findings > 0:
            grades_parts.append(f"Containers {container_grade.letter} ({container_grade.percentage}%)")
        grades_summary = " ".join(grades_parts)
        
        slack_message = (
            "🔔 InfraScan completed | "
            f"Repo: {repo_url} | "
            f"Grades: {grades_summary} | "
            f"Findings: {total_findings} ({findings_summary}) | "
            f"Resource count: {resource_count} | "
            f"Scanner: {scanner_type}{recipient_line} | "
            f"Time: {scan_timestamp}"
        )
        send_slack_notification(slack_message)
        
        # Legacy compatibility: keep old format fields
        regex_results = [r for r in results if r.get('scanner') == 'regex']
        checkov_results = [r for r in results if r.get('scanner') == 'checkov']
        container_results = [r for r in results if r.get('scanner') == 'docker-scout']
        
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
        'analysis': data.get('analysis')
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
    recipient = metadata.get('recipient', '')
    recipient_line = f" | Recipient: {recipient}" if recipient else ""

    share_url = build_share_url(result_id, request)

    slack_message = (
        "🔗 InfraScan results shared | "
        f"Repo: {repo_url} | "
        f"Share: {share_url}{recipient_line}"
    )
    send_slack_notification(slack_message)
    
    return jsonify({'id': result_id})

@app.route('/api/results/<result_id>', methods=['GET'])
def get_results(result_id):
    # Basic validation of result_id to prevent path traversal
    if not result_id.replace('-', '').isalnum():
        return jsonify({'error': 'Invalid result ID'}), 400
        
    file_path = os.path.join(app.config['RESULTS_DIR'], f"{result_id}.json")
    
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
                'recipient': metadata.get('recipient', ''),
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

    # Return only the 50 most recent
    return jsonify({'scans': scans[:50]})

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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
