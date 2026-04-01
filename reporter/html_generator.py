import os
import json
import base64
import re

def generate_standalone_html(report_dict):
    """
    Generate a standalone HTML report by embedding CSS, JS, and JSON data
    into the existing index.html template.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Paths to assets
    template_path = os.path.join(base_dir, 'templates', 'index.html')
    css_path = os.path.join(base_dir, 'static', 'style.css')
    js_path = os.path.join(base_dir, 'static', 'app.js')
    logo_path = os.path.join(base_dir, 'static', 'images', 'soldevelo.png')
    
    # Read files
    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
            
        with open(css_path, 'r', encoding='utf-8') as f:
            css_content = f.read()
            
        with open(js_path, 'r', encoding='utf-8') as f:
            js_content = f.read()
            
        with open(logo_path, 'rb') as f:
            logo_b64 = base64.b64encode(f.read()).decode('utf-8')
    except Exception as e:
        import logging
        logging.error(f"Failed to read assets for HTML generation: {e}")
        return f"<html><body><h1>Error generating HTML report</h1><p>{str(e)}</p></body></html>"

    # Convert JSON data to string
    json_data_str = json.dumps(report_dict)

    # Replace template tags with inline content using regex for robustness
    
    # CSS Replacement
    css_pattern = r'<link[^>]*href=["\'].*?style\.css.*?["\'][^>]*>'
    html_content = re.sub(
        css_pattern, 
        lambda m: f'<style>\n{css_content}\n</style>', 
        html_content
    )
    
    # JS Replacement - inject data BEFORE the actual app logic
    js_pattern = r'<script[^>]*src=["\'].*?app\.js.*?["\'][^>]*>\s*</script>'
    injected_script = f"""
    <script>
        window.CLI_INJECTED_DATA = {json_data_str};
        {js_content}
    </script>
    """
    html_content = re.sub(js_pattern, lambda m: injected_script, html_content)
    
    # Images (base64) - replace all occurrences
    logo_tag_pattern = r'\{\{\s*url_for\([\'"]static[\'"],\s*filename=[\'"]images/soldevelo\.png[\'"]\)\s*\}\}'
    logo_data_uri = f"data:image/png;base64,{logo_b64}"
    html_content = re.sub(logo_tag_pattern, lambda m: logo_data_uri, html_content)
    
    # Links
    index_tag_pattern = r'\{\{\s*url_for\([\'"]index[\'"]\)\s*\}\}'
    html_content = re.sub(index_tag_pattern, lambda m: "#", html_content)
    
    # Clean up Jinja blocks (raw/endraw)
    html_content = re.sub(r'\{%\s*(raw|endraw)\s*%\}', "", html_content)
    
    # Clean up any remaining Jinja tags that might break things (static_version etc)
    # This now handles tags with spaces, dots, or calls like {{ something(...) }}
    html_content = re.sub(r'\{\{\s*.*?\s*\}\}', "", html_content)
    
    return html_content
