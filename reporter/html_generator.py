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

    # Convert JSON data to string and escape closing script tags to avoid breaking the HTML
    # Convert JSON data to string and encode as Base64 to avoid all HTML/JS quoting issues
    json_data_str = json.dumps(report_dict, separators=(',', ':'))
    json_b64 = base64.b64encode(json_data_str.encode('utf-8')).decode('utf-8')

    # Replace template tags with inline content using regex for robustness
    
    # CSS Replacement
    css_pattern = r'<link[^>]*href=["\'].*?style\.css.*?["\'][^>]*>'
    html_content = re.sub(
        css_pattern, 
        lambda m: f'<style>\n{css_content}\n</style>', 
        html_content
    )
    
    # Images (base64) - replace all occurrences
    logo_tag_pattern = r'\{\{\s*url_for\([\'"]static[\'"],\s*filename=[\'"]images/soldevelo\.png[\'"]\)\s*\}\}'
    logo_data_uri = f"data:image/png;base64,{logo_b64}"
    html_content = re.sub(logo_tag_pattern, lambda m: logo_data_uri, html_content)
    
    # Links
    index_tag_pattern = r'\{\{\s*url_for\([\'"]index[\'"]\)\s*\}\}'
    html_content = re.sub(index_tag_pattern, lambda m: "#", html_content)
    
    # Clean up Jinja blocks (raw/endraw) BEFORE injecting data to avoid corrupting findings
    html_content = re.sub(r'\{%\s*(raw|endraw)\s*%\}', "", html_content)
    
    # Protect the app.js script tag from generic cleanup
    js_placeholder = "<!-- APP_JS_PLACEHOLDER -->"
    js_pattern = r'<script[^>]*src=["\'].*?app\.js.*?["\'][^>]*>\s*</script>'
    html_content = re.sub(js_pattern, js_placeholder, html_content)

    # Clean up ALL remaining Jinja tags (static_version etc)
    # This must happen before data injection
    html_content = re.sub(r'\{\{\s*.*?\s*\}\}', "", html_content)
    
    # NOW inject the JS content and the actual data
    # Use a safe way to build the script tag without f-string interpolation issues for JS content
    injected_script = "<script>\n"
    injected_script += f"    window.CLI_INJECTED_DATA_B64 = \"{json_b64}\";\n"
    injected_script += f"    {js_content}\n"
    injected_script += "</script>"
    
    html_content = html_content.replace(js_placeholder, injected_script)
    
    return html_content
