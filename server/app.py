from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import zipfile
from pathlib import Path
import shutil
from androguard.core.apk import APK

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = 'uploads'
EXTRACT_FOLDER = 'extracted'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(EXTRACT_FOLDER, exist_ok=True)

def is_safe_path(base_path, target_path):
    base = Path(base_path).resolve()
    target = Path(target_path).resolve()
    try:
        target.relative_to(base)
        return True
    except ValueError:
        return False

def safe_extract(zip_ref, extract_path):
    for member_info in zip_ref.infolist():
        member_path = os.path.join(extract_path, member_info.filename)
        
        if not is_safe_path(extract_path, member_path):
            raise Exception(f"Unsafe path in zip: {member_info.filename}")
        
        if member_info.is_dir():
            os.makedirs(member_path, exist_ok=True)
        else:
            if member_info.external_attr >> 16 & 0o170000 == 0o120000:
                raise Exception(f"Symlinks are not allowed: {member_info.filename}")
            
            os.makedirs(os.path.dirname(member_path), exist_ok=True)
            with zip_ref.open(member_info) as source, open(member_path, 'wb') as target:
                shutil.copyfileobj(source, target)

def parse_manifest_with_androguard(apk_path):
    try:
        apk = APK(apk_path)
        
        package_name = apk.get_package() or 'Unknown'
        version_code = apk.get_androidversion_code() or 'Unknown'
        version_name = apk.get_androidversion_name() or 'Unknown'
        
        permissions = apk.get_permissions() or []
        activities = apk.get_activities() or []
        
        return {
            'package': package_name,
            'versionCode': str(version_code),
            'versionName': version_name,
            'permissions': permissions,
            'activities': activities
        }
    except Exception as e:
        return {'error': f'Failed to parse manifest: {str(e)}'}

def build_file_tree(base_path, current_path=None):
    if current_path is None:
        current_path = base_path
    
    tree = []
    try:
        for item in sorted(os.listdir(current_path)):
            item_path = os.path.join(current_path, item)
            rel_path = os.path.relpath(item_path, base_path)
            
            if os.path.isdir(item_path):
                tree.append({
                    'name': item,
                    'type': 'directory',
                    'path': rel_path,
                    'children': build_file_tree(base_path, item_path)
                })
            else:
                tree.append({
                    'name': item,
                    'type': 'file',
                    'path': rel_path,
                    'size': os.path.getsize(item_path)
                })
    except Exception as e:
        pass
    return tree

@app.route('/api/upload', methods=['POST'])
def upload_apk():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.filename.endswith('.apk'):
        return jsonify({'error': 'File must be an APK'}), 400
    
    filepath = None
    extract_path = None
    
    try:
        filename = os.path.basename(file.filename)
        safe_filename = ''.join(c for c in filename if c.isalnum() or c in ('_', '-', '.'))
        filepath = os.path.join(UPLOAD_FOLDER, safe_filename)
        file.save(filepath)
        
        extract_name = safe_filename.replace('.apk', '')
        extract_path = os.path.join(EXTRACT_FOLDER, extract_name)
        
        if os.path.exists(extract_path):
            shutil.rmtree(extract_path)
        os.makedirs(extract_path)
        
        with zipfile.ZipFile(filepath, 'r') as zip_ref:
            safe_extract(zip_ref, extract_path)
        
        manifest_info = parse_manifest_with_androguard(filepath)
        
        file_tree = build_file_tree(extract_path)
        
        file_list = []
        for root, dirs, files in os.walk(extract_path):
            for f in files:
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, extract_path)
                file_list.append({
                    'path': rel_path,
                    'size': os.path.getsize(full_path)
                })
        
        return jsonify({
            'success': True,
            'filename': safe_filename,
            'extractId': extract_name,
            'manifestInfo': manifest_info,
            'fileTree': file_tree,
            'fileCount': len(file_list),
            'totalSize': sum(f['size'] for f in file_list)
        })
    
    except Exception as e:
        if extract_path and os.path.exists(extract_path):
            shutil.rmtree(extract_path)
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': str(e)}), 500

@app.route('/api/download/<extract_id>/<path:filepath>')
def download_file(extract_id, filepath):
    try:
        safe_extract_id = ''.join(c for c in extract_id if c.isalnum() or c in ('_', '-', '.'))
        extract_base = os.path.join(EXTRACT_FOLDER, safe_extract_id)
        
        full_path = os.path.join(extract_base, filepath)
        
        if not is_safe_path(extract_base, full_path):
            return jsonify({'error': 'Invalid file path'}), 403
        
        if os.path.exists(full_path) and os.path.isfile(full_path):
            return send_file(full_path, as_attachment=True, download_name=os.path.basename(filepath))
        return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/docs/<filename>')
def get_document(filename):
    try:
        safe_filename = ''.join(c for c in filename if c.isalnum() or c in ('_', '-', '.'))
        
        if not safe_filename.endswith('.md'):
            return jsonify({'error': 'Only markdown files allowed'}), 400
        
        doc_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), safe_filename)
        
        if os.path.exists(doc_path) and os.path.isfile(doc_path):
            with open(doc_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return content, 200, {'Content-Type': 'text/markdown; charset=utf-8'}
        
        return jsonify({'error': 'Document not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
