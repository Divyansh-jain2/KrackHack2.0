from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import os
import yara
import magic
import pefile
import tempfile
from utils.file_analysis import analyze_file
from utils.security import validate_file
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={
    r"/upload": {
        "origins": "http://localhost:5173",
        "methods": ["POST"],
        "allow_headers": ["Content-Type"]
    }
})

# Configuration
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()
app.config['YARA_RULES'] = os.path.join(os.path.dirname(__file__), 'yara_rules/malware_rules.yar')

# Load YARA rules
rules = yara.compile(app.config['YARA_RULES'])

@app.route('/')
def health_check():
    return jsonify({"status": "Malware Scanner API", "version": "1.0.0"}), 200


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
        
    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({'error': 'Invalid file'}), 400

    # Security checks
    try:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        if not validate_file(file_path):
            return jsonify({'error': 'File validation failed'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    # Analyze the file
    try:
        analysis_result = analyze_file(file_path, rules)
        return jsonify(analysis_result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
        
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

if __name__ == '__main__':
    app.run(debug=True, port=5001)