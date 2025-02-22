from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from utils.yara_manager import YaraManager
from utils.file_analysis import (
    PEAnalyzer,
    PDFAnalyzer,
    DOCXAnalyzer
)
from utils.security import validate_file, calculate_entropy
import tempfile
import os

app = Flask(__name__)
yara = YaraManager()
analyzers = {
    'application/x-msdownload': PEAnalyzer(),
    'application/pdf': PDFAnalyzer(),
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': DOCXAnalyzer()
}

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
        
    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({'error': 'Invalid file'}), 400

    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            file.save(tmp_file.name)
            valid, message = validate_file(tmp_file.name)
            if not valid:
                return jsonify({'error': message}), 400

            # Perform analysis
            result = {
                'verdict': 'Clean',
                'score': 0,
                'findings': [],
                'metadata': {
                    'file_type': magic.from_file(tmp_file.name, mime=True),
                    'sha256': hashlib.sha256(file.read()).hexdigest()
                }
            }
            
            # YARA Analysis
            yara_matches = yara.scan_file(tmp_file.name)
            if yara_matches:
                result['score'] += len(yara_matches) * 20
                result['findings'].extend([
                    f"YARA: {m.rule} (tags: {', '.join(m.tags)})" 
                    for m in yara_matches
                ])
            
            # File-Type Specific Analysis
            analyzer = analyzers.get(result['metadata']['file_type'])
            if analyzer:
                analysis_result = analyzer.analyze(tmp_file.name)
                result['score'] += analysis_result['score']
                result['findings'].extend(analysis_result['findings'])
            
            # Entropy Check
            entropy = calculate_entropy(tmp_file.name)
            if entropy > 7.5:
                result['score'] += 25
                result['findings'].append(f"High entropy detected: {entropy:.2f}")
            
            # Determine Verdict
            if result['score'] >= 75:
                result['verdict'] = 'Malicious'
            elif result['score'] >= 40:
                result['verdict'] = 'Suspicious'
            
            return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if os.path.exists(tmp_file.name):
            os.remove(tmp_file.name)