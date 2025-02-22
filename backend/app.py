from flask import Flask, request, jsonify
from utils.file_handler import validate_file, sanitize_filename
from services.file_analysis import analyze_file
from flask_cors import CORS  # Add this import

app = Flask(__name__)
CORS(app, resources={r"/scan": {"origins": "http://localhost:5173"}})  # Enable CORS

@app.route('/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
        
    file = request.files['file']
    
    # Sanitize and validate before processing
    original_name = sanitize_filename(file.filename)
    
    if not validate_file(file):
        return jsonify({'error': 'Invalid file type'}), 400

    try:
        # Use sanitized name for any storage/processing
        result = analyze_file(file.stream,filename=original_name)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5001)  # Change the port here