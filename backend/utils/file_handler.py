# utils/file_handler.py
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'exe', 'dll', 'docx', 'pdf'}

def validate_file(file):
    filename = sanitize_filename(file.filename)  # Sanitize before checking
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitize_filename(filename):
    """Make filenames safe for storage"""
    return secure_filename(filename).replace(' ', '_')