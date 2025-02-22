import os
import magic

ALLOWED_MIME_TYPES = {
    'application/pdf',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/x-msdownload',  # EXE
    'application/octet-stream'   # Fallback
}

MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB

def validate_file(file_path):
    # Check file size
    if os.path.getsize(file_path) > MAX_FILE_SIZE:
        return False
        
    # Verify MIME type
    mime = magic.from_file(file_path, mime=True)
    if mime not in ALLOWED_MIME_TYPES:
        return False
        
    return True