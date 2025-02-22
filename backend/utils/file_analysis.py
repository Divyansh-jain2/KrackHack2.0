import pefile
import math
import yara
import magic
from PyPDF2 import PdfReader
from docx import Document

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(x)/len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return entropy

def analyze_pe(file_path):
    findings = []
    try:
        pe = pefile.PE(file_path)
        
        # Check for suspicious sections
        for section in pe.sections:
            if section.Entropy_H > 7.0:  # High entropy
                findings.append(f"High entropy section ({section.Name.decode().strip()}): {section.Entropy_H}")
                
        # Check suspicious imports
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode().lower()
            if dll in ['ws2_32.dll', 'wininet.dll']:
                findings.append(f"Suspicious DLL import: {dll}")
                
    except Exception as e:
        findings.append(f"PE parsing error: {str(e)}")
    return findings

def analyze_pdf(file_path):
    findings = []
    try:
        with open(file_path, 'rb') as f:
            pdf = PdfReader(f)
            if '/JS' in pdf.pdf_header:
                findings.append("PDF contains JavaScript")
            for page in pdf.pages:
                if '/AA' in page:
                    findings.append("PDF contains automatic actions")
    except:
        pass
    return findings

def analyze_docx(file_path):
    findings = []
    try:
        doc = Document(file_path)
        if doc.core_properties.comments:
            findings.append("Document contains metadata comments")
        # Check for macros (simplified)
        if any(part.content_type == 'application/vnd.ms-word.document.macroEnabled' for part in doc.package.parts):
            findings.append("Document contains macros")
    except:
        pass
    return findings

def analyze_file(file_path, yara_rules):
    result = {
        'verdict': 'Clean',
        'score': 0,
        'findings': [],
        'file_type': magic.from_file(file_path, mime=True)
    }
    
    # YARA rule matches
    matches = yara_rules.match(file_path)
    if matches:
        result['score'] += len(matches) * 10
        result['findings'].extend([str(m) for m in matches])
    
    # File-type specific analysis
    if 'PE32' in result['file_type']:
        result['findings'].extend(analyze_pe(file_path))
    elif 'PDF' in result['file_type']:
        result['findings'].extend(analyze_pdf(file_path))
    elif 'wordprocessing' in result['file_type']:
        result['findings'].extend(analyze_docx(file_path))
    
    # Entropy check
    with open(file_path, 'rb') as f:
        data = f.read(4096)
        entropy = calculate_entropy(data)
        if entropy > 7.5:
            result['findings'].append(f"High entropy detected: {entropy:.2f}")
            result['score'] += 20
    
    # Determine final verdict
    if result['score'] > 30:
        result['verdict'] = 'Malicious'
    elif result['score'] > 15:
        result['verdict'] = 'Suspicious'
        
    return result