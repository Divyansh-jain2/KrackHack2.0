# services/file_analysis.py
import yara
from pefile import PE
import math

def analyze_file(file_stream, filename):
    try:
        # Read file content
        file_stream.seek(0)
        file_content = file_stream.read()
        
        # Initialize YARA with PE support
        rules = yara.compile(
            filepath='rules/malware_rules.yar',
            modules=['pe'],
            includes=True,
            error_on_warning=True
        )
        
        # Perform YARA scan
        matches = rules.match(data=file_content)
        
        # PE Analysis
        pe_analysis = {}
        if filename.lower().endswith(('.exe', '.dll')):
            pe = PE(data=file_content)
            pe_analysis = {
                'entry_point': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                'suspicious_sections': [
                    {
                        'name': section.Name.decode().strip('\x00'),
                        'entropy': section.get_entropy(),
                        'size': section.SizeOfRawData
                    } 
                    for section in pe.sections
                ]
            }
        
        return {
            'verdict': 'Malicious' if matches else 'Clean',
            'indicators': {
                'yara_matches': [str(m) for m in matches],
                'pe_analysis': pe_analysis
            }
        }
    except Exception as e:
        return {
            'verdict': 'Error',
            'error': str(e)
        }