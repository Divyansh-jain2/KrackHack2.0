import pefile

class PEAnalyzer:
    SUSPICIOUS_DLLS = {
        'ws2_32.dll', 'wininet.dll', 'kernel32.dll',
        'urlmon.dll', 'shell32.dll'
    }
    MALICIOUS_SECTIONS = {'.crypto', '.packed', '.bind'}

    def analyze(self, file_path):
        findings = []
        try:
            pe = pefile.PE(file_path)
            
            # Section Analysis
            for section in pe.sections:
                name = section.Name.decode().strip('\x00')
                entropy = section.get_entropy()
                
                if entropy > 7.2:
                    findings.append(f"High entropy section ({name}): {entropy:.2f}")
                    
                if any(m in name.lower() for m in self.MALICIOUS_SECTIONS):
                    findings.append(f"Suspicious section name: {name}")

            # Import Table Analysis
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode().lower()
                    if dll in self.SUSPICIOUS_DLLS:
                        imports = [func.name.decode() for func in entry.imports]
                        findings.append(
                            f"Suspicious imports from {dll}: {', '.join(imports)}"
                        )

            # Header Flags Analysis
            characteristics = pe.FILE_HEADER.Characteristics
            if characteristics & 0x2000:  # DLL
                findings.append("File is a DLL (Potential sideloading risk)")
                
            if characteristics & 0x0002:  # Executable
                findings.append("File is executable")

        except Exception as e:
            findings.append(f"PE parsing error: {str(e)}")
            
        return findings