import yara
import os

class YaraManager:
    def __init__(self, rules_dir='yara_rules'):
        self.rules_dir = rules_dir
        self.rules = self._compile_rules()

    def _compile_rules(self):
        rule_files = {
            'packed': os.path.join(self.rules_dir, 'packed_files.yar'),
            'suspicious': os.path.join(self.rules_dir, 'suspicious_strings.yar'),
            'exploits': os.path.join(self.rules_dir, 'exploit_patterns.yar')
        }
        
        try:
            return yara.compile(filepaths=rule_files)
        except yara.SyntaxError as e:
            raise RuntimeError(f"YARA rule error: {str(e)}")

    def scan_file(self, file_path):
        return self.rules.match(file_path)