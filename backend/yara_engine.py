import os
import yara
from typing import List, Dict
from datetime import datetime

class YaraEngine:
    def __init__(self, rules_dir: str = "yara_rules"):
        self.rules_dir = rules_dir
        self.compiled_rules = None
        self.rules_info = []
        self.load_rules()
    
    def load_rules(self):
        """Load and compile all YARA rules"""
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir)
            return
        
        rule_files = {}
        rule_paths = []
        
        for filename in os.listdir(self.rules_dir):
            if filename.endswith('.yar') or filename.endswith('.yara'):
                rule_path = os.path.join(self.rules_dir, filename)
                rule_paths.append(rule_path)
                rule_files[filename] = rule_path
        
        if rule_files:
            try:
                self.compiled_rules = yara.compile(filepaths=rule_files)
                # Load rule metadata
                self._load_rules_metadata(rule_paths)
            except Exception as e:
                print(f"Error compiling YARA rules: {e}")
                self.compiled_rules = None
    
    def _load_rules_metadata(self, rule_paths: List[str]):
        """Extract metadata from YARA rule files"""
        self.rules_info = []
        
        for rule_path in rule_paths:
            try:
                with open(rule_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Extract rule name and metadata
                    rule_name = None
                    mitre_id = None
                    severity = 'Medium'
                    description = ''
                    
                    lines = content.split('\n')
                    for i, line in enumerate(lines):
                        if line.strip().startswith('rule '):
                            rule_name = line.split('rule ')[1].split('{')[0].strip()
                        elif 'mitre_attack_id' in line.lower():
                            # Extract MITRE ID from comment or meta
                            mitre_id = self._extract_mitre_id(line)
                        elif 'severity' in line.lower() or 'level' in line.lower():
                            severity = self._extract_severity(line)
                        elif 'description' in line.lower():
                            description = self._extract_description(lines, i)
                    
                    self.rules_info.append({
                        'name': rule_name or os.path.basename(rule_path),
                        'mitre_attack_id': mitre_id or 'N/A',
                        'severity': severity,
                        'description': description
                    })
            except Exception as e:
                print(f"Error loading metadata from {rule_path}: {e}")
    
    def _extract_mitre_id(self, line: str) -> str:
        """Extract MITRE ATT&CK ID from line"""
        # Look for patterns like T1055, T1003, etc.
        import re
        match = re.search(r'T\d{4}', line)
        return match.group(0) if match else 'N/A'
    
    def _extract_severity(self, line: str) -> str:
        """Extract severity from line"""
        line_lower = line.lower()
        if 'high' in line_lower or 'critical' in line_lower:
            return 'High'
        elif 'medium' in line_lower:
            return 'Medium'
        elif 'low' in line_lower:
            return 'Low'
        return 'Medium'
    
    def _extract_description(self, lines: List[str], start_idx: int) -> str:
        """Extract description from rule file"""
        description = ''
        for i in range(start_idx, min(start_idx + 5, len(lines))):
            if 'description' in lines[i].lower():
                desc_line = lines[i].split('description')[1].strip(' :"\'')
                if desc_line:
                    description = desc_line
                    break
        return description
    
    def scan_file(self, file_content: bytes, file_name: str) -> List[Dict]:
        """
        Scan file content with YARA rules
        Returns list of detection results
        """
        results = []
        
        if not self.compiled_rules:
            return results
        
        try:
            matches = self.compiled_rules.match(data=file_content)
            
            for match in matches:
                rule_name = match.rule
                matched_strings = [str(ms) for ms in match.strings]
                matched_pattern = ', '.join(matched_strings[:3])  # First 3 matches
                
                # Get rule metadata
                rule_meta = next(
                    (r for r in self.rules_info if r['name'] == rule_name),
                    {'mitre_attack_id': 'N/A', 'severity': 'Medium', 'description': ''}
                )
                
                results.append({
                    'rule_name': rule_name,
                    'detected_pattern': matched_pattern,
                    'mitre_attack_id': rule_meta['mitre_attack_id'],
                    'severity': rule_meta['severity'],
                    'is_false_positive': False,
                    'rule_type': 'YARA',
                    'timestamp': datetime.now().isoformat(),
                    'file_name': file_name,
                    'description': rule_meta['description']
                })
        
        except Exception as e:
            print(f"Error scanning file with YARA: {e}")
        
        return results
    
    def get_rules_info(self) -> List[Dict]:
        """Get information about all loaded YARA rules"""
        return self.rules_info

