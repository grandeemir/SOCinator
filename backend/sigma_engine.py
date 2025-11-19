import os
import re
import yaml
from typing import List, Dict
from datetime import datetime

class SigmaEngine:
    def __init__(self, rules_dir: str = "sigma_rules"):
        self.rules_dir = rules_dir
        self.rules = []
        self.load_rules()
    
    def load_rules(self):
        """Load all Sigma rules from the rules directory"""
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir)
            return
        
        for filename in os.listdir(self.rules_dir):
            if filename.endswith('.yml') or filename.endswith('.yaml'):
                rule_path = os.path.join(self.rules_dir, filename)
                try:
                    with open(rule_path, 'r', encoding='utf-8') as f:
                        rule = yaml.safe_load(f)
                        rule['file_path'] = rule_path
                        self.rules.append(rule)
                except Exception as e:
                    print(f"Error loading rule {filename}: {e}")
    
    def scan_logs(self, log_content: str, file_name: str) -> List[Dict]:
        """
        Scan log content against Sigma rules
        Returns list of detection results
        """
        results = []
        log_lines = log_content.split('\n')
        
        for rule in self.rules:
            detections = self._apply_rule(rule, log_lines, file_name)
            results.extend(detections)
        
        return results
    
    def _apply_rule(self, rule: Dict, log_lines: List[str], file_name: str) -> List[Dict]:
        """Apply a single Sigma rule to log lines"""
        detections = []
        
        try:
            # Extract rule metadata
            rule_name = rule.get('title', 'Unknown Rule')
            rule_id = rule.get('id', '')
            description = rule.get('description', '')
            
            # Extract MITRE ATT&CK tags
            tags = rule.get('tags', [])
            mitre_ids = [tag for tag in tags if tag.startswith('attack.')]
            # Handle both attack.t1059.001 and attack.t1059 formats
            mitre_id = mitre_ids[0].replace('attack.', '').split('.')[0] if mitre_ids else 'N/A'
            
            # Extract severity
            level = rule.get('level', 'medium').lower()
            severity_map = {
                'critical': 'High',
                'high': 'High',
                'medium': 'Medium',
                'low': 'Low',
                'informational': 'Low'
            }
            severity = severity_map.get(level, 'Medium')
            
            # Extract detection patterns
            detection = rule.get('detection', {})
            if not detection:
                return detections
            
            # Simple pattern matching (can be enhanced with proper Sigma parser)
            patterns = self._extract_patterns(detection)
            
            if not patterns:
                return detections
            
            # Scan log lines
            for line_num, line in enumerate(log_lines, 1):
                line_lower = line.lower()
                for pattern in patterns:
                    if pattern.search(line_lower):
                        matched_text = pattern.search(line_lower).group(0) if pattern.search(line_lower) else line[:100]
                        
                        detections.append({
                            'rule_name': rule_name,
                            'detected_pattern': matched_text[:200],  # Limit length
                            'mitre_attack_id': mitre_id,
                            'severity': severity,
                            'is_false_positive': False,  # Can be enhanced with FP detection
                            'rule_type': 'Sigma',
                            'timestamp': datetime.now().isoformat(),
                            'line_number': line_num,
                            'rule_id': rule_id,
                            'description': description
                        })
                        break  # One detection per line per rule
        
        except Exception as e:
            print(f"Error applying rule {rule.get('title', 'Unknown')}: {e}")
        
        return detections
    
    def _extract_patterns(self, detection: Dict) -> List[re.Pattern]:
        """Extract regex patterns from Sigma detection"""
        patterns = []
        
        # Handle different detection structures
        for key, value in detection.items():
            if isinstance(value, dict):
                # Handle conditions like 'selection', 'filter', etc.
                if 'selection' in value:
                    patterns.extend(self._extract_patterns(value['selection']))
                elif isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        if isinstance(sub_value, (str, list)):
                            patterns.extend(self._pattern_from_value(sub_value))
            elif isinstance(value, (str, list)):
                patterns.extend(self._pattern_from_value(value))
        
        return patterns
    
    def _pattern_from_value(self, value) -> List[re.Pattern]:
        """Convert value to regex pattern"""
        patterns = []
        
        if isinstance(value, str):
            # Simple keyword matching - escape special chars but allow word boundaries
            escaped = re.escape(value)
            # Use word boundary for better matching
            pattern_str = r'\b' + escaped + r'\b'
            patterns.append(re.compile(pattern_str, re.IGNORECASE))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    escaped = re.escape(item)
                    pattern_str = r'\b' + escaped + r'\b'
                    patterns.append(re.compile(pattern_str, re.IGNORECASE))
        
        return patterns
    
    def get_rules_info(self) -> List[Dict]:
        """Get information about all loaded rules"""
        return [
            {
                'name': rule.get('title', 'Unknown'),
                'id': rule.get('id', ''),
                'severity': rule.get('level', 'medium'),
                'mitre_attack_id': [tag.replace('attack.', '') for tag in rule.get('tags', []) if tag.startswith('attack.')]
            }
            for rule in self.rules
        ]

