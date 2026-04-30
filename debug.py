import sys
import json
import os

sys.path.append(r'c:\Users\mo663\OneDrive\Desktop\MALTRACER')
from detection_engine.rule_parser import load_rules
from detection_engine.rule_engine import RuleEngine

event_str_data = '{"event_type": "executable_modified", "source": "C:\\\\Users\\\\mo663\\\\Desktop\\\\malware.exe", "destination": "C:\\\\Users\\\\mo663\\\\Desktop\\\\malware.exe", "file_hash": "dummyhash", "file_size_kb": 12}'
event = json.loads(event_str_data)

base_dir = r'c:\Users\mo663\OneDrive\Desktop\MALTRACER\detection_engine'
rules = []
rules += load_rules(os.path.join(base_dir, 'rules', 'network.rules'))
rules += load_rules(os.path.join(base_dir, 'rules', 'process.rules'))
rules += load_rules(os.path.join(base_dir, 'rules', 'file.rules'))

engine = RuleEngine()
matched = engine.match(event, rules)
print("Matched Rules:", matched)
score = sum(r.get('score',0) for r in matched)
print("Total Score:", score)
