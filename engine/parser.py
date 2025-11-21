import yaml
import os
from typing import List, Dict, Any

class AttackParser:
    def __init__(self, attacks_dir: str):
        self.attacks_dir = attacks_dir

    def load_tests(self) -> List[Dict[str, Any]]:
        tests = []
        for root, _, files in os.walk(self.attacks_dir):
            for file in files:
                if file.endswith(".yaml") or file.endswith(".yml"):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r') as f:
                            data = yaml.safe_load(f)
                            if data and 'tests' in data:
                                for test in data['tests']:
                                    # Add metadata to the test for reporting
                                    test['category'] = os.path.basename(root)
                                    test['file'] = file
                                    tests.append(test)
                    except Exception as e:
                        print(f"Error loading {file_path}: {e}")
        return tests
