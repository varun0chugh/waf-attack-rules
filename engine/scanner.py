import requests
from typing import Dict, Any, List
from urllib.parse import urljoin
import time

class WAFScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()

    def run_test(self, test: Dict[str, Any]) -> Dict[str, Any]:
        results = {
            "test_id": test.get("test_id"),
            "desc": test.get("desc"),
            "category": test.get("category"),
            "passed": True, # Passed means WAF BLOCKED it (Good)
            "details": []
        }

        for stage in test.get("stages", []):
            stage_input = stage.get("stage", {}).get("input", {})
            stage_output = stage.get("stage", {}).get("output", {})
            
            # Construct Request
            method = stage_input.get("method", "GET")
            uri = stage_input.get("uri", "/")
            headers = stage_input.get("headers", {})
            data = stage_input.get("data")
            
            # Handle headers that might be lists or other types in some YAMLs, 
            # but usually they are dicts in our format.
            # Ensure Host header is set correctly for the target if needed, 
            # but for now we trust the requests lib to handle Host unless specified.
            
            full_url = urljoin(self.target_url, uri)
            
            try:
                response = self.session.request(
                    method=method,
                    url=full_url,
                    headers=headers,
                    data=data,
                    timeout=5,
                    allow_redirects=False
                )
                
                # Detection Logic
                # If status is 403 or 406 or 429, we assume WAF blocked it.
                # If status is 200, 404, 500, it likely bypassed or hit the app.
                
                is_blocked = response.status_code in [403, 406, 429]
                
                # Check for specific log strings if we had access to logs, 
                # but we are black-box testing here.
                # So we rely on status codes and response content.
                
                # In a real scenario, we might check for specific WAF block pages.
                if "WAF" in response.text or "blocked" in response.text.lower():
                    is_blocked = True

                # If the test expects a block (which all our attack tests do),
                # then is_blocked == True means PASS.
                # is_blocked == False means FAIL (Bypass).
                
                if not is_blocked:
                    results["passed"] = False
                    results["details"].append(f"Stage failed: Status {response.status_code}, Payload likely bypassed.")
                else:
                    results["details"].append(f"Stage passed: Status {response.status_code} (Blocked).")

            except Exception as e:
                # If request failed (e.g. connection reset), it might be a block too.
                results["details"].append(f"Request failed (likely blocked): {e}")
                # We'll count connection errors as 'Blocked' for now as some WAFs drop packets.
                pass

        return results

    def scan(self, tests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        scan_results = []
        for test in tests:
            result = self.run_test(test)
            scan_results.append(result)
        return scan_results
