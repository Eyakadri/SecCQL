from urllib.parse import urljoin
import requests
import logging
from typing import Dict, List, Optional, Union

class CSRFScanner:
    def __init__(self, driver=None):
        self.driver = driver
        self.csrf_tokens = set()
        self.logger = logging.getLogger(__name__)

    def analyze_form(self, form: Dict, base_url: str) -> Dict:
        """
        Analyze a HTML form for CSRF vulnerabilities
        
        Args:
            form: Dictionary containing 'action' and 'inputs' keys
            base_url: Base URL of the website
            
        Returns:
            Dictionary with vulnerability analysis results
        """
        if not isinstance(form, dict) or "action" not in form or "inputs" not in form:
            self.logger.error(f"Invalid form structure: {form}")
            return {"vulnerable": False, "reason": "Invalid form structure"}

        target_url = urljoin(base_url, form.get("action", ""))
        if not target_url.strip():
            self.logger.error("Invalid or empty form action URL.")
            return {"vulnerable": False, "reason": "Empty form action"}

        # Check for CSRF token in form inputs
        csrf_fields = [input for input in form["inputs"] 
                      if input.get("name", "").lower() in ["csrf", "csrf_token", "_token", "authenticity_token"]]
        
        # Prepare test data
        test_data = {
            input["name"]: "test_value" 
            for input in form["inputs"] 
            if "name" in input and input.get("type") != "hidden"
        }

        results = {
            "url": target_url,
            "has_csrf_field": bool(csrf_fields),
            "vulnerable": False,
            "tests": []
        }

        # Test 1: Request with valid CSRF token (if available)
        if csrf_fields:
            try:
                response = requests.post(target_url, data=test_data)
                results["tests"].append({
                    "test_type": "with_csrf_token",
                    "status": response.status_code,
                    "vulnerable": False  # This is the expected case
                })
            except Exception as e:
                self.logger.error(f"Error testing with CSRF token: {e}")

        # Test 2: Request without CSRF token
        test_data_no_csrf = {
            k: v for k, v in test_data.items() 
            if not k.lower() in ["csrf", "csrf_token", "_token", "authenticity_token"]
        }
        
        try:
            response = requests.post(target_url, data=test_data_no_csrf)
            vulnerable = response.status_code in [200, 302] and "error" not in response.text.lower()
            results["tests"].append({
                "test_type": "without_csrf_token",
                "status": response.status_code,
                "vulnerable": vulnerable
            })
            results["vulnerable"] = vulnerable
        except Exception as e:
            self.logger.error(f"Error testing without CSRF token: {e}")

        return results

    def check_protections(self, response: requests.Response) -> Dict:
        """
        Check response for anti-CSRF protections
        
        Args:
            response: requests.Response object
            
        Returns:
            Dictionary of detected protections
        """
        protections = {
            "headers": {},
            "cookies": {},
            "csrf_in_body": False
        }
        
        # Check headers
        for header in ["x-csrf-token", "x-xsrf-token", "csrf-token", "x-csrf-protection"]:
            if header in response.headers:
                protections["headers"][header] = response.headers[header]
        
        # Check cookies
        for cookie in response.cookies:
            if "csrf" in cookie.name.lower():
                protections["cookies"][cookie.name] = cookie.value
                
        # Check for CSRF token in response body
        if response.text:
            protections["csrf_in_body"] = any(
                token in response.text.lower() 
                for token in ["csrf_token", "_csrf", "authenticity_token"]
            )
                
        return protections

    def generate_payloads(self) -> List[Dict]:
        """Generate comprehensive CSRF test payloads"""
        return [
            {},  # No token at all
            {"csrf_token": ""},  # Empty token
            {"csrf_token": "invalid"},  # Invalid token
            {"_csrf": "test"},  # Common alternative name
            {"authenticity_token": "test"},  # Rails-style
            {"token": "test"},  # Generic name
            {"security_token": "test"}  # Another common variant
        ]

    def scan_endpoint(self, url: str, session: Optional[requests.Session] = None) -> Dict:
        """
        Scan a specific endpoint for CSRF vulnerabilities
        
        Args:
            url: URL to test
            session: Optional authenticated session
            
        Returns:
            Detailed scan results
        """
        if session is None:
            session = requests.Session()

        results = {
            "url": url,
            "vulnerable": False,
            "protections": {},
            "tests": []
        }

        # First get request to check protections
        try:
            initial_response = session.get(url)
            results["protections"] = self.check_protections(initial_response)
        except Exception as e:
            self.logger.error(f"Error in initial GET request: {e}")
            return results

        # Test with each payload
        for payload in self.generate_payloads():
            test_result = {
                "payload": payload,
                "status": None,
                "vulnerable": False,
                "error": None
            }

            try:
                response = session.post(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )

                test_result["status"] = response.status_code
                
                # Consider vulnerable if:
                # - Returns 200 with no error message
                # - Returns 302 redirect (unless to login)
                if response.status_code == 200:
                    test_result["vulnerable"] = "error" not in response.text.lower()
                elif response.status_code == 302:
                    location = response.headers.get("location", "")
                    test_result["vulnerable"] = "login" not in location.lower()

                if test_result["vulnerable"]:
                    results["vulnerable"] = True

            except Exception as e:
                test_result["error"] = str(e)
                self.logger.error(f"Error testing {url} with payload {payload}: {e}")

            results["tests"].append(test_result)

        return results

    def scan_juice_shop(self, base_url: str = "https://juice-shop.herokuapp.com") -> Dict:
        """
        Specialized scanner for Juice Shop endpoints
        
        Args:
            base_url: Base URL of Juice Shop instance
            
        Returns:
            Aggregate scan results
        """
        endpoints = [
            "/rest/user/change-password",
            "/api/BasketItems/",
            "/rest/user/reset-password",
            "/rest/product/reviews",
            "/api/Feedbacks/"
        ]
        
        results = {
            "base_url": base_url,
            "vulnerable_endpoints": [],
            "scan_results": {}
        }

        # Create authenticated session
        session = requests.Session()
        try:
            login_response = session.post(
                f"{base_url}/rest/user/login",
                json={"email": "' OR 1=1--", "password": "anything"}  # SQLi to bypass auth
            )
            if login_response.status_code != 200:
                self.logger.error("Failed to authenticate to Juice Shop")
                return results
        except Exception as e:
            self.logger.error(f"Authentication failed: {e}")
            return results

        # Scan each endpoint
        for endpoint in endpoints:
            url = f"{base_url}{endpoint}"
            self.logger.info(f"Scanning {url}")
            results["scan_results"][endpoint] = self.scan_endpoint(url, session)
            
            if results["scan_results"][endpoint]["vulnerable"]:
                results["vulnerable_endpoints"].append(endpoint)

        return results