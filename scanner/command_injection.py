import requests
import logging

class CommandInjectionScanner:
    def __init__(self, payloads=None):
        """
        Initialize the Command Injection scanner with configurable payloads.
        """
        self.payloads = payloads or [
            "; ls",
            "&& whoami",
            "| cat /etc/passwd",
            "`id`",
            "$(uname -a)",
            "; sleep 10",
        ]
        self.log_file = "command_injection_vulnerabilities.log"
        logging.basicConfig(filename=self.log_file, level=logging.INFO)

    def test_command_injection(self, form, url):
        """
        Test a form for command injection vulnerabilities.
        """
        action = form.get("action", url)
        method = form.get("method", "GET").lower()
        inputs = form.get("inputs", [])
        data = {input_field.get("name"): "test" for input_field in inputs if input_field.get("name")}

        for payload in self.payloads:
            for input_name in data:
                modified_data = data.copy()
                modified_data[input_name] = payload

                try:
                    response = requests.post(action, data=modified_data) if method == "post" else requests.get(action, params=modified_data)
                    if response.status_code == 200 and any(keyword in response.text.lower() for keyword in ["root", "uid", "gid", "bin/bash"]):
                        logging.warning(f"Potential command injection vulnerability found at {action} with payload: {payload}")
                        print(f"Potential command injection vulnerability found at {action} with payload: {payload}")
                        return True
                except requests.RequestException as e:
                    logging.error(f"Error testing command injection on {action}: {e}")

        return False
