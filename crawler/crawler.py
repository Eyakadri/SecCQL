import sys
import os
import threading  # Add threading for thread safety

# Add the root directory to sys.path if not already included
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Verify sys.path to ensure the parent directory is included
# print(sys.path)

import time
import random
import logging
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from selenium import webdriver  # Explicitly import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service  # Correct import for Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium_stealth import stealth  # Ensure selenium-stealth is installed
from database.db_handler import Database # Ensure this module exists and is in the correct path
import undetected_chromedriver as uc  # Ensure undetected-chromedriver is installed
from scanner.xss import XSSScanner  # Ensure these modules exist and are in the correct path
from scanner.csrf import CSRFScanner
from scanner.sqli import SQLInjectionScanner
from scanner.ssrf import SSRFScanner
from scanner.idor import IDORScanner
import signal  # Import signal for graceful shutdown

# Set up logging
logging.basicConfig(
    filename="crawler.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

class WebCrawler:
    """Web crawler for discovering endpoints, forms, and input fields."""
    def __init__(self, base_url, max_depth=3, delay=1, proxy=None):
        logging.info(f"Initializing WebCrawler with base_url: {base_url}, max_depth: {max_depth}, delay: {delay}")
        self.base_url = base_url
        self.visited_urls = set()
        self.max_depth = max_depth
        self.delay = delay
        self.proxy = proxy
        self.db = Database()
        self.driver = None
        self.initialize_driver()
        self.original_domain = urlparse(base_url).netloc  # Extract target domain
        # Add these new properties
        self.blocked_domains = set()
        self.allowed_domains = [self.original_domain]
        self.redirect_history = {}
        # Add rate limiting
        self.request_counter = 0
        self.MAX_REQUESTS_PER_MINUTE = 60
        self.start_time = time.time()  # Track start time for rate limiting
        signal.signal(signal.SIGINT, self.graceful_shutdown)  # Handle Ctrl+C
        signal.signal(signal.SIGTERM, self.graceful_shutdown)  # Handle termination signals
        self.visited_urls_lock = threading.Lock()  # Add lock for thread safety
        self.shutdown_flag = threading.Event()  # Use an event for graceful shutdown
        self.executor = ThreadPoolExecutor(max_workers=5)  # Initialize ThreadPoolExecutor
        self.manual_input = False  # Add a flag for optional manual input

        # Initialize scanners
        self.xss_scanner = XSSScanner(self.driver)
        self.csrf_scanner = CSRFScanner(self.driver)
        self.sqli_scanner = SQLInjectionScanner(self.driver)
        self.ssrf_scanner = SSRFScanner(self.driver)
        self.idor_scanner = IDORScanner()  # Initialize IDOR scanner

    def login(self, login_url, username_field, password_field, submit_button, username, password):
        """Login to a web application using Selenium."""
        try:
            self.driver.get(login_url)
            self.driver.find_element(By.NAME, username_field).send_keys(username)
            self.driver.find_element(By.NAME, password_field).send_keys(password)
            self.driver.find_element(By.XPATH, submit_button).click()
            time.sleep(self.delay + random.uniform(-0.5, 0.5))
            logging.info("Login successful.")
        except Exception as e:
            logging.error(f"Failed to log in: {e}")
            raise


    def initialize_driver(self):
        """Initialize the Selenium WebDriver."""
        try:
            logging.info("Initializing the WebDriver...")
            
            chrome_options = Options()
            chrome_options.add_argument("--disable-blink-features=AutomationControlled")
            chrome_options.add_argument("--disable-extensions")
            chrome_options.add_argument("--disable-popup-blocking")
            chrome_options.add_argument("--disable-infobars")
            chrome_options.add_argument("--start-maximized")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--disable-gpu")

            if self.proxy:
                chrome_options.add_argument(f"--proxy-server={self.proxy}")

            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            ]
            chrome_options.add_argument(f"--user-agent={random.choice(user_agents)}")

            # Specify the path to chromedriver explicitly
            chromedriver_path = "/usr/local/bin/chromedriver"  # Revert to hardcoded path
            service = Service(chromedriver_path)  # Use hardcoded chromedriver path
            self.driver = webdriver.Chrome(service=service, options=chrome_options)  # Pass Service object

            stealth(
                self.driver,
                languages=["en-US", "en"],
                vendor="Google Inc.",
                platform="Win32",
                webgl_vendor="Intel Inc.",
                renderer="Intel Iris OpenGL Engine",
                fix_hairline=True,
            )
            logging.info("Selenium WebDriver initialized successfully.")
        except Exception as e:
            logging.error(f"Failed to initialize Selenium WebDriver: {e}")
            raise

    def fetch_page(self, url, retries=3):
        """Fetch the content of a web page using Selenium with retry mechanism."""
        for attempt in range(retries):
            try:
                self.driver.get(url)
                WebDriverWait(self.driver, 30).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
                logging.info(f"Page loaded: {url}")
                
                # Wait for manual input to proceed
                if self.manual_input:  # Check if manual input is enabled
                    input("Press Enter to continue crawling...")  # Keeps the browser open until user input
                
                return self.driver.page_source
            except Exception as e:
                logging.error(f"Error fetching {url} with Selenium: {e}")
                if attempt < retries - 1:
                    logging.warning(f"Retrying ({attempt + 1}/{retries})...")
                    time.sleep(2)
                else:
                    logging.error(f"Failed to fetch {url} after {retries} attempts.")
                    self.restart_browser()  # Restart browser on final failure
                    return None

    def crawl(self, url, depth=0):
        """Crawl a web application starting from the given URL."""
        if self.shutdown_flag.is_set():  # Check for shutdown signal
            return
        print(f"Starting crawl for URL: {url} at depth: {depth}")
        # Rate limiting
        if self.request_counter >= self.MAX_REQUESTS_PER_MINUTE:
            elapsed_time = time.time() - self.start_time
            if (elapsed_time < 60):
                sleep_time = 60 - elapsed_time
                logging.info(f"Rate limit reached. Sleeping for {sleep_time:.2f} seconds.")
                time.sleep(sleep_time)
            self.start_time = time.time()
            self.request_counter = 0

        self.request_counter += 1

        with self.visited_urls_lock:  # Ensure thread-safe access to visited_urls
            if url in self.visited_urls or depth > self.max_depth:
                return
            self.visited_urls.add(url)

        logging.info(f"Crawling: {url}")
        print(f"Crawling: {url}")

        try:
            # Fetch the page
            html = self.fetch_page(url)
            if not html:
                logging.error(f"Failed to fetch {url}. Retrying...")
                self.restart_browser()  # Restart browser on failure
                return  # Exit crawl for this URL

            # Save URL to database
            self.db.save_url(url, depth)

            # Extract links and crawl them
            links = self.extract_links(html, self.base_url)
            logging.info(f"Found {len(links)} links at {url}")
            futures = []
            for link in links:
                # Check allowed and blocked domains
                if any(domain in link for domain in self.blocked_domains):
                    logging.info(f"Skipping blocked domain: {link}")
                    continue
                if not any(domain in link for domain in self.allowed_domains):
                    logging.info(f"Skipping disallowed domain: {link}")
                    continue
                if link not in self.visited_urls:
                    futures.append(self.executor.submit(self.crawl, link, depth + 1))
            for future in futures:
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"Error in thread: {e}")

            # Extract forms and save them to the database
            forms = self.extract_forms(html)
            logging.info(f"Found {len(forms)} forms at {url}")
            self._scan_vulnerabilities(url, forms)  # Refactored scanning logic

            # Add a random delay between requests
            time.sleep(self.delay + random.uniform(-0.5, 0.5))

        except Exception as e:
            logging.error(f"Error during crawling {url}: {e}")
            # Restart the browser if it crashes
            self.restart_browser()
        
        print(f"Finished crawling URL: {url}")

    def _scan_vulnerabilities(self, url, forms):
        """Refactored method to scan for vulnerabilities."""
        for form in forms:
            logging.info(f"Form found at {url}: {form}")
            print(f"Form found at {url}: {form}")
            self.db.save_form(url, form)

            if self.xss_scanner.test_xss(form, url):
                logging.warning(f"XSS vulnerability detected at {url}")
                print(f"XSS vulnerability detected at {url}")

            if self.csrf_scanner.test_csrf(form, url):
                logging.warning(f"CSRF vulnerability detected at {url}")
                print(f"CSRF vulnerability detected at {url}")

            if self.sqli_scanner.test_sql_injection(form, url):
                logging.warning(f"SQLi vulnerability detected at {url}")
                print(f"SQLi vulnerability detected at {url}")

            if self.ssrf_scanner.test_ssrf(url, form):
                logging.warning(f"SSRF vulnerability detected at {url}")
                print(f"SSRF vulnerability detected at {url}")

            if self.idor_scanner.test_idor(url):
                logging.warning(f"IDOR vulnerability detected at {url}")
                print(f"IDOR vulnerability detected at {url}")

    def extract_links(self, html, base_url):
        """Extract all links from a web page."""
        soup = BeautifulSoup(html, "html.parser")
        links = set()
        for link in soup.find_all("a", href=True):
            full_url = urljoin(base_url, link["href"])
            links.add(full_url)
            logging.debug(f"Extracted link: {full_url}")
        return links

    def extract_forms(self, html):
        """Extract all forms from a web page."""
        soup = BeautifulSoup(html, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            form_details = {
                "action": form.get("action", ""),
                "method": form.get("method", "GET").upper(),
                "inputs": []
            }
            for input_tag in form.find_all("input"):
                input_details = {
                    "name": input_tag.get("name", ""),
                    "type": input_tag.get("type", "text"),
                    "value": input_tag.get("value", "")
                }
                form_details["inputs"].append(input_details)
            forms.append(form_details)
        return forms

    def _is_same_domain(self, url):
        """Check if URL belongs to the target domain."""
        parsed = urlparse(url)
        return parsed.netloc == self.original_domain
    
    def restart_browser(self):
        """Restart the browser if it crashes or loses connection."""
        logging.info("Restarting browser...")
        try:
            if self.driver:
                self.driver.quit()
            self.initialize_driver()
            logging.info("Browser restarted successfully.")
        except Exception as e:
            logging.error(f"Failed to restart browser: {e}")
            raise

    def block_domain(self, domain):
        """Dynamically block a domain."""
        self.blocked_domains.add(domain)
        logging.info(f"Blocked domain: {domain}")

    def unblock_domain(self, domain):
        """Dynamically unblock a domain."""
        self.blocked_domains.discard(domain)
        logging.info(f"Unblocked domain: {domain}")

    def graceful_shutdown(self, signum, frame):
        """Handle graceful shutdown on termination signals."""
        logging.info("Graceful shutdown initiated.")
        self.shutdown_flag.set()  # Signal threads to stop
        self.executor.shutdown(wait=False)  # Interrupt threads immediately
        self.close()

    def close(self):
        """Close the Selenium WebDriver and database connection."""
        if self.driver:
            self.driver.quit()
        self.db.close()
        logging.info("Crawler closed successfully.")
