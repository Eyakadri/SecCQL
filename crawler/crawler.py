import sys
import os
import threading  # Add threading for thread safety
import time
import random
import logging
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from selenium import webdriver  # Ensure selenium is installed: pip install selenium
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service  # Correct import for Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium_stealth import stealth  # Ensure selenium-stealth is installed: pip install selenium-stealth
from crawler.db_handler import Database  # Ensure this matches the actual path
from scanner.xss import XSSScanner  # Ensure these match the actual paths
from scanner.csrf import CSRFScanner
from scanner.sqli import SQLInjectionScanner
from scanner.ssrf import SSRFScanner
from scanner.idor import IDORScanner
from scanner.command_injection import CommandInjectionScanner
import signal  # Import signal for graceful shutdown
from queue import Queue, Empty, Full  # Import Empty and Full for handling queue timeout
import sqlite3  # Assuming SQLite is used for the database

# Ensure the parent directory is in the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Add the crawler directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Set up logging
logging.basicConfig(
    filename="crawler.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

class ConnectionPool:
    """A simple connection pool for database connections."""
    def __init__(self, db_path, pool_size=10):  # Increase default pool size
        self.db_path = db_path
        self.pool = Queue(maxsize=pool_size)
        for _ in range(pool_size):
            self.pool.put(self._create_connection())

    def _create_connection(self):
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def get_connection(self):
        try:
            conn = self.pool.get(timeout=5)
            # Validate the connection
            try:
                conn.execute("SELECT 1")
            except sqlite3.Error:
                conn = self._create_connection()  # Replace invalid connection
            return conn
        except Empty:
            logging.warning("Connection pool is full. Consider increasing the pool size.")
            raise Exception("No available database connections in the pool.")

    def return_connection(self, connection):
        try:
            self.pool.put(connection, timeout=5)
        except Full:
            logging.warning("Connection pool is full, discarding connection.")
            connection.close()  # Close the connection if it cannot be returned to the pool

    def close_all(self):
        while not self.pool.empty():
            conn = self.pool.get_nowait()
            conn.close()

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
        self.connection_pool_size = 10  # Increase connection pool size to handle more concurrent requests
        self.executor = ThreadPoolExecutor(max_workers=self.connection_pool_size)  # Adjust thread pool size
        self.manual_input = False  # Add a flag for optional manual input
        self.db_queue = Queue()  # Queue for database operations
        self.db_thread = threading.Thread(target=self._process_db_queue, daemon=True)
        self.db_thread.start()
        self.rate_limit_lock = threading.Lock()  # Add lock for rate-limiting logic

        # Initialize scanners
        self.xss_scanner = XSSScanner(self.driver)
        self.csrf_scanner = CSRFScanner(self.driver)
        self.sqli_scanner = SQLInjectionScanner(self.driver)
        self.ssrf_scanner = SSRFScanner(self.driver)
        self.idor_scanner = IDORScanner()
        self.command_injection_scanner = CommandInjectionScanner()

        self.connection_pool = ConnectionPool(
            db_path=os.getenv("DB_PATH", "crawler.db"), pool_size=10
        )  # Use connection pool
        self._initialize_schema()  # Initialize database schema

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
            # Remove or comment out the headless mode to make the browser visible
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

            # Make chromedriver path configurable
            chromedriver_path = os.getenv("CHROMEDRIVER_PATH", "/usr/local/bin/chromedriver")
            if not os.path.exists(chromedriver_path):
                raise FileNotFoundError(f"Chromedriver not found at {chromedriver_path}")
            service = Service(chromedriver_path)
            self.driver = webdriver.Chrome(service=service, options=chrome_options)

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
                logging.debug(f"Attempting to fetch page: {url}, Attempt: {attempt + 1}")
                print(f"Navigating to: {url}")  # Add this line to display navigation
                logging.info(f"Navigating to: {url}")  # Log navigation
                self.driver.get(url)
                WebDriverWait(self.driver, 30).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
                logging.info(f"Page loaded: {url}")
                
                # Wait for manual input to proceed with a timeout
                if self.manual_input:
                    try:
                        print("Waiting for manual input (timeout in 30 seconds)...")
                        input("Press Enter to continue crawling...")
                    except TimeoutError:
                        logging.warning("Manual input timed out.")
                
                return self.driver.page_source
            except Exception as e:
                logging.error(f"Error fetching {url}: {e}")
                if attempt < retries - 1:
                    time.sleep(2)
                else:
                    logging.error(f"Failed to fetch {url} after {retries} attempts.")
                    self.restart_browser()
                    return None

    def crawl(self, url, depth=0):
        """Crawl a web application starting from the given URL."""
        if self.shutdown_flag.is_set():  # Check for shutdown signal
            logging.info("Shutdown flag set. Stopping crawl.")
            return
        print(f"Starting crawl for URL: {url} at depth: {depth}")
        # Improved rate-limiting logic
        with self.rate_limit_lock:
            elapsed_time = time.time() - self.start_time
            if self.request_counter >= self.MAX_REQUESTS_PER_MINUTE and elapsed_time < 60:
                sleep_time = 60 - elapsed_time
                logging.info(f"Rate limit reached. Sleeping for {sleep_time:.2f} seconds.")
                time.sleep(sleep_time)
                self.start_time = time.time()
                self.request_counter = 0
            self.request_counter += 1

        with self.visited_urls_lock:  # Ensure thread-safe access to visited_urls
            if url in self.visited_urls or depth > self.max_depth:
                logging.debug(f"Skipping URL: {url} (already visited or max depth reached)")
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

            # Save URL to database using the queue
            self.db_queue.put(("save_url", (url, depth)))

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
            for form in forms:
                # Save forms to database using the queue
                self.db_queue.put(("save_form", (url, form)))
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
            logging.debug(f"Scanning form at {url}: {form}")
            logging.info(f"Form found at {url}: {form}")
            print(f"Form found at {url}: {form}")
            try:
                self.db.save_form(url, form)
            except Exception as e:
                logging.error(f"Failed to save form to database: {e}")

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

            if self.command_injection_scanner.test_command_injection(form, url):
                logging.warning(f"Command Injection vulnerability detected at {url}")
                print(f"Command Injection vulnerability detected at {url}")

    def extract_links(self, html, base_url):
        """Extract all links from a web page and validate them."""
        soup = BeautifulSoup(html, "html.parser")
        links = set()
        for link in soup.find_all("a", href=True):
            full_url = urljoin(base_url, link["href"])
            if self._is_valid_url(full_url):
                links.add(full_url)
                logging.debug(f"Valid link extracted: {full_url}")
            else:
                logging.debug(f"Invalid link skipped: {full_url}")
        return links

    def _is_valid_url(self, url):
        """Check if a URL is valid."""
        parsed = urlparse(url)
        return bool(parsed.netloc) and bool(parsed.scheme)

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
        for _ in range(3):  # Retry up to 3 times
            try:
                if self.driver:
                    self.driver.quit()
                self.initialize_driver()
                logging.info("Browser restarted successfully.")
                return
            except Exception as e:
                logging.error(f"Failed to restart browser: {e}")
                time.sleep(2)
        logging.error("Failed to restart browser after 3 attempts.")
        raise RuntimeError("Browser restart failed.")

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
        logging.info(f"Received shutdown signal: {signum}")
        logging.info("Graceful shutdown initiated.")
        self.shutdown_flag.set()  # Signal threads to stop
        try:
            self.executor.shutdown(wait=True, timeout=30)  # Add timeout for thread pool shutdown
        except Exception as e:
            logging.error(f"Error during executor shutdown: {e}")
        self.close()

    def _process_db_queue(self):
        """Process database operations in a single thread using connection pooling."""
        while not self.shutdown_flag.is_set():
            try:
                operation, args = self.db_queue.get(timeout=1)
                logging.debug(f"Processing database operation: {operation}")
                conn = self.connection_pool.get_connection()
                try:
                    if operation == "save_url":
                        self._save_url(conn, *args)
                    elif operation == "save_form":
                        self._save_form(conn, *args)
                finally:
                    self.connection_pool.return_connection(conn)  # Ensure connection is returned
                self.db_queue.task_done()
            except Empty:
                continue
            except sqlite3.OperationalError as e:
                logging.error(f"Database is locked: {e}")
                time.sleep(1)  # Wait before retrying
            except Exception as e:
                logging.error(f"Error processing database operation: {e}")
        # Ensure all tasks in the queue are processed before shutdown
        while not self.db_queue.empty():
            try:
                operation, args = self.db_queue.get_nowait()
                logging.debug(f"Processing remaining database operation: {operation}")
                conn = self.connection_pool.get_connection()
                try:
                    if operation == "save_url":
                        self._save_url(conn, *args)
                    elif operation == "save_form":
                        self._save_form(conn, *args)
                finally:
                    self.connection_pool.return_connection(conn)  # Ensure connection is returned
                self.db_queue.task_done()
            except sqlite3.OperationalError as e:
                logging.error(f"Database is locked: {e}")
                time.sleep(1)  # Wait before retrying
            except Exception as e:
                logging.error(f"Error processing remaining database operation: {e}")

    def _save_url(self, conn, url, depth):
        """Save a URL to the database."""
        try:
            cursor = conn.cursor()
            cursor.execute("INSERT OR IGNORE INTO urls (url, depth) VALUES (?, ?)", (url, depth))  # Use INSERT OR IGNORE
            conn.commit()
        except sqlite3.OperationalError as e:
            logging.error(f"Database operation error: {e}")
        except Exception as e:
            logging.error(f"Error saving URL to database: {e}")

    def _save_form(self, conn, url, form):
        """Save a form to the database."""
        try:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO forms (url, form_data) VALUES (?, ?)", (url, str(form)))
            conn.commit()
        except sqlite3.OperationalError as e:
            logging.error(f"Database operation error: {e}")
        except Exception as e:
            logging.error(f"Error saving form to database: {e}")

    def _initialize_schema(self):
        """Initialize the database schema if it does not exist."""
        conn = self.connection_pool.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS urls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL UNIQUE,  -- Add UNIQUE constraint to prevent duplicates
                    depth INTEGER NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS forms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    form_data TEXT NOT NULL
                )
            """)
            conn.commit()
        finally:
            self.connection_pool.return_connection(conn)

    def close(self):
        """Close the Selenium WebDriver, database connection pool, and other resources."""
        logging.info("Closing crawler resources...")
        try:
            self.shutdown_flag.set()
            self.db_thread.join()
            if self.driver:
                self.driver.quit()
            self.connection_pool.close_all()
            logging.info("Crawler closed successfully.")
        except Exception as e:
            logging.error(f"Error during shutdown: {e}")

# Example instantiation (ensure this matches your usage)
if __name__ == "__main__":
    try:
        crawler = WebCrawler(base_url="http://example.com", max_depth=3, delay=1, proxy=None)
        crawler.crawl(crawler.base_url)
    except Exception as e:
        logging.error(f"Unhandled exception: {e}")
    finally:
        crawler.close()
