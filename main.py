import logging
import argparse
import time
import json
import signal
from urllib.parse import urlparse
from crawler.crawler import WebCrawler  # Ensure this matches the actual path
from concurrent.futures import ThreadPoolExecutor

# Add a debug log to confirm the correct class is imported
logging.debug(f"Imported WebCrawler from: {WebCrawler.__module__}")

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,  # Changed to DEBUG for more granular logs
    format="%(asctime)s - %(levelname)s - %(message)s",
)

def validate_url(url):
    """
    Validate the provided URL to ensure it is well-formed.
    """
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")

def check_for_updates(crawler, config_file="config.json"):
    """
    Check for updates to crawler parameters and apply them dynamically.
    """
    try:
        with open(config_file, "r") as config_file:
            config = json.load(config_file)
            if "depth" in config and isinstance(config["depth"], int):
                crawler.max_depth = config["depth"]
                logging.info(f"Updated max_depth to {crawler.max_depth}")
            if "delay" in config and isinstance(config["delay"], (int, float)):
                crawler.delay = config["delay"]
                logging.info(f"Updated delay to {crawler.delay}")
    except FileNotFoundError:
        logging.debug("Configuration file not found. Skipping updates.")  # Change to DEBUG to suppress unnecessary warnings
    except json.JSONDecodeError:
        logging.error("Error decoding JSON from config file.")
    except Exception as e:
        logging.error(f"Error while checking for updates: {e}")

def handle_shutdown(signum, frame):
    """
    Gracefully shut down on signal interrupt.
    """
    logging.info("Received shutdown signal. Shutting down gracefully...")
    raise KeyboardInterrupt

def validate_positive_int(value):
    """Validate that a value is a positive integer."""
    try:
        ivalue = int(value)
        if ivalue <= 0:
            raise ValueError
        return ivalue
    except ValueError:
        raise argparse.ArgumentTypeError(f"Value must be a positive integer: {value}")

def main():
    """
    Main function to initialize and run the web crawler.
    """
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Web Application Security Crawler")
    parser.add_argument("url", help="Base URL to start crawling from")
    parser.add_argument("--depth", type=validate_positive_int, default=3, help="Maximum depth to crawl")
    parser.add_argument("--delay", type=float, default=1, help="Delay between requests (in seconds)")
    parser.add_argument("--proxy", type=str, help="Proxy server (e.g., http://your_proxy:port)")
    parser.add_argument("--thread-pool-size", type=validate_positive_int, default=5, help="Number of threads in the thread pool")
    parser.add_argument("--username", type=str, help="Username for login (optional)")
    parser.add_argument("--password", type=str, help="Password for login (optional)")
    parser.add_argument("--login-url", type=str, help="Login URL (optional, defaults to base URL)")
    parser.add_argument("--username-field", type=str, default="username", help="Username field name (optional)")
    parser.add_argument("--password-field", type=str, default="password", help="Password field name (optional)")
    parser.add_argument("--submit-button", type=str, default="//input[@type='submit']", help="Submit button XPath (optional)")
    parser.add_argument("--block-domain", type=str, nargs="*", help="Domains to block during crawling")
    parser.add_argument("--update-frequency", type=int, default=10, help="Frequency (in seconds) to check for updates")
    parser.add_argument("--max-iterations", type=int, default=100, help="Maximum number of crawling iterations")
    parser.add_argument("--output", type=str, default="report.pdf", help="Path to save the generated report")  # Added output argument

    try:
        args = parser.parse_args()
    except SystemExit as e:
        logging.error(f"Argument parsing failed: {e}")
        print("Error: Invalid arguments provided. Use --help for usage information.")
        return

    # Validate the base URL
    try:
        validate_url(args.url)
    except ValueError as e:
        logging.error(e)
        return

    # Initialize the crawler
    logging.info("Initializing WebCrawler...")
    try:
        # Pass all required arguments to WebCrawler
        crawler = WebCrawler(
            base_url=args.url,
            max_depth=args.depth,
            delay=args.delay,
            proxy=args.proxy,
        )
        crawler.executor = ThreadPoolExecutor(max_workers=args.thread_pool_size)  # Set thread pool size dynamically
        logging.info("WebCrawler initialized successfully.")
    except Exception as e:
        logging.error(f"Failed to initialize WebCrawler: {e}")
        return

    # Block specified domains
    if args.block_domain:
        for domain in args.block_domain:
            crawler.block_domain(domain)

    # Setup signal handling for graceful shutdown
    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    iteration_count = 0
    max_iterations = args.max_iterations  # Use configurable max_iterations

    try:
        # Log in (if credentials are provided)
        if args.username and args.password:
            login_url = args.login_url if args.login_url else args.url
            logging.info(f"Logging in at {login_url}...")
            try:
                crawler.login(
                    login_url=login_url,
                    username_field=args.username_field,
                    password_field=args.password_field,
                    submit_button=args.submit_button,
                    username=args.username,
                    password=args.password,
                )
                logging.info("Login successful.")
            except Exception as e:
                logging.error(f"Failed to log in: {e}")
                return

        # Start crawling with periodic update checks
        logging.info(f"Starting crawl on: {args.url}")
        logging.info("Crawler initialized. Starting crawl...")
        print("Crawler initialized. Starting crawl...")
        while iteration_count < max_iterations:
            crawler.crawl(args.url)
            logging.info(f"Iteration {iteration_count + 1}/{max_iterations} completed. Checking for updates...")
            check_for_updates(crawler)
            iteration_count += 1
            time.sleep(args.update_frequency)  # Wait before the next iteration or update check
        logging.info("Reached maximum iterations. Stopping crawler.")
    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt detected. Shutting down gracefully...")
    except Exception as e:
        logging.error(f"Error during crawling: {e}")
    finally:
        # Ensure resources are closed
        logging.info("Shutting down crawler and cleaning up resources...")

        # Graceful shutdown for WebDriver and threads
        try:
            if hasattr(crawler, "executor"):
                crawler.executor.shutdown(wait=True)  # Ensure threads are stopped
        except Exception as e:
            logging.error(f"Error during executor shutdown: {e}")

        # Close WebDriver and database connection
        crawler.close()
        logging.info("Crawler shutdown complete.")

        # Generate a report after crawling
        try:
            from reporter.report_generator import ReportGenerator
            vulnerabilities = []  # Replace with actual vulnerabilities detected during crawling
            reporter = ReportGenerator()
            reporter.generate_pdf(vulnerabilities, args.output)
            logging.info(f"Report saved to {args.output}")
        except Exception as e:
            logging.error(f"Failed to generate report: {e}")

from cli.console import main

if __name__ == "__main__":
    main()
