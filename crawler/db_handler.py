import sqlite3
import logging

class Database:
    """
    A class to handle database operations for the web crawler.
    """
    def __init__(self, db_name="crawler.db"):
        try:
            self.conn = sqlite3.connect(db_name, check_same_thread=False)  # Allow connection across threads
            self.cursor = self.conn.cursor()
            self._create_tables()
        except sqlite3.Error as e:
            logging.error(f"Error connecting to database {db_name}: {e}")
            raise

    def _create_tables(self):
        try:
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS urls (
                    id INTEGER PRIMARY KEY,
                    url TEXT UNIQUE,
                    depth INTEGER
                )
            """)
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS forms (
                    id INTEGER PRIMARY KEY,
                    url TEXT,
                    action TEXT,
                    method TEXT,
                    inputs TEXT
                )
            """)
            self.conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Error creating tables: {e}")
            raise

    def save_url(self, url, depth):
        try:
            with self.conn:  # Use context manager for transactions
                self.cursor.execute("INSERT OR IGNORE INTO urls (url, depth) VALUES (?, ?)", (url, depth))
        except sqlite3.Error as e:
            logging.error(f"Error saving URL {url} with depth {depth}: {e}")

    def save_form(self, url, form):
        try:
            with self.conn:  # Use context manager for transactions
                self.cursor.execute("""
                    INSERT INTO forms (url, action, method, inputs)
                    VALUES (?, ?, ?, ?)
                """, (url, form["action"], form["method"], str(form["inputs"])))
        except sqlite3.Error as e:
            logging.error(f"Error saving form for URL {url}: {e}")

    def fetch_urls(self):
        try:
            self.cursor.execute("SELECT * FROM urls")
            return self.cursor.fetchall()
        except sqlite3.Error as e:
            logging.error(f"Error fetching URLs: {e}")
            return []

    def fetch_forms(self):
        try:
            self.cursor.execute("SELECT * FROM forms")
            return self.cursor.fetchall()
        except sqlite3.Error as e:
            logging.error(f"Error fetching forms: {e}")
            return []

    def url_exists(self, url):
        try:
            self.cursor.execute("SELECT 1 FROM urls WHERE url = ?", (url,))
            return self.cursor.fetchone() is not None
        except sqlite3.Error as e:
            logging.error(f"Error checking existence of URL {url}: {e}")
            return False

    def close(self):
        try:
            if self.conn:
                self.conn.close()
        except sqlite3.Error as e:
            logging.error(f"Error closing database connection: {e}")