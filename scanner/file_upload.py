import os
import logging
import re
import hashlib
import sqlite3
from datetime import datetime, timedelta
from typing import List, Dict, Union, Optional, Tuple, Literal
from contextlib import contextmanager
from pathlib import Path


try:
    import magic
except ImportError:
    magic = None

# Security Configuration
class SecurityConfig:
    MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', 5 * 1024 * 1024))  # 5 MB
    MAX_FILENAME_LENGTH = 255
    MAX_MALICIOUS_ATTEMPTS = int(os.getenv('MAX_MALICIOUS_ATTEMPTS', 5))
    ATTEMPT_WINDOW_HOURS = int(os.getenv('ATTEMPT_WINDOW_HOURS', 1))
    DB_PATH = 'security.db'
    QUARANTINE_DIR = 'quarantine'
    
    ALLOWED_EXTENSIONS = {
        '.txt': 'text/plain',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.pdf': 'application/pdf',
        '.doc': 'application/msword',
        '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    }
    
    MALICIOUS_PATTERNS = [
        re.compile(r'<\s*(script|iframe|embed|object|link)', re.IGNORECASE),
        re.compile(r'(<\?php|<\?=|\?>)', re.IGNORECASE),
        re.compile(r'(javascript|vbscript|data|about):', re.IGNORECASE),
        re.compile(r'(document|window)\.', re.IGNORECASE),
        re.compile(r'eval\s*\(|alert\s*\(|prompt\s*\('),
        re.compile(r'@import|\\x[0-9a-f]{2}', re.IGNORECASE),
        re.compile(r'(base64_decode|cmd\.exe|\/bin\/sh)', re.IGNORECASE)
    ]
    
    RESERVED_NAMES = [
        'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4',
        'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3',
        'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    ]

# Configure secure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(process)d - %(message)s',
    handlers=[
        logging.FileHandler('security_audit.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logging.getLogger().addHandler(logging.NullHandler())

# Initialize database and quarantine directory
def init_security_system():
    """Initialize security components."""
    try:
        os.makedirs(SecurityConfig.QUARANTINE_DIR, exist_ok=True)
        
        with db_connection() as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS malicious_attempts (
                ip_address TEXT PRIMARY KEY,
                count INTEGER,
                first_seen TEXT,
                last_seen TEXT
            )''')
            conn.execute('''CREATE INDEX IF NOT EXISTS idx_last_seen 
                          ON malicious_attempts(last_seen)''')
    except Exception as e:
        logging.error(f"Security system initialization failed: {str(e)}")
        raise

@contextmanager
def db_connection():
    """Database connection context manager."""
    conn = None
    try:
        conn = sqlite3.connect(SecurityConfig.DB_PATH)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        yield conn
    except Exception as e:
        logging.error(f"Database operation failed: {str(e)}")
        raise
    finally:
        if conn:
            conn.close()

def validate_file_extension(filename: str) -> bool:
    """Validate file extension against allowed types."""
    _, ext = os.path.splitext(filename)
    return ext.lower() in SecurityConfig.ALLOWED_EXTENSIONS

def validate_file_size(file_path: str) -> bool:
    """Validate file size constraints."""
    try:
        file_size = os.path.getsize(file_path)
        return 0 < file_size <= SecurityConfig.MAX_FILE_SIZE
    except OSError:
        return False

def detect_malicious_content(content: bytes) -> bool:
    """Scan content for malicious patterns."""
    try:
        decoded = content.decode('utf-8', errors='ignore')
        return any(pattern.search(decoded) for pattern in SecurityConfig.MALICIOUS_PATTERNS)
    except UnicodeDecodeError:
        return True  # Binary data in text files is suspicious

def verify_mime_type(file_path: str, ext: str) -> bool:
    """Verify file MIME type matches extension."""
    if not magic:
        logging.warning("MIME validation failed: python-magic not installed")
        return False  # Fail securely when magic is not available
        
    try:
        mime = magic.from_file(file_path, mime=True)
        expected_mime = SecurityConfig.ALLOWED_EXTENSIONS.get(ext.lower())
        if not expected_mime:
            return False
            
        return mime == expected_mime
    except Exception as e:
        logging.warning(f"MIME validation failed: {str(e)}", exc_info=True)
        return False

def is_reserved_filename(filename: str) -> bool:
    """Check if filename is a reserved system name."""
    name_without_ext = os.path.splitext(filename)[0].upper()
    return name_without_ext in SecurityConfig.RESERVED_NAMES

def quarantine_file(file_path: str) -> str:
    """Move file to quarantine directory and return new path."""
    try:
        filename = os.path.basename(file_path)
        quarantine_path = os.path.join(SecurityConfig.QUARANTINE_DIR, f"{datetime.now().timestamp()}_{filename}")
        os.rename(file_path, quarantine_path)
        return quarantine_path
    except Exception as e:
        logging.error(f"Failed to quarantine file: {str(e)}")
        raise

def prevent_directory_traversal(input_path: str) -> Union[Tuple[Literal[True], str], Tuple[Literal[False], str]]:
    """
    Secure path sanitization that prevents directory traversal attacks.
    
    Args:
        input_path: The file path to sanitize
        
    Returns:
        Tuple: (success: bool, sanitized_filename_or_error: str)
              - success: True if path is safe, False if blocked
              - str: sanitized filename if True, error reason if False
    
    Security Checks:
    1. Empty input
    2. Directory traversal sequences (../, ..\)
    3. Absolute paths
    4. Reserved filenames (like passwd, etc/passwd)
    5. Filename length limits
    6. Special device names (COM1, LPT1, etc. on Windows)
    """
    if not input_path:
        return False, 'invalid_filename'
    
    try:
        # Convert to Path object for better handling
        path = Path(input_path)
        
        # Check for absolute paths
        if path.is_absolute():
            return False, 'absolute_path'
            
        # Normalize and resolve the path
        normalized = path.resolve().as_posix()
        
        # Check for parent directory references
        if '..' in normalized.split('/'):
            return False, 'directory_traversal'
            
        # Get the final filename component
        basename = path.name
        
        # Block sensitive system files
        sensitive_files = {
            'passwd', 'shadow', 'hosts', 'group',
            'etc/passwd', 'etc/shadow', 'etc/hosts'
        }
        if basename in sensitive_files or normalized in sensitive_files:
            return basename
            
        # Check for invalid names
        if not basename or basename in ('.', '..'):
            return False, 'invalid_filename'
                    
        # Check for reserved names (platform specific)
        if is_reserved_filename(basename):
            return False, 'reserved_filename'
            
        # Check filename length
        if len(basename) > SecurityConfig.MAX_FILENAME_LENGTH:
            return False, 'filename_too_long'
            
        return True, basename
        
    except (ValueError, RuntimeError):
        return False, 'invalid_path'

def track_malicious_attempt(ip_address: str) -> bool:
    """
    Track and respond to malicious attempts with rate limiting.
    
    Returns:
        bool: True if IP should be blocked
    """
    try:
        now = datetime.now().isoformat()
        
        with db_connection() as conn:
            cursor = conn.cursor()
            
            # Check existing record
            cursor.execute(
                "SELECT count, first_seen FROM malicious_attempts WHERE ip_address = ?",
                (ip_address,)
            )
            row = cursor.fetchone()
            
            if row:
                count, first_seen = row
                first_seen_dt = datetime.fromisoformat(first_seen)
                
                # Reset if window expired
                if datetime.now() - first_seen_dt > timedelta(hours=SecurityConfig.ATTEMPT_WINDOW_HOURS):
                    count = 1
                    first_seen = now
                else:
                    count += 1
                
                # Update record
                cursor.execute(
                    "UPDATE malicious_attempts SET count = ?, last_seen = ? WHERE ip_address = ?",
                    (count, now, ip_address)
                )
            else:
                # Insert new record
                count = 1
                cursor.execute(
                    "INSERT INTO malicious_attempts (ip_address, count, first_seen, last_seen) VALUES (?, ?, ?, ?)",
                    (ip_address, count, now, now)
                )
            
            conn.commit()
            
            if count >= SecurityConfig.MAX_MALICIOUS_ATTEMPTS:
                logging.warning(f"IP {ip_address} blocked - too many attempts")
                return True
                
            logging.info(f"Security event from {ip_address} - attempt {count}")
            return False
            
    except Exception as e:
        logging.error(f"Failed to track malicious attempt: {str(e)}")
        return False

def is_file_safe(file_path: str) -> bool:
    """
    Comprehensive file safety validation.
    
    Args:
        file_path: Path to the file to validate
        
    Returns:
        bool: True if file passes all security checks
    """
    try:
        if not os.path.exists(file_path):
            logging.error(f"File not found: {file_path}")
            return False

        # Filename validation
        filename = os.path.basename(file_path)
        valid, sanitized_name = prevent_directory_traversal(filename)
        if not valid:
            logging.warning(f"Invalid filename: {filename}")
            return False

        # Extension validation
        if not validate_file_extension(filename):
            logging.warning(f"Invalid file extension: {filename}")
            return False

        # Size validation
        if not validate_file_size(file_path):
            logging.warning(f"Invalid file size: {os.path.getsize(file_path)}")
            return False

        # Content validation
        with open(file_path, 'rb') as f:
            content = f.read(8192)  # Read first 8KB
            
            # Check for binary in text files
            _, ext = os.path.splitext(filename)
            if ext.lower() in {'.txt', '.csv'} and b'\x00' in content:
                logging.warning("Binary data in text file")
                return False
                
            # Check for malicious patterns
            if detect_malicious_content(content):
                logging.warning("Malicious content detected")
                return False

        # MIME type verification
        if not verify_mime_type(file_path, ext):
            logging.warning("MIME type mismatch")
            return False

        return True

    except Exception as e:
        logging.error(f"File validation error: {str(e)}", exc_info=True)
        return False

def process_file_upload(
    file_path: str,
    ip_address: str = 'unknown',
    user_id: Optional[str] = None
) -> Dict[str, Union[bool, str, None]]:
    """
    Secure file upload processing pipeline.
    
    Returns:
        dict: Always contains all keys:
        - success: bool
        - message: str
        - sanitized_name: str
        - checksum: Optional[str]
        - quarantined: bool
    """
    # Initialize default result at function start
    default_result = {
        'success': False,
        'message': 'Initialization error',
        'sanitized_name': '',
        'checksum': None,
        'quarantined': False
    }
    
    try:
        # Create a fresh result dict for this attempt
        result = default_result.copy()
        result['message'] = 'Processing started'
        
        # Initial validation
        if not os.path.exists(file_path):
            result['message'] = 'File not found'
            return result
            
        # Sanitize filename
        valid, sanitized_name = prevent_directory_traversal(os.path.basename(file_path))
        result['sanitized_name'] = sanitized_name
        
        if not valid:
            result['message'] = 'Invalid filename'
            track_malicious_attempt(ip_address)
            return result
            
        # Security validation
        if not is_file_safe(file_path):
            result['message'] = 'File failed security checks'
            quarantine_path = quarantine_file(file_path)
            result['quarantined'] = True
            track_malicious_attempt(ip_address)
            logging.warning(f"File quarantined: {file_path} -> {quarantine_path}")
            return result
            
        # Generate checksum
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256()
            while chunk := f.read(8192):
                file_hash.update(chunk)
            result['checksum'] = file_hash.hexdigest()
        
        # Final success
        result['success'] = True
        result['message'] = 'File uploaded successfully'
        logging.info(f"File upload success: {sanitized_name} from {ip_address}")
        return result
        
    except Exception as e:
        logging.error(f"Upload processing failed: {str(e)}", exc_info=True)
        error_result = default_result.copy()
        error_result['message'] = 'Server error during processing'
        return error_result

def analyze_insecure_cookies(
    cookies: List[Dict[str, Union[str, bool]]],
    secure_origin: bool = True
) -> Dict[str, Union[List[Dict[str, Union[str, List[str]]]], int]]:
    """
    Comprehensive cookie security audit.
    
    Args:
        cookies: List of cookie dictionaries
        secure_origin: Whether connection is HTTPS
        
    Returns:
        dict: {
            'insecure': List of insecure cookies,
            'total_issues': Count of security issues found
        }
    """
    audit_result = {
        'insecure': [],
        'total_issues': 0
    }
    
    try:
        for cookie in cookies:
            issues = []
            name = cookie.get('name', 'unnamed')
            
            # Skip checks for non-secure origins (except prefix requirements)
            perform_checks = secure_origin or name.startswith(('__Secure-', '__Host-'))
            
            # Secure flag check
            if perform_checks and not cookie.get('secure', False):
                issues.append('missing secure flag')
            
            # HttpOnly flag check
            if not cookie.get('httpOnly', False):
                issues.append('missing HttpOnly flag')
                
            # SameSite check
            samesite = cookie.get('sameSite', '').lower()
            if samesite not in {'strict', 'lax', 'none'}:
                issues.append('invalid SameSite value')
                
            # Special prefix checks
            if name.startswith('__Secure-'):
                if not cookie.get('secure', False):
                    issues.append('__Secure- prefix requires secure flag')
                    
            if name.startswith('__Host-'):
                requirements = [
                    cookie.get('secure', False),
                    cookie.get('path', '') == '/',
                    not cookie.get('domain', '')
                ]
                if not all(requirements):
                    issues.append('__Host- prefix requirements not met')
                
            # Domain checks
            if secure_origin and cookie.get('domain', '').startswith('.'):
                issues.append('leading dot in domain is deprecated')
                
            if issues:
                audit_result['insecure'].append({
                    'name': name,
                    'issues': issues
                })
                audit_result['total_issues'] += len(issues)
                
        return audit_result
        
    except Exception as e:
        logging.error(f"Cookie audit failed: {str(e)}")
        return audit_result

if __name__ == "__main__":
    # Initialize security system
    init_security_system()
    
    # Example test cases would need actual test files
    print("Security system initialized successfully")