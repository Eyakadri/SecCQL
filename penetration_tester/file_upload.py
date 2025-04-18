import os
import logging
import re
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Union, Optional
try:
    import magic
except ImportError:
    magic = None

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

# Security constants
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
MAX_FILENAME_LENGTH = 255
MAX_MALICIOUS_ATTEMPTS = 5
ATTEMPT_WINDOW_HOURS = 1
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

# Security state
MALICIOUS_UPLOAD_ATTEMPTS: Dict[str, Dict[str, Union[int, datetime]]] = {}

def validate_file_extension(file_path: str) -> bool:
    """Validate file extension against allowed types."""
    _, ext = os.path.splitext(file_path)
    return ext.lower() in ALLOWED_EXTENSIONS

def validate_file_size(file_path: str) -> bool:
    """Validate file size constraints."""
    file_size = os.path.getsize(file_path)
    return 0 < file_size <= MAX_FILE_SIZE

def detect_malicious_content(content: bytes) -> bool:
    """Scan content for malicious patterns."""
    try:
        decoded = content.decode('utf-8', errors='ignore')
        return any(pattern.search(decoded) for pattern in MALICIOUS_PATTERNS)
    except UnicodeDecodeError:
        return True  # Binary files in text extensions are suspicious

def verify_mime_type(file_path: str, ext: str) -> bool:
    """Verify file MIME type matches extension."""
    if not magic:
        logging.warning("MIME validation skipped: python-magic not installed")
        return True
        
    try:
        mime = magic.from_file(file_path, mime=True)
        expected_mime = ALLOWED_EXTENSIONS.get(ext.lower())
        if mime != expected_mime:
            logging.warning(f"MIME type mismatch: {mime} (expected: {expected_mime})")
        return mime == expected_mime
    except Exception as e:
        logging.warning(f"MIME validation failed: {str(e)}", exc_info=True)
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

        # Extension validation
        _, ext = os.path.splitext(file_path)
        if not validate_file_extension(file_path):
            logging.warning(f"Invalid file extension: {ext}")
            return False

        # Size validation
        if not validate_file_size(file_path):
            logging.warning(f"Invalid file size: {os.path.getsize(file_path)}")
            return False

        # Content validation
        with open(file_path, 'rb') as f:
            content = f.read(8192)  # Read first 8KB
            
            # Check for binary in text files
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

# In your file_upload.py implementation, update the prevent_directory_traversal function:
def prevent_directory_traversal(filename: str) -> str:
    """
    Secure filename sanitization with comprehensive checks.
    """
    try:
        if not filename:
            return 'invalid_filename'
            
        # Normalize path separators
        filename = filename.replace('\\', '/')
        
        # Remove path traversal attempts
        filename = re.sub(
            r'(\.\.|%2e%2e|%252e%252e|\.\/|\/\.)[\\\/]?', 
            '', 
            filename, 
            flags=re.IGNORECASE
        )
        
        # Get basename and sanitize
        basename = os.path.basename(filename)
        basename = re.sub(r'[^\w\-_. ]', '', basename).strip()
        basename = basename[:MAX_FILENAME_LENGTH]
        
        if not basename:  # Handle empty results after sanitization
            return 'invalid_filename'
            
        # Check reserved names
        if any(
            re.match(fr'(?i)^{reserved}(\.|$)', basename)
            for reserved in RESERVED_NAMES
        ):
            return 'invalid_filename'
            
        # Check for double extensions
        if len(basename.split('.')) > 2:
            logging.warning("Potential double extension detected")
            return 'invalid_filename'
            
        return basename
        
    except Exception as e:
        logging.error(f"Filename sanitization failed: {str(e)}")
        return 'invalid_filename'

def track_malicious_attempt(ip_address: str) -> bool:
    """
    Track and respond to malicious attempts with rate limiting.
    
    Args:
        ip_address: Origin IP of the request
        
    Returns:
        bool: True if IP should be blocked
    """
    try:
        now = datetime.now()
        record = MALICIOUS_UPLOAD_ATTEMPTS.get(ip_address, {
            'count': 0,
            'first_seen': now,
            'last_seen': now
        })
        
        # Reset if window expired
        if now - record['first_seen'] > timedelta(hours=ATTEMPT_WINDOW_HOURS):
            record = {'count': 1, 'first_seen': now, 'last_seen': now}
        else:
            record['count'] += 1
            record['last_seen'] = now
            
        MALICIOUS_UPLOAD_ATTEMPTS[ip_address] = record
        
        if record['count'] >= MAX_MALICIOUS_ATTEMPTS:
            logging.warning(f"IP {ip_address} blocked - too many attempts")
            return True
            
        logging.info(f"Security event from {ip_address} - attempt {record['count']}")
        return False
        
    except Exception as e:
        logging.error(f"Failed to track malicious attempt: {str(e)}")
        return False

def process_file_upload(
    file_path: str,
    ip_address: str = 'unknown',
    user_id: Optional[str] = None
) -> Dict[str, Union[bool, str]]:
    """
    Secure file upload processing pipeline.
    
    Args:
        file_path: Path to uploaded file
        ip_address: Client IP address
        user_id: Optional user identifier
        
    Returns:
        dict: {
            'success': bool,
            'message': str,
            'sanitized_name': str,
            'checksum': Optional[str]
        }
    """
    result = {
        'success': False,
        'message': '',
        'sanitized_name': '',
        'checksum': None
    }
    
    try:
        # Initial validation
        if not os.path.exists(file_path):
            result['message'] = 'File not found'
            return result
            
        # Sanitize filename
        sanitized_name = prevent_directory_traversal(os.path.basename(file_path))
        result['sanitized_name'] = sanitized_name
        
        if sanitized_name == 'invalid_filename':
            result['message'] = 'Invalid filename'
            track_malicious_attempt(ip_address)
            return result
            
        # Security validation
        if not is_file_safe(file_path):
            result['message'] = 'File failed security checks'
            track_malicious_attempt(ip_address)
            return result
            
        # Generate checksum
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256()
            while chunk := f.read(8192):
                file_hash.update(chunk)
            result['checksum'] = file_hash.hexdigest()
        
        result['success'] = True
        result['message'] = 'File uploaded successfully'
        logging.info(
            f"File upload success: {sanitized_name} "
            f"from {ip_address} (user: {user_id})"
        )
        return result
        
    except Exception as e:
        logging.error(f"Upload processing failed: {str(e)}", exc_info=True)
        result['message'] = 'Server error during processing'
        return result

def test_insecure_cookies(
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
            
            # Secure flag check
            if not cookie.get('secure', False) and secure_origin:
                issues.append('missing secure flag')
                
            # HttpOnly check
            if not cookie.get('httpOnly', False):
                issues.append('missing HttpOnly flag')
                
            # SameSite check
            samesite = cookie.get('sameSite', '').lower()
            if samesite not in {'strict', 'lax'}:
                issues.append('invalid SameSite value')
                
            # Prefix checks
            if name.startswith('__Secure-') and not cookie.get('secure', False):
                issues.append('__Secure- prefix requires secure flag')
                
            if name.startswith('__Host-') and not (
                cookie.get('secure', False) and 
                cookie.get('path', '') == '/' and
                not cookie.get('domain', '')
            ):
                issues.append('__Host- prefix requirements not met')
                
            # Domain/path checks
            if cookie.get('domain', '').startswith('.'):
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
    # Example test cases
    test_files = [
        ('legit.txt', True),
        ('malicious.php', False),
        ('../../etc/passwd', False),
        ('normal.doc', True),
        ('script.jpg', False)  # Would fail content check
    ]
    
    for filename, should_pass in test_files:
        result = process_file_upload(filename)
        assert result['success'] == should_pass, \
            f"Test failed for {filename}"
    
    print("All security tests completed")