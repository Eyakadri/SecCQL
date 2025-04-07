# Malicious file upload testing

import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

def is_file_safe(file_path):
    """
    Check if the uploaded file is safe by validating its extension, size, and content.
    """
    allowed_extensions = {'.txt', '.jpg', '.png', '.pdf'}
    _, ext = os.path.splitext(file_path)

    # Validate file extension
    if ext.lower() not in allowed_extensions:
        logging.warning(f"File {file_path} has an invalid extension: {ext}")
        return False

    # Validate file size
    file_size = os.path.getsize(file_path)
    if file_size > MAX_FILE_SIZE:
        logging.warning(f"File {file_path} exceeds the maximum allowed size of {MAX_FILE_SIZE} bytes.")
        return False

    # Validate file content
    try:
        with open(file_path, 'rb') as f:
            content = f.read(1024)  # Read the first 1KB of the file
            if b'<script>' in content or b'<?php' in content:
                logging.warning(f"File {file_path} contains potentially malicious content.")
                return False
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return False

    logging.info(f"File {file_path} passed validation.")
    return True

def prevent_directory_traversal(file_name):
    """
    Prevent directory traversal by sanitizing the file name.
    """
    sanitized_name = os.path.basename(file_name)
    if sanitized_name != file_name:
        logging.warning(f"Potential directory traversal attempt detected: {file_name}")
    return sanitized_name

def test_file_upload(file_path):
    """
    Simulate a file upload and test for vulnerabilities.
    """
    if not os.path.exists(file_path):
        logging.error(f"File {file_path} does not exist.")
        return False

    sanitized_file_name = prevent_directory_traversal(os.path.basename(file_path))  # Pass only the file name
    sanitized_file_path = os.path.join(os.path.dirname(file_path), sanitized_file_name)

    if is_file_safe(sanitized_file_path):  # Use sanitized file path
        logging.info(f"File {sanitized_file_name} uploaded successfully.")
        return True
    else:
        logging.error(f"File {sanitized_file_name} failed validation and was not uploaded.")
        return False

if __name__ == "__main__":
    # Example usage
    test_file = "example.txt"  # Replace with the path to the file you want to test
    test_file_upload(test_file)