# Remote Code Execution (RCE) simulation

import subprocess
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def execute_command(command):
    """
    Simulate command execution and check for RCE vulnerabilities.

    Args:
        command (str): The command to execute.

    Returns:
        str or None: The result of the command execution, or None if an error occurs.
    """
    dangerous_keywords = [';', '&&', '|', '`', '$(', '>', '<', '||', '&', '\\']
    if any(keyword in command for keyword in dangerous_keywords):
        logging.warning(f"Potential RCE attempt detected in command: {command}")
        return None

    try:
        result = subprocess.check_output(command, shell=True, text=True)
        logging.info(f"Command executed successfully: {command}")
        return result.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with error: {e}. Command: {command}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error executing command: {e}. Command: {command}")
        return None

if __name__ == "__main__":
    # Example usage
    user_input = "ls"  # Replace with user-provided input
    execute_command(user_input)
