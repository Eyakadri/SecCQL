# Remote Code Execution (RCE) simulation

import subprocess
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def execute_command(command):
    """
    Simulate command execution and check for RCE vulnerabilities.
    """
    dangerous_keywords = [';', '&&', '|', '`', '$(', '>', '<', '||', '&', '\\']
    if any(keyword in command for keyword in dangerous_keywords):
        logging.warning("Potential RCE attempt detected in command.")
        return None

    try:
        result = subprocess.check_output(command, shell=True, text=True)
        logging.info(f"Command executed successfully: {command}")
        return result
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with error: {e}")
        return None
    except Exception as e:
        logging.error(f"Error executing command: {e}")
        return None

if __name__ == "__main__":
    # Example usage
    user_input = "ls"  # Replace with user-provided input
    execute_command(user_input)
