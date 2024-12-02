import os
import hashlib
from pathlib import Path
import time
import psutil  # For monitoring running processes

# Load known malicious file hashes
def load_signatures(signature_file="malicious_signatures.txt"):
    try:
        with open(signature_file, 'r') as file:
            return set(line.strip() for line in file if line.strip())
    except FileNotFoundError:
        print(f"Signature file {signature_file} not found. Using an empty signature set.")
        return set()

# Calculate hash of a file
def calculate_file_hash(file_path, algorithm="sha256"):
    try:
        hasher = hashlib.new(algorithm)
        with open(file_path, 'rb') as file:
            while chunk := file.read(8192):  # Read file in chunks
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None

# Monitor directory for changes
def monitor_directory(directory, signatures, target_process="virus.py", interval=3):
    print(f"Monitoring directory: {directory}")
    baseline = {}

    # Capture initial state
    for file_path in Path(directory).rglob('*'):
        if file_path.is_file():
            baseline[file_path] = calculate_file_hash(file_path)

    while True:
        # Check if the virus process is running
        if is_process_running(target_process):
            print(f"Warning: {target_process} is running!")
            # Check for new or modified files
            current_state = {}
            for file_path in Path(directory).rglob('*'):
                if file_path.is_file():
                    file_hash = calculate_file_hash(file_path)
                    current_state[file_path] = file_hash

                    # Detect unauthorized actions
                    if file_path not in baseline:
                        print(f"Unauthorized file creation: {file_path}")
                    elif baseline[file_path] != file_hash:
                        print(f"Unauthorized file modification: {file_path}")

            # Update baseline
            baseline = current_state
        else:
            print(f"{target_process} is not running.")

        time.sleep(interval)

# Check if a specific process is running
def is_process_running(script_name):
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = proc.info['cmdline']
            if cmdline and script_name in cmdline:  # Ensure cmdline is not None
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return False


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Antivirus Script")
    parser.add_argument("directory", help="Directory to monitor for changes")
    parser.add_argument("signature_file", nargs="?", default="malicious_signatures.txt", help="File containing malicious signatures")
    args = parser.parse_args()

    # Load signatures
    signatures = load_signatures(args.signature_file)

    # Monitor the specified directory
    try:
        monitor_directory(args.directory, signatures)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
