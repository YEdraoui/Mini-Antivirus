import os
import hashlib
from pathlib import Path
import time
import psutil
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("antivirus_log.txt")
    ]
)

def load_signatures(signature_file="malicious_signatures.txt"):
    """Load malicious file signatures from a file."""
    try:
        with open(signature_file, 'r') as file:
            signatures = set(line.strip() for line in file if line.strip())
            logging.info(f"Loaded {len(signatures)} signatures from {signature_file}.")
            return signatures
    except FileNotFoundError:
        logging.warning(f"Signature file {signature_file} not found. Using an empty signature set.")
        return set()

def calculate_file_hash(file_path, algorithm="sha256"):
    """Calculate the hash of a file using the specified algorithm."""
    try:
        hasher = hashlib.new(algorithm)
        with open(file_path, 'rb') as file:
            while chunk := file.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        logging.error(f"Error calculating hash for {file_path}: {e}")
        return None

def is_process_running(script_name):
    """Check if a specific process is running."""
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if script_name in (proc.info.get('cmdline') or []):
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return False

def monitor_directory(directory, signatures, target_process="virus.py", interval=3):
    """Monitor directory for unauthorized file changes or creations."""
    logging.info(f"Starting directory monitoring: {directory}")
    baseline = {}

    # Capture initial file state
    for file_path in Path(directory).rglob('*'):
        if file_path.is_file():
            baseline[file_path] = calculate_file_hash(file_path)

    try:
        while True:
            if is_process_running(target_process):
                logging.warning(f"Detected running process: {target_process}")
            
            current_state = {}
            for file_path in Path(directory).rglob('*'):
                if file_path.is_file():
                    file_hash = calculate_file_hash(file_path)
                    if not file_hash:
                        continue

                    current_state[file_path] = file_hash

                    # Check for new or modified files
                    if file_path not in baseline:
                        logging.warning(f"New file detected: {file_path}")
                    elif baseline[file_path] != file_hash:
                        logging.warning(f"File modified: {file_path}")

                    # Check against malicious signatures
                    if file_hash in signatures:
                        logging.critical(f"Malicious file detected: {file_path}")

            # Update baseline with the current state
            baseline = current_state
            time.sleep(interval)
    except KeyboardInterrupt:
        logging.info("Monitoring stopped by user.")
    except Exception as e:
        logging.error(f"Error during monitoring: {e}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Antivirus Script")
    parser.add_argument("directory", help="Directory to monitor for changes")
    parser.add_argument(
        "signature_file",
        nargs="?",
        default="malicious_signatures.txt",
        help="File containing malicious signatures (default: malicious_signatures.txt)"
    )
    args = parser.parse_args()

    # Load signatures
    signatures = load_signatures(args.signature_file)

    # Monitor the specified directory
    if os.path.isdir(args.directory):
        monitor_directory(args.directory, signatures)
    else:
        logging.error(f"Directory not found: {args.directory}")
