import os
import hashlib
import sys

# Define a few known malicious file hashes (as an example)
MALICIOUS_SIGNATURES = [
    "a3027753445857731e9d9979ebf479ff"  # bad_file.txt hash
]

def calculate_file_hash(file_path):
    """Calculates the MD5 hash of a file."""
    hasher = hashlib.md5()
    try:
        with open(file_path, 'rb') as file:
            buf = file.read()
            hasher.update(buf)
        return hasher.hexdigest()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None

def scan_file(file_path):
    """Scans a file for malicious content."""
    print(f"Scanning file: {file_path}")
    
    # Check if the file hash matches any known malicious signatures
    file_hash = calculate_file_hash(file_path)
    if file_hash in MALICIOUS_SIGNATURES:
        print(f"Warning! The file {file_path} is flagged as malicious!")
    else:
        print(f"The file {file_path} seems clean.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 mini_antivirus.py <file_path>")
    else:
        file_path = sys.argv[1]
        scan_file(file_path)
