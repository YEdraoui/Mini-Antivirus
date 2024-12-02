import os
import time
import shutil
from pathlib import Path

# Define directories
source_dir = Path("test_dir")  # Use Path object
destination_dir = Path("test_dir/virus_output")  # Use Path object

# Ensure the directories exist
source_dir.mkdir(parents=True, exist_ok=True)
destination_dir.mkdir(parents=True, exist_ok=True)

# Simulate malicious actions
while True:
    # Create a new file
    new_file = source_dir / f"new_file_{int(time.time())}.txt"
    with open(new_file, 'w') as f:
        f.write("This is a malicious file.")

    print(f"Created new file: {new_file}")

    # Copy an existing file
    for file in source_dir.glob("*"):
        if file.is_file():
            shutil.copy(file, destination_dir / file.name)
            print(f"Copied {file} to {destination_dir}")

    # Modify an existing file
    existing_file = source_dir / "clean_file.txt"
    if existing_file.exists():
        with open(existing_file, 'a') as f:
            f.write("\nMalicious content added!")
        print(f"Modified file: {existing_file}")

    time.sleep(5)  
