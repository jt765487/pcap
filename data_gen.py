#!/usr/bin/env python3
"""
Test Data Generator

Creates a new pcap test file in the source directory each time a key is pressed,
and appends a corresponding CSV record. Reads target directories and CSV filename
from 'config.ini' in the script's directory.

CSV record format:
   <epoch time>,<full file path>,<SHA256-HASH result>

Filename format (for valid records):
    MAH11-YYYYMMDD-HHMMSS.pcap

Modes:
    SPACE   Generate a valid file in SRC_DIR and a matching CSV record.
    1       Generate 'missing_field' invalid CSV record.
    2       Generate 'empty_path' invalid CSV record.
    3       Generate 'extra_row' invalid CSV record.
    4       Generate 'garbled' invalid CSV record.
    r       Generate 'relative' path invalid CSV record (fails path checks).
    o       Generate 'outside' path invalid CSV record (fails path checks).
    t       Truncate (empty) the CSV file.
    q       Quit.
"""

import os
import sys
import termios
import tty
import time
import hashlib
import configparser
from pathlib import Path
from typing import Optional, Tuple # Added Tuple

# -----------------------------------------------------------------------------
# LOAD CONFIGURATION FROM config.ini
# -----------------------------------------------------------------------------
CONFIG_FILE_NAME = "config.ini"
script_dir = Path(__file__).parent.resolve()
CONFIG_PATH = script_dir / CONFIG_FILE_NAME

SRC_DIR_PATH: Optional[Path] = None
CSV_FILE_PATH: Optional[Path] = None

print(f"Attempting to load configuration from: {CONFIG_PATH}")

if not CONFIG_PATH.is_file():
    print(f"CRITICAL: Configuration file '{CONFIG_PATH}' not found.", file=sys.stderr)
    print("Please ensure config.ini exists in the same directory as this script.", file=sys.stderr)
    sys.exit(1)

config = configparser.ConfigParser()
try:
    config.read(CONFIG_PATH)
    # Read required values (with basic error handling)
    try:
        src_dir_str = config.get("Directories", "source_dir")
        csv_dir_str = config.get("Directories", "csv_dir")
        csv_filename = config.get("Files", "csv_filename")
    except (configparser.NoSectionError, configparser.NoOptionError) as e:
        print(f"CRITICAL: Missing required configuration in {CONFIG_PATH}: {e}", file=sys.stderr)
        sys.exit(1)

    SRC_DIR_PATH = Path(src_dir_str).resolve()
    CSV_DIR_PATH = Path(csv_dir_str).resolve()
    CSV_FILE_PATH = CSV_DIR_PATH / csv_filename

    print(f"  Using Source Dir : {SRC_DIR_PATH}")
    print(f"  Using CSV File   : {CSV_FILE_PATH}")

except configparser.Error as e:
    print(f"CRITICAL: Error parsing configuration file {CONFIG_PATH}: {e}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"CRITICAL: Unexpected error loading configuration: {e}", file=sys.stderr)
    sys.exit(1)

if SRC_DIR_PATH is None or CSV_FILE_PATH is None:
    print("CRITICAL: Failed to determine Source Directory or CSV File Path from config.", file=sys.stderr)
    sys.exit(1)

# -----------------------------------------------------------------------------
# FIXED TEST DATA VALUES
# -----------------------------------------------------------------------------
FILE_CONTENT = b"test file content for pcap"  # Test file content
FILE_HASH = hashlib.sha256(FILE_CONTENT).hexdigest()

# -----------------------------------------------------------------------------
# ENSURE DIRECTORIES EXIST
# -----------------------------------------------------------------------------
try:
    SRC_DIR_PATH.mkdir(parents=True, exist_ok=True)
    CSV_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    print("Directories ensured.")
except Exception as e:
    print(f"CRITICAL: Failed to create necessary directories: {e}", file=sys.stderr)
    sys.exit(1)


# -----------------------------------------------------------------------------
# HELPER FUNCTIONS
# -----------------------------------------------------------------------------
def getch():
    """
    Read a single character from standard input without waiting for Enter.
    Unix-like systems ONLY.
    """
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch


# --- CSV Record Generation Helpers ---

def generate_valid_record() -> Tuple[Optional[str], Optional[Path]]:
    """
    Generates a valid record:
      - Creates a new file in SRC_DIR with the content FILE_CONTENT.
      - Returns the CSV record (as a string) and the file's Path, or (None, None) on error.
    """
    epoch_time = int(time.time())
    current_time = time.localtime()
    filename = f"MAH11-{time.strftime('%Y%m%d-%H%M%S', current_time)}.pcap"
    file_path = SRC_DIR_PATH / filename

    try:
        with file_path.open("wb") as f:
            f.write(FILE_CONTENT)
        print(f"Created file: {file_path}")
    except Exception as e:
        print(f"Error creating file {file_path}: {e}", file=sys.stderr)
        return None, None # Return None for csv_line on error

    csv_line = f"{epoch_time},{file_path},{FILE_HASH}\n"
    return csv_line, file_path


# REMOVED: error_types_e and error_index_e globals

def generate_error_record(error_type: str) -> str:
    """
    Generates a CSV record with a specific deliberate formatting error.
    Supported error_type values:
      - "missing_field": Only one field present.
      - "empty_path": Second field is empty.
      - "extra_row": Contains an extra CSV row.
      - "garbled": Completely invalid CSV data.
    """
    epoch_time = int(time.time())
    # For a reference valid file path string, we use the valid filename format.
    current_time = time.localtime()
    filename = f"MAH11-{time.strftime('%Y%m%d-%H%M%S', current_time)}.pcap"
    # Use a constructed valid file path, though no file will be created here.
    valid_path = str(SRC_DIR_PATH / filename)

    csv_line = "" # Initialize
    if error_type == "missing_field":
        csv_line = f"{epoch_time}\n"
    elif error_type == "empty_path":
        csv_line = f"{epoch_time},,{FILE_HASH}\n" # Note the double comma
    elif error_type == "extra_row":
        csv_line = f"{epoch_time},{valid_path},{FILE_HASH}\nEXTRA,ROW,DATA\n"
    elif error_type == "garbled":
        csv_line = "garbled data, not, even close\nto csv format!\n" # Ensure newline
    else:
        # Fallback to a valid-looking format if unknown type is passed (defensive)
        print(f"Warning: Unknown error_type '{error_type}' in generate_error_record", file=sys.stderr)
        csv_line = f"{epoch_time},{valid_path},{FILE_HASH}\n"

    print(f"Generated error CSV ({error_type}): {csv_line.strip()}")
    return csv_line


# REMOVED: error_types_f and error_index_f globals

def generate_fail_record(fail_type: str) -> str:
    """
    Generates a CSV record with a specific invalid file path type.
    Supported fail_type values:
      - "relative": Uses a relative path (filename only).
      - "outside": Uses an absolute path outside SRC_DIR (e.g., under /tmp).
    """
    epoch_time = int(time.time())
    current_time = time.localtime()
    filename = f"MAH11-{time.strftime('%Y%m%d-%H%M%S', current_time)}.pcap"

    file_path_str = "" # Initialize
    if fail_type == "relative":
        file_path_str = filename  # relative: no directory info
    elif fail_type == "outside":
        # Ensure /tmp exists or use a more reliable temporary location if needed
        # For simplicity, using /tmp is common in examples
        temp_dir = Path("/tmp")
        try:
            temp_dir.mkdir(exist_ok=True) # Ensure /tmp exists
            file_path_str = str(temp_dir / filename)
        except OSError as e:
            print(f"Warning: Could not use /tmp for 'outside' path ({e}), using relative path instead.", file=sys.stderr)
            file_path_str = filename # Fallback if /tmp is not usable
    else:
         # Fallback to relative path if unknown type is passed (defensive)
        print(f"Warning: Unknown fail_type '{fail_type}' in generate_fail_record", file=sys.stderr)
        file_path_str = filename

    csv_line = f"{epoch_time},{file_path_str},{FILE_HASH}\n"
    print(f"Generated fail CSV ({fail_type}): {csv_line.strip()}")
    return csv_line


# -----------------------------------------------------------------------------
# MAIN FUNCTION
# -----------------------------------------------------------------------------
def main():
    print("\nTest Data Generator:")
    print(f"  Source Directory: {SRC_DIR_PATH}")
    print(f"  CSV File: {CSV_FILE_PATH}")
    print("Press key for action:")
    print("  SPACE : Create VALID file and append valid CSV record.")
    print("  Error Record Types (CSV format errors):")
    print("    1   : Append 'missing_field' invalid CSV record.")
    print("    2   : Append 'empty_path' invalid CSV record.")
    print("    3   : Append 'extra_row' invalid CSV record.")
    print("    4   : Append 'garbled' invalid CSV record.")
    print("  Failure Record Types (File path errors):")
    print("    r   : Append 'relative' path invalid CSV record.")
    print("    o   : Append 'outside' path invalid CSV record.")
    print("  Other Actions:")
    print("    t   : Truncate (empty) the CSV file.")
    print("    q   : Quit.")

    while True:
        ch = getch().lower() # Read character and convert to lower case
        csv_line_to_append: Optional[str] = None
        operation_description = "" # For consistent logging

        if ch == " ":
            # Generate valid record: create file and CSV entry.
            csv_line, _ = generate_valid_record() # We don't need file_path here
            if csv_line:
                csv_line_to_append = csv_line
                operation_description = "valid"
        elif ch == "1":
            csv_line_to_append = generate_error_record("missing_field")
            operation_description = "error (missing_field)"
        elif ch == "2":
            csv_line_to_append = generate_error_record("empty_path")
            operation_description = "error (empty_path)"
        elif ch == "3":
            csv_line_to_append = generate_error_record("extra_row")
            operation_description = "error (extra_row)"
        elif ch == "4":
            csv_line_to_append = generate_error_record("garbled")
            operation_description = "error (garbled)"
        elif ch == "r":
            csv_line_to_append = generate_fail_record("relative")
            operation_description = "fail (relative path)"
        elif ch == "o":
            csv_line_to_append = generate_fail_record("outside")
            operation_description = "fail (outside path)"
        elif ch == "t":
            try:
                # Open the CSV file in write mode to truncate (empty) it.
                with CSV_FILE_PATH.open("w", encoding="utf-8") as csv_file:
                    csv_file.truncate(0)
                print("CSV file truncated successfully.")
            except Exception as e:
                print(f"Error truncating CSV file: {e}", file=sys.stderr)
            # No CSV line to append for truncate operation
            continue # Go to next loop iteration
        elif ch == "q":
            print("\nQuitting test data generator.")
            break
        # else: Ignore other inputs silently

        # Append the generated line (if any)
        if csv_line_to_append:
            try:
                with CSV_FILE_PATH.open("a", encoding="utf-8") as csv_file:
                    csv_file.write(csv_line_to_append)
                print(f"Appended {operation_description} CSV: {csv_line_to_append.strip()}")
            except Exception as e:
                print(f"Error appending {operation_description} CSV record: {e}", file=sys.stderr)


if __name__ == '__main__':
    if os.name != 'posix':
        print("ERROR: This script requires a POSIX (Linux/macOS) environment.", file=sys.stderr)
        sys.exit(1)
    main()