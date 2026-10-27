import os
import re
import uuid
from pathlib import Path
from werkzeug.utils import secure_filename

def format_size(size_bytes: int) -> str:
    """Convert bytes into a human-readable string (B, KB, MB, GB)."""
    if size_bytes < 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(size_bytes)
    unit_index = 0
    while size >= 1024.0 and unit_index < len(units) - 1:
        size /= 1024.0
        unit_index += 1
    if unit_index == 0:
        return f"{int(size)} B"
    return f"{size:.2f} {units[unit_index]}"

def parse_size_string(text: str) -> int | None:
    """
    Parses a string like '5MB', '5 MB', '500 kb', '2 gigabytes', '1048576 bytes'
    and returns size in bytes, or None if no valid size found.
    """
    if not text:
        return None
        
    pattern = r'(\d+(?:\.\d+)?)\s*(bytes?|b|kb|kib|kilobytes?|mb|mib|megabytes?|gb|gib|gigabytes?)'
    match = re.search(pattern, text, re.IGNORECASE)
    if not match:
        return None
        
    val = float(match.group(1))
    unit = match.group(2).lower()
    
    if unit in ["b", "byte", "bytes"]:
        return int(val)
    elif unit in ["kb", "kib", "kilobyte", "kilobytes"]:
        return int(val * 1024)
    elif unit in ["mb", "mib", "megabyte", "megabytes"]:
        return int(val * 1024 * 1024)
    elif unit in ["gb", "gib", "gigabyte", "gigabytes"]:
        return int(val * 1024 * 1024 * 1024)
        
    return None

def ensure_upload_directory(folder_path: str) -> None:
    """Creates the upload folder with restricted permissions if it does not exist."""
    try:
        os.makedirs(folder_path, exist_ok=True)
    except OSError as e:
        import logging
        logging.getLogger("FileGuard").warning(
            f"Could not create storage directory '{folder_path}': {e}"
        )

def generate_safe_filename(original_name: str) -> tuple[str, str]:
    """
    Sanitizes the original filename and generates a unique storage name using UUID
    to prevent directory traversal, overwrite collisions, and execution vulnerabilities.
    Returns (clean_display_name, unique_storage_filename).
    """
    clean_name = secure_filename(original_name)
    if not clean_name:
        clean_name = "unnamed_upload"
        
    ext = Path(clean_name).suffix.lower()
    unique_name = f"{uuid.uuid4().hex}{ext}"
    return clean_name, unique_name

def cleanup_file(file_path: str) -> None:
    """Safely removes a file if it exists without raising exceptions."""
    try:
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
    except Exception:
        pass
