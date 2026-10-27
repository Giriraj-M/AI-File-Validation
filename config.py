import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent

# Check if running in a serverless / read-only environment like Vercel or AWS Lambda
IS_VERCEL = bool(
    os.environ.get("VERCEL") 
    or os.environ.get("VERCEL_ENV") 
    or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
)

if IS_VERCEL:
    # On Vercel, the app root /var/task is read-only; only /tmp is writable
    STORAGE_DIR = Path("/tmp") / "ai-file-validation"
else:
    STORAGE_DIR = BASE_DIR / "instance"

def _resolve_folder(env_name: str, default_subfolder: str) -> str:
    env_val = os.environ.get(env_name)
    if IS_VERCEL:
        if env_val and (env_val.startswith("/tmp") or env_val.startswith("\\tmp")):
            return env_val
        return (STORAGE_DIR / default_subfolder).as_posix()
    if env_val:
        p = Path(env_val)
        return str(p if p.is_absolute() else (BASE_DIR / p))
    return str(STORAGE_DIR / default_subfolder)

def _resolve_file(env_name: str, default_filename: str) -> str:
    env_val = os.environ.get(env_name)
    if IS_VERCEL:
        if env_val and (env_val.startswith("/tmp") or env_val.startswith("\\tmp")):
            return env_val
        return (STORAGE_DIR / default_filename).as_posix()
    if env_val:
        p = Path(env_val)
        return str(p if p.is_absolute() else (BASE_DIR / p))
    return str(STORAGE_DIR / default_filename)

class Config:
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "fileguard-ai-production-secret-change-in-prod-8f9a2b")
    IS_VERCEL = IS_VERCEL
    
    # Private storage directory for uploaded files (not publicly accessible via static route)
    UPLOAD_FOLDER = _resolve_folder("UPLOAD_FOLDER", "uploads")
    
    # Max content upload length (default: 64MB)
    MAX_CONTENT_LENGTH_MB = int(os.environ.get("MAX_CONTENT_LENGTH_MB", "64"))
    MAX_CONTENT_LENGTH = MAX_CONTENT_LENGTH_MB * 1024 * 1024

    # AI Configuration (Gemini 3.5 Flash)
    AI_PROVIDER = os.environ.get("AI_PROVIDER", "gemini").lower()
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()
    GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash")
    
    # Folder for recovered/repaired files, reports, and temp storage
    RECOVERED_FOLDER = _resolve_folder("RECOVERED_FOLDER", "recovered_files")
    REPORTS_FOLDER = _resolve_folder("REPORTS_FOLDER", "reports")
    TEMP_CORRUPTED_FOLDER = _resolve_folder("TEMP_CORRUPTED_FOLDER", "temp_corrupted")
    
    # Folder for corrupted files, reports, and temp storage
    CORRUPTED_FOLDER = _resolve_folder("CORRUPTED_FOLDER", "corrupted_files")
    CORRUPTION_REPORTS_FOLDER = _resolve_folder("CORRUPTION_REPORTS_FOLDER", "corruption_reports")

    # Recovery Execution Limits
    MAX_RECOVERY_ATTEMPTS = int(os.environ.get("MAX_RECOVERY_ATTEMPTS", "7"))
    RECOVERY_TIMEOUT_SECONDS = int(os.environ.get("RECOVERY_TIMEOUT_SECONDS", "120"))
    
    # History storage
    HISTORY_FILE = _resolve_file("HISTORY_FILE", "validation_history.json")
    RECOVERY_HISTORY_FILE = _resolve_file("RECOVERY_HISTORY_FILE", "recovery_history.json")
    CORRUPTION_HISTORY_FILE = _resolve_file("CORRUPTION_HISTORY_FILE", "corruption_history.json")
    BATCH_HISTORY_FILE = _resolve_file("BATCH_HISTORY_FILE", "batch_history.json")
    
    # Supported File Types Configuration (Central Source of Truth)
    FILE_TYPES = {
        "pdf": {
            "name": "PDF",
            "extensions": [".pdf"],
            "mimes": ["application/pdf"],
            "signatures": [b"%PDF-"],
            "description": "Portable Document Format"
        },
        "word": {
            "name": "Word",
            "extensions": [".doc", ".docx"],
            "mimes": [
                "application/msword",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            ],
            "signatures": [
                b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",  # Legacy .doc
                b"PK\x03\x04"                          # Office Open XML .docx (ZIP)
            ],
            "description": "Microsoft Word Document"
        },
        "excel": {
            "name": "Excel",
            "extensions": [".xls", ".xlsx"],
            "mimes": [
                "application/vnd.ms-excel",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            ],
            "signatures": [
                b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",  # Legacy .xls
                b"PK\x03\x04"                          # Office Open XML .xlsx (ZIP)
            ],
            "description": "Microsoft Excel Spreadsheet"
        },
        "powerpoint": {
            "name": "PowerPoint",
            "extensions": [".ppt", ".pptx"],
            "mimes": [
                "application/vnd.ms-powerpoint",
                "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            ],
            "signatures": [
                b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",  # Legacy .ppt
                b"PK\x03\x04"                          # Office Open XML .pptx (ZIP)
            ],
            "description": "Microsoft PowerPoint Presentation"
        },
        "image": {
            "name": "Image",
            "extensions": [".jpg", ".jpeg", ".png", ".gif", ".webp"],
            "mimes": [
                "image/jpeg",
                "image/png",
                "image/gif",
                "image/webp"
            ],
            "signatures": [
                b"\xFF\xD8\xFF",                        # JPEG
                b"\x89PNG\r\n\x1a\n",                  # PNG
                b"GIF87a", b"GIF89a",                   # GIF
                b"RIFF"                                 # WEBP (RIFF....WEBP)
            ],
            "description": "Image Files (PNG, JPG, GIF, WebP)"
        },
        "text": {
            "name": "Text",
            "extensions": [".txt"],
            "mimes": ["text/plain"],
            "signatures": [],
            "description": "Plain Text Document"
        },
        "csv": {
            "name": "CSV",
            "extensions": [".csv"],
            "mimes": ["text/csv", "text/plain", "application/csv"],
            "signatures": [],
            "description": "Comma Separated Values"
        },
        "json": {
            "name": "JSON",
            "extensions": [".json"],
            "mimes": ["application/json", "text/plain"],
            "signatures": [],
            "description": "JavaScript Object Notation"
        },
        "zip": {
            "name": "Archive",
            "extensions": [".zip"],
            "mimes": ["application/zip", "application/x-zip-compressed"],
            "signatures": [b"PK\x03\x04"],
            "description": "ZIP Compressed Archive"
        }
    }

    # Dangerous executable signatures to immediately flag regardless of extension
    DANGEROUS_SIGNATURES = {
        "Windows Executable (EXE/DLL)": [b"MZ"],
        "ELF Linux Executable": [b"\x7fELF"],
        "Mach-O macOS Binary": [b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"],
        "Java Class/Compiled": [b"\xca\xfe\xba\xbe"],
        "Shell Script/Batch": [b"#!/bin/", b"#!/usr/bin/", b"@echo off", b"rem "]
    }
