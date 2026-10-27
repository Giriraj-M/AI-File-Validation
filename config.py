import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent

class Config:
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "fileguard-ai-production-secret-change-in-prod-8f9a2b")
    
    # Private storage directory for uploaded files (not publicly accessible via static route)
    UPLOAD_FOLDER = os.environ.get(
        "UPLOAD_FOLDER", 
        str(BASE_DIR / "instance" / "uploads")
    )
    
    # Max content upload length (default: 64MB)
    MAX_CONTENT_LENGTH_MB = int(os.environ.get("MAX_CONTENT_LENGTH_MB", "64"))
    MAX_CONTENT_LENGTH = MAX_CONTENT_LENGTH_MB * 1024 * 1024

    # AI Configuration (Gemini 3.5 Flash)
    AI_PROVIDER = os.environ.get("AI_PROVIDER", "gemini").lower()
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()
    GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash")
    
    # Folder for recovered/repaired files, reports, and temp storage
    RECOVERED_FOLDER = os.environ.get(
        "RECOVERED_FOLDER",
        str(BASE_DIR / "instance" / "recovered_files")
    )
    REPORTS_FOLDER = os.environ.get(
        "REPORTS_FOLDER",
        str(BASE_DIR / "instance" / "reports")
    )
    TEMP_CORRUPTED_FOLDER = os.environ.get(
        "TEMP_CORRUPTED_FOLDER",
        str(BASE_DIR / "instance" / "temp_corrupted")
    )
    
    # Folder for corrupted files, reports, and temp storage
    CORRUPTED_FOLDER = os.environ.get(
        "CORRUPTED_FOLDER",
        str(BASE_DIR / "instance" / "corrupted_files")
    )
    CORRUPTION_REPORTS_FOLDER = os.environ.get(
        "CORRUPTION_REPORTS_FOLDER",
        str(BASE_DIR / "instance" / "corruption_reports")
    )

    # Recovery Execution Limits
    MAX_RECOVERY_ATTEMPTS = int(os.environ.get("MAX_RECOVERY_ATTEMPTS", "7"))
    RECOVERY_TIMEOUT_SECONDS = int(os.environ.get("RECOVERY_TIMEOUT_SECONDS", "120"))
    
    # History storage
    HISTORY_FILE = str(BASE_DIR / "instance" / "validation_history.json")
    RECOVERY_HISTORY_FILE = str(BASE_DIR / "instance" / "recovery_history.json")
    CORRUPTION_HISTORY_FILE = str(BASE_DIR / "instance" / "corruption_history.json")
    BATCH_HISTORY_FILE = str(BASE_DIR / "instance" / "batch_history.json")
    
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
