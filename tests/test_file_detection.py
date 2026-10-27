import os
import tempfile
import pytest
from services.file_detection_service import FileDetectionService

def test_detect_valid_pdf_magic_bytes():
    # Write sample PDF header
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        f.write(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF")
        temp_path = f.name
        
    try:
        meta = FileDetectionService.inspect_file(temp_path, "sample.pdf", "application/pdf")
        assert meta["detected_category"] == "pdf"
        assert meta["extension_match"] is True
        assert meta["signature_verified"] is True
        assert meta["is_dangerous"] is False
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

def test_detect_disguised_executable():
    # DOS/Windows executable header (MZ) disguised as PDF
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        f.write(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")
        temp_path = f.name

    try:
        meta = FileDetectionService.inspect_file(temp_path, "malware.pdf", "application/pdf")
        assert meta["is_dangerous"] is True
        assert "Windows Executable" in meta["danger_reason"]
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

def test_detect_png_image():
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        f.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01")
        temp_path = f.name

    try:
        meta = FileDetectionService.inspect_file(temp_path, "graphic.png", "image/png")
        assert meta["detected_category"] == "image"
        assert meta["extension_match"] is True
        assert meta["signature_verified"] is True
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

def test_detect_plain_text():
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        f.write(b"Hello world! This is a plain text file without binary data.")
        temp_path = f.name

    try:
        meta = FileDetectionService.inspect_file(temp_path, "notes.txt", "text/plain")
        assert meta["detected_category"] == "text"
        assert meta["extension_match"] is True
        assert meta["signature_verified"] is True
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
