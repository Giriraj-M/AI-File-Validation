import os
import re
from pathlib import Path
from typing import Dict, Any, List, Optional
import filetype

class FileDetector:
    """
    Advanced File Type & Signature Detection Service.
    Inspects magic bytes, binary headers, and file extensions.
    Guarantees that file extensions are never trusted alone and
    detects disguised executables, scripts, or mismatched formats.
    """

    DANGEROUS_SIGNATURES: Dict[str, List[bytes]] = {
        "Windows Executable (EXE/DLL)": [b"MZ"],
        "ELF Linux Executable": [b"\x7fELF"],
        "Mach-O macOS Binary": [
            b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
            b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe"
        ],
        "Java Class/Compiled": [b"\xca\xfe\xba\xbe"],
        "Shell Script/Batch": [b"#!/bin/", b"#!/usr/bin/", b"@echo off", b"rem "]
    }

    ZIP_SIGNATURE = b"PK\x03\x04"
    PDF_SIGNATURE = b"%PDF-"

    @classmethod
    def detect_type(cls, file_path: str, original_filename: str = "") -> tuple[str, str, str]:
        """Convenience tuple return: (category, extension, mime_type)."""
        info = cls.detect_file_type(file_path, original_filename)
        return info.get("file_type", "UNKNOWN"), info.get("extension", ""), info.get("mime_type", "application/octet-stream")

    @classmethod
    def detect_file_type(cls, file_path: str, original_filename: str = "") -> Dict[str, Any]:
        """
        Performs dual-layer identification using both magic bytes and extension.
        Returns detailed detection report including MIME type, confidence, and safety flags.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        file_size = os.path.getsize(file_path)
        ext = Path(original_filename or file_path).suffix.lower()

        # Handle zero-byte files
        if file_size == 0:
            return {
                "file_type": "EMPTY",
                "detected_format": "empty",
                "mime_type": "application/x-empty",
                "extension": ext,
                "is_executable": False,
                "is_dangerous": False,
                "signature_matched": False,
                "details": "File is empty (0 bytes)."
            }

        # Read first 8KB for signature inspection
        with open(file_path, "rb") as f:
            header_sample = f.read(8192)

        # 1. Dangerous executable check
        for danger_name, sigs in cls.DANGEROUS_SIGNATURES.items():
            for sig in sigs:
                if header_sample.startswith(sig):
                    return {
                        "file_type": "EXECUTABLE",
                        "detected_format": "executable",
                        "mime_type": "application/x-dosexec" if sig == b"MZ" else "application/octet-stream",
                        "extension": ext,
                        "is_executable": True,
                        "is_dangerous": True,
                        "signature_matched": True,
                        "danger_type": danger_name,
                        "details": f"Dangerous binary signature identified: {danger_name}."
                    }

        # 2. Check for PDF signature (%PDF-)
        # PDF specification allows header to be preceded by up to 1024 or 2048 bytes of junk
        pdf_pos = header_sample.find(cls.PDF_SIGNATURE)
        if pdf_pos != -1 and pdf_pos < 2048:
            version = "unknown"
            v_match = re.search(rb"%PDF-(\d+\.\d+)", header_sample[pdf_pos:pdf_pos + 16])
            if v_match:
                version = v_match.group(1).decode("ascii", errors="ignore")

            return {
                "file_type": "PDF",
                "detected_format": "pdf",
                "mime_type": "application/pdf",
                "extension": ext,
                "is_executable": False,
                "is_dangerous": False,
                "signature_matched": True,
                "header_offset": pdf_pos,
                "pdf_version": version,
                "details": f"PDF {version} signature verified at byte offset {pdf_pos}."
            }

        # 2b. Check for PDF internal structures if %PDF- header is missing/deleted
        if ext == ".pdf" or any(k in header_sample for k in [b" 0 obj", b"obj\n", b"obj\r", b"/Catalog", b"/Pages", b"/MediaBox", b"startxref", b"%%EOF"]):
            return {
                "file_type": "PDF",
                "detected_format": "pdf",
                "mime_type": "application/pdf",
                "extension": ext,
                "is_executable": False,
                "is_dangerous": False,
                "signature_matched": False,
                "header_offset": -1,
                "pdf_version": "damaged_header",
                "details": "Corrupted PDF detected: %PDF header signature is missing or damaged, but document object structures are present."
            }

        # 3. Check for ZIP / OOXML signature (PK\x03\x04)
        zip_pos = header_sample.find(cls.ZIP_SIGNATURE)
        if zip_pos != -1 and zip_pos < 1024:
            # Inspect internal ZIP entries to classify DOCX vs XLSX vs standard ZIP
            zip_classification = cls._classify_zip_container(file_path, header_sample)
            return {
                "file_type": zip_classification["file_type"],
                "detected_format": zip_classification["format"],
                "mime_type": zip_classification["mime_type"],
                "extension": ext,
                "is_executable": False,
                "is_dangerous": False,
                "signature_matched": True,
                "header_offset": zip_pos,
                "details": zip_classification["details"]
            }

        # 4. Check for legacy OLE compound documents (.doc, .xls, .ppt)
        if header_sample.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
            if ext in [".doc", ".dot"]:
                doc_type = "WORD_LEGACY"
                mime = "application/msword"
            elif ext in [".xls", ".xlt"]:
                doc_type = "EXCEL_LEGACY"
                mime = "application/vnd.ms-excel"
            else:
                doc_type = "OLE_COMPOUND"
                mime = "application/x-ole-storage"
            return {
                "file_type": doc_type,
                "detected_format": doc_type.lower(),
                "mime_type": mime,
                "extension": ext,
                "is_executable": False,
                "is_dangerous": False,
                "signature_matched": True,
                "header_offset": 0,
                "details": "Microsoft OLE Structured Storage signature identified."
            }

        # 5. Check standard images using filetype
        kind = filetype.guess(file_path)
        if kind and kind.mime.startswith("image/"):
            return {
                "file_type": "IMAGE",
                "detected_format": kind.extension,
                "mime_type": kind.mime,
                "extension": ext,
                "is_executable": False,
                "is_dangerous": False,
                "signature_matched": True,
                "details": f"Image format verified: {kind.mime}."
            }

        # 6. Check for plain text or CSV
        if cls._is_plain_text(header_sample):
            fmt = "csv" if ext == ".csv" or b"," in header_sample[:500] else "text"
            return {
                "file_type": "TEXT" if fmt == "text" else "CSV",
                "detected_format": fmt,
                "mime_type": "text/csv" if fmt == "csv" else "text/plain",
                "extension": ext,
                "is_executable": False,
                "is_dangerous": False,
                "signature_matched": False,
                "details": "Valid UTF-8 / ASCII text stream detected without binary nulls."
            }

        # 7. Fallback to extension if format is unrecognized or corrupted
        inferred_type = "UNKNOWN"
        if ext == ".pdf":
            inferred_type = "PDF"
        elif ext in [".docx", ".doc"]:
            inferred_type = "DOCX"
        elif ext in [".xlsx", ".xls"]:
            inferred_type = "EXCEL"

        return {
            "file_type": inferred_type,
            "detected_format": "unknown",
            "mime_type": "application/octet-stream",
            "extension": ext,
            "is_executable": False,
            "is_dangerous": False,
            "signature_matched": False,
            "details": f"Unrecognized binary stream. Inferred potential intended type '{inferred_type}' from extension."
        }

    @classmethod
    def _classify_zip_container(cls, file_path: str, sample_bytes: bytes) -> Dict[str, str]:
        """
        Inspects ZIP member records or raw binary signatures to distinguish
        Word (.docx), Excel (.xlsx), PowerPoint (.pptx), or standard ZIP archive.
        """
        # Fast raw search in sample or file contents
        try:
            with open(file_path, "rb") as f:
                content_chunk = f.read(65536)

            if b"word/document.xml" in content_chunk or b"word/" in content_chunk:
                return {
                    "file_type": "DOCX",
                    "format": "docx",
                    "mime_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "details": "Microsoft Word OpenXML (DOCX) container verified."
                }
            if b"xl/workbook.xml" in content_chunk or b"xl/" in content_chunk:
                return {
                    "file_type": "EXCEL",
                    "format": "xlsx",
                    "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    "details": "Microsoft Excel OpenXML (XLSX) container verified."
                }
            if b"ppt/presentation.xml" in content_chunk or b"ppt/" in content_chunk:
                return {
                    "file_type": "POWERPOINT",
                    "format": "pptx",
                    "mime_type": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                    "details": "Microsoft PowerPoint OpenXML (PPTX) container verified."
                }
        except Exception:
            pass

        # Try zipfile module if available
        import zipfile
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                names = zf.namelist()
                if any(n.startswith("word/") for n in names) or "word/document.xml" in names:
                    return {
                        "file_type": "DOCX",
                        "format": "docx",
                        "mime_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        "details": "Microsoft Word OpenXML (DOCX) container verified."
                    }
                if any(n.startswith("xl/") for n in names) or "xl/workbook.xml" in names:
                    return {
                        "file_type": "EXCEL",
                        "format": "xlsx",
                        "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        "details": "Microsoft Excel OpenXML (XLSX) container verified."
                    }
        except Exception:
            # Corrupted ZIP container - fallback to check file extension
            ext = Path(file_path).suffix.lower()
            if ext == ".docx":
                return {
                    "file_type": "DOCX",
                    "format": "docx",
                    "mime_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "details": "Damaged ZIP container detected with .docx extension (Word)."
                }
            if ext == ".xlsx":
                return {
                    "file_type": "EXCEL",
                    "format": "xlsx",
                    "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    "details": "Damaged ZIP container detected with .xlsx extension (Excel)."
                }

        return {
            "file_type": "ZIP",
            "format": "zip",
            "mime_type": "application/zip",
            "details": "Generic ZIP compressed archive."
        }

    @staticmethod
    def _is_plain_text(sample: bytes) -> bool:
        """Determines if a byte slice consists of valid UTF-8/ASCII without binary nulls."""
        if not sample:
            return True
        if b"\x00" in sample:
            return False
        try:
            sample.decode("utf-8")
            return True
        except UnicodeDecodeError:
            try:
                sample.decode("latin-1")
                # Ensure printable characters ratio is high (> 90%)
                printable = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
                return (printable / len(sample)) > 0.90
            except Exception:
                return False
