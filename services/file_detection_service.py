import os
import zipfile
from pathlib import Path
import filetype
from config import Config

class FileDetectionService:
    """
    Robust, multi-layered file type and signature detection service.
    Combines magic byte inspection, binary structure analysis, and MIME cross-checking.
    """

    @classmethod
    def inspect_file(cls, file_path: str, original_filename: str, client_mime: str = "") -> dict:
        """
        Performs deep inspection of the file content and returns comprehensive metadata.
        """
        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        extension = Path(original_filename).suffix.lower()
        
        # Read header bytes
        header_bytes = b""
        if os.path.exists(file_path) and file_size > 0:
            with open(file_path, "rb") as f:
                header_bytes = f.read(4096)
                
        # 1. Check for known dangerous executable / binary signatures
        is_dangerous, danger_reason = cls._check_dangerous_signatures(header_bytes)
        
        # 2. Detect content type via filetype library and custom magic bytes
        detected_info = cls._detect_content_type(file_path, header_bytes, extension)
        
        detected_mime = detected_info["mime"]
        detected_ext = detected_info["extension"]
        detected_type = detected_info["type"]
        detected_category = detected_info["category"]
        signature_verified = detected_info["signature_verified"]
        signature_name = detected_info["signature_name"]
        
        # 3. Verify extension vs detected content
        extension_match = cls._verify_extension_match(extension, detected_ext, detected_category)
        
        # 4. Verify reported MIME vs detected MIME
        mime_match = True
        if client_mime and detected_mime and detected_mime != "application/octet-stream":
            # Normalization of common mime variations
            client_clean = client_mime.split(";")[0].strip().lower()
            detected_clean = detected_mime.split(";")[0].strip().lower()
            if client_clean != detected_clean and not cls._is_mime_compatible(client_clean, detected_clean):
                mime_match = False

        return {
            "original_filename": original_filename,
            "extension": extension,
            "file_size": file_size,
            "client_mime": client_mime,
            "detected_mime": detected_mime,
            "detected_extension": detected_ext,
            "detected_type": detected_type,
            "detected_category": detected_category,
            "signature_verified": signature_verified,
            "signature_name": signature_name,
            "extension_match": extension_match,
            "mime_match": mime_match,
            "is_dangerous": is_dangerous,
            "danger_reason": danger_reason
        }

    @classmethod
    def _check_dangerous_signatures(cls, header: bytes) -> tuple[bool, str]:
        """Detects executable code disguised under false extensions."""
        if not header:
            return False, ""
            
        for name, sigs in Config.DANGEROUS_SIGNATURES.items():
            for sig in sigs:
                if header.startswith(sig):
                    return True, f"Detected dangerous file signature ({name}). Executables are strictly prohibited."
        return False, ""

    @classmethod
    def _detect_content_type(cls, file_path: str, header: bytes, fallback_ext: str) -> dict:
        """
        Determines the true MIME type, category, and signature of the file.
        """
        # Empty file
        if not header:
            return {
                "mime": "application/x-empty",
                "extension": fallback_ext,
                "type": "Empty File",
                "category": "unknown",
                "signature_verified": False,
                "signature_name": "None (Empty)"
            }

        # 1. Check PDF
        if header.startswith(b"%PDF-") or (b"%PDF-" in header[:2048]):
            return {
                "mime": "application/pdf",
                "extension": ".pdf",
                "type": "PDF Document",
                "category": "pdf",
                "signature_verified": True,
                "signature_name": "%PDF- header signature"
            }
            
        if fallback_ext == ".pdf" or any(k in header for k in [b" 0 obj", b"obj\n", b"obj\r", b"/Catalog", b"/Pages", b"/MediaBox", b"startxref", b"%%EOF"]):
            return {
                "mime": "application/pdf",
                "extension": ".pdf",
                "type": "PDF Document (Damaged Header)",
                "category": "pdf",
                "signature_verified": False,
                "signature_name": "PDF object structures (Missing Header Signature)"
            }

        # 2. Check ZIP-based modern Office documents (DOCX, XLSX, PPTX)
        if header.startswith(b"PK\x03\x04"):
            office_type = cls._inspect_zip_container(file_path)
            if office_type:
                return office_type

        # 3. Check Legacy Microsoft Office Compound File Binary (OLE)
        if header.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
            return cls._inspect_ole_container(header, fallback_ext)

        # 4. Check standard image signatures
        if header.startswith(b"\xFF\xD8\xFF"):
            return {
                "mime": "image/jpeg",
                "extension": ".jpg",
                "type": "JPEG Image",
                "category": "image",
                "signature_verified": True,
                "signature_name": "JPEG magic header (FF D8 FF)"
            }
            
        if header.startswith(b"\x89PNG\r\n\x1a\n"):
            return {
                "mime": "image/png",
                "extension": ".png",
                "type": "PNG Image",
                "category": "image",
                "signature_verified": True,
                "signature_name": "PNG magic header (89 PNG)"
            }
            
        if header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
            return {
                "mime": "image/gif",
                "extension": ".gif",
                "type": "GIF Image",
                "category": "image",
                "signature_verified": True,
                "signature_name": "GIF magic header"
            }

        if header.startswith(b"RIFF") and len(header) >= 12 and header[8:12] == b"WEBP":
            return {
                "mime": "image/webp",
                "extension": ".webp",
                "type": "WebP Image",
                "category": "image",
                "signature_verified": True,
                "signature_name": "WebP RIFF signature"
            }

        # 5. Use filetype library as secondary detector
        kind = filetype.guess(file_path) if os.path.exists(file_path) else None
        if kind:
            category = cls._map_mime_to_category(kind.mime)
            return {
                "mime": kind.mime,
                "extension": f".{kind.extension}",
                "type": kind.mime.split("/")[-1].upper(),
                "category": category,
                "signature_verified": True,
                "signature_name": f"File signature match for {kind.mime}"
            }

        # 6. Check if Plain Text or CSV
        if cls._is_plain_text(header):
            is_csv = cls._is_csv_format(header, fallback_ext)
            if is_csv:
                return {
                    "mime": "text/csv",
                    "extension": ".csv",
                    "type": "CSV Spreadsheet",
                    "category": "csv",
                    "signature_verified": True,
                    "signature_name": "Delimited text stream"
                }
            return {
                "mime": "text/plain",
                "extension": ".txt",
                "type": "Text Document",
                "category": "text",
                "signature_verified": True,
                "signature_name": "Valid UTF-8/ASCII character encoding"
            }

        # Unknown binary file
        return {
            "mime": "application/octet-stream",
            "extension": "",
            "type": "Unknown Binary",
            "category": "unknown",
            "signature_verified": False,
            "signature_name": "Unknown / Unrecognized magic bytes"
        }

    @classmethod
    def _inspect_zip_container(cls, file_path: str) -> dict | None:
        """Inspects internal ZIP structure to distinguish DOCX, XLSX, PPTX from generic ZIP."""
        try:
            with zipfile.ZipFile(file_path, "r") as z:
                namelist = z.namelist()
                namelist_lower = [n.lower() for n in namelist]
                
                # Check for Word
                if any(n.startswith("word/") for n in namelist_lower) or "word/document.xml" in namelist_lower:
                    return {
                        "mime": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        "extension": ".docx",
                        "type": "Word Document (DOCX)",
                        "category": "word",
                        "signature_verified": True,
                        "signature_name": "PK Zip + Office Word OpenXML structure"
                    }
                    
                # Check for Excel
                if any(n.startswith("xl/") for n in namelist_lower) or "xl/workbook.xml" in namelist_lower:
                    return {
                        "mime": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        "extension": ".xlsx",
                        "type": "Excel Spreadsheet (XLSX)",
                        "category": "excel",
                        "signature_verified": True,
                        "signature_name": "PK Zip + Office Excel OpenXML structure"
                    }
                    
                # Check for PowerPoint
                if any(n.startswith("ppt/") for n in namelist_lower) or "ppt/presentation.xml" in namelist_lower:
                    return {
                        "mime": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                        "extension": ".pptx",
                        "type": "PowerPoint Presentation (PPTX)",
                        "category": "powerpoint",
                        "signature_verified": True,
                        "signature_name": "PK Zip + Office PowerPoint OpenXML structure"
                    }
                    
                # Standard ZIP
                return {
                    "mime": "application/zip",
                    "extension": ".zip",
                    "type": "ZIP Archive",
                    "category": "zip",
                    "signature_verified": True,
                    "signature_name": "PK standard archive signature"
                }
        except Exception:
            return None

    @classmethod
    def _inspect_ole_container(cls, header: bytes, fallback_ext: str) -> dict:
        """Handles legacy Microsoft Compound Document (OLE2) formats."""
        if fallback_ext in [".xls", ".xlsx"]:
            return {
                "mime": "application/vnd.ms-excel",
                "extension": ".xls",
                "type": "Excel 97-2003 (XLS)",
                "category": "excel",
                "signature_verified": True,
                "signature_name": "OLE2 Compound Document (Excel)"
            }
        elif fallback_ext in [".ppt", ".pptx"]:
            return {
                "mime": "application/vnd.ms-powerpoint",
                "extension": ".ppt",
                "type": "PowerPoint 97-2003 (PPT)",
                "category": "powerpoint",
                "signature_verified": True,
                "signature_name": "OLE2 Compound Document (PowerPoint)"
            }
        else:
            return {
                "mime": "application/msword",
                "extension": ".doc",
                "type": "Word 97-2003 (DOC)",
                "category": "word",
                "signature_verified": True,
                "signature_name": "OLE2 Compound Document (Word)"
            }

    @classmethod
    def _is_plain_text(cls, header: bytes) -> bool:
        """Determines if a byte sequence represents valid human-readable text rather than arbitrary binary."""
        if not header:
            return False
        # Null bytes or non-printable ASCII control characters indicate binary data
        control_chars = sum(1 for b in header[:1024] if b < 32 and b not in (9, 10, 13))
        if control_chars > 0:
            return False
        try:
            decoded = header.decode("utf-8")
            return True
        except UnicodeDecodeError:
            try:
                decoded = header.decode("latin-1")
                printable = sum(1 for c in decoded if c.isprintable() or c in "\r\n\t")
                return (printable / len(decoded)) > 0.90
            except Exception:
                return False

    @classmethod
    def _is_csv_format(cls, header: bytes, fallback_ext: str) -> bool:
        """Checks if text content has CSV delimiters (commas, tabs, semicolons) across lines."""
        if fallback_ext == ".csv":
            return True
        try:
            sample = header[:1024].decode("utf-8", errors="ignore")
            lines = [line for line in sample.splitlines() if line.strip()]
            if len(lines) >= 2:
                has_commas = all("," in line for line in lines[:3])
                if has_commas:
                    return True
        except Exception:
            pass
        return False

    @classmethod
    def _map_mime_to_category(cls, mime: str) -> str:
        for cat, conf in Config.FILE_TYPES.items():
            if mime in conf["mimes"]:
                return cat
        return "unknown"

    @classmethod
    def _verify_extension_match(cls, original_ext: str, detected_ext: str, detected_cat: str) -> bool:
        """
        Validates whether the user-provided file extension corresponds to the actual detected content.
        Crucial for detecting disguised malware (e.g. payload.exe disguised as payload.pdf).
        """
        if not original_ext or not detected_ext or detected_cat == "unknown":
            return False
            
        original_ext = original_ext.lower()
        detected_ext = detected_ext.lower()
        
        # Direct extension match
        if original_ext == detected_ext:
            return True
            
        # Category-level match (e.g. .jpg matches .jpeg; .doc matches word category)
        if detected_cat in Config.FILE_TYPES:
            allowed_exts = Config.FILE_TYPES[detected_cat]["extensions"]
            if original_ext in allowed_exts:
                return True
                
        return False

    @classmethod
    def _is_mime_compatible(cls, client_mime: str, detected_mime: str) -> bool:
        """Checks compatible MIME aliases."""
        compatible_pairs = [
            ("text/csv", "application/csv"),
            ("text/csv", "text/plain"),
            ("image/jpeg", "image/jpg"),
            ("application/vnd.ms-excel", "application/msexcel"),
            ("application/octet-stream", "application/zip")
        ]
        for a, b in compatible_pairs:
            if (client_mime == a and detected_mime == b) or (client_mime == b and detected_mime == a):
                return True
        return False
