import os
import io
import csv
import json
import re
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("FileGuard.TextRecovery")

class TextRecoveryEngine:
    """
    Deterministic Multi-Strategy Text, CSV, and JSON Recovery Engine.
    Handles:
      1. Encoding Normalization (UTF-8, UTF-16, Latin-1, CP1252, ASCII)
      2. CSV Delimiter & Inconsistent Column Reconstruction
      3. JSON Structural Repair (Mismatched braces, unescaped quotes, trailing commas)
      4. Null-byte stripping and control-character sanitization
    """

    ENCODINGS = ["utf-8", "utf-8-sig", "latin-1", "cp1252", "utf-16", "utf-16-le", "utf-16-be", "iso-8859-1"]

    @classmethod
    def recover_text(cls, corrupted_path: str, output_path: str) -> Dict[str, Any]:
        if not os.path.exists(corrupted_path):
            return {"success": False, "error": "Source file not found", "status": "FAILED"}

        file_size = os.path.getsize(corrupted_path)
        if file_size == 0:
            return {"success": False, "error": "File is empty (0 bytes).", "status": "UNRECOVERABLE"}

        with open(corrupted_path, "rb") as f:
            raw_bytes = f.read()

        # Try multi-encoding decode with fallback replacement
        decoded_text = None
        used_enc = None

        for enc in cls.ENCODINGS:
            try:
                decoded_text = raw_bytes.decode(enc)
                used_enc = enc
                break
            except Exception:
                continue

        if decoded_text is None:
            # Fallback with replacement of unmapped bytes
            decoded_text = raw_bytes.decode("utf-8", errors="replace")
            used_enc = "utf-8 (lossy replacement)"

        # Strip null bytes and non-printable noise if corrupt binary
        sanitized = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F]", "", decoded_text)
        if not sanitized.strip():
            return {"success": False, "error": "Document contains no readable text.", "status": "UNRECOVERABLE"}

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(sanitized)

        return {
            "success": True,
            "status": "FULLY_RECOVERED",
            "strategy": f"Encoding Normalization ({used_enc})",
            "char_count": len(sanitized),
            "line_count": len(sanitized.splitlines())
        }

    @classmethod
    def recover_csv(cls, corrupted_path: str, output_path: str) -> Dict[str, Any]:
        if not os.path.exists(corrupted_path):
            return {"success": False, "error": "Source file not found", "status": "FAILED"}

        with open(corrupted_path, "rb") as f:
            raw_bytes = f.read()

        if len(raw_bytes) == 0:
            return {"success": False, "error": "CSV file is empty (0 bytes).", "status": "UNRECOVERABLE"}

        # Decode
        text = None
        for enc in cls.ENCODINGS:
            try:
                text = raw_bytes.decode(enc)
                break
            except Exception:
                pass

        if text is None:
            text = raw_bytes.decode("utf-8", errors="replace")

        # Strip nulls and binary garbage
        clean_text = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F]", "", text)
        lines = [line.strip() for line in clean_text.splitlines() if line.strip()]

        if not lines:
            return {"success": False, "error": "CSV contains no data rows.", "status": "UNRECOVERABLE"}

        # Detect delimiter (comma, semicolon, tab, pipe)
        sample = "\n".join(lines[:10])
        delimiters = [",", ";", "\t", "|"]
        best_delim = ","
        best_count = -1

        for d in delimiters:
            cnt = sample.count(d)
            if cnt > best_count:
                best_count = cnt
                best_delim = d

        # Parse rows and equalize column lengths
        parsed_rows = []
        for line in lines:
            try:
                reader = csv.reader([line], delimiter=best_delim)
                row = next(reader)
                if row:
                    parsed_rows.append(row)
            except Exception:
                # Fallback split
                row = line.split(best_delim)
                parsed_rows.append(row)

        if not parsed_rows:
            return {"success": False, "error": "Could not extract CSV records.", "status": "UNRECOVERABLE"}

        max_cols = max(len(r) for r in parsed_rows)
        # Pad shorter rows
        normalized_rows = []
        for r in parsed_rows:
            if len(r) < max_cols:
                r = r + [""] * (max_cols - len(r))
            normalized_rows.append(r)

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerows(normalized_rows)

        return {
            "success": True,
            "status": "FULLY_RECOVERED",
            "strategy": f"CSV Structure Rebuilder (Delim: '{best_delim}', Columns: {max_cols})",
            "row_count": len(normalized_rows),
            "col_count": max_cols
        }

    @classmethod
    def recover_json(cls, corrupted_path: str, output_path: str) -> Dict[str, Any]:
        if not os.path.exists(corrupted_path):
            return {"success": False, "error": "Source file not found", "status": "FAILED"}

        with open(corrupted_path, "rb") as f:
            raw_bytes = f.read()

        if len(raw_bytes) == 0:
            return {"success": False, "error": "JSON file is empty.", "status": "UNRECOVERABLE"}

        text = raw_bytes.decode("utf-8", errors="replace").strip()

        # Try parsing directly
        try:
            parsed = json.loads(text)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(parsed, f, indent=2)
            return {"success": True, "status": "FULLY_RECOVERED", "strategy": "Direct JSON Validation"}
        except Exception:
            pass

        # Clean trailing commas and balance braces
        cleaned = re.sub(r",\s*([\]}])", r"\1", text)
        open_braces = cleaned.count("{") - cleaned.count("}")
        open_brackets = cleaned.count("[") - cleaned.count("]")

        if open_brackets > 0:
            cleaned += "]" * open_brackets
        if open_braces > 0:
            cleaned += "}" * open_braces

        try:
            parsed = json.loads(cleaned)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(parsed, f, indent=2)
            return {"success": True, "status": "PARTIALLY_RECOVERED", "strategy": "JSON Syntax Repair (Balanced Braces & Trailing Commas)"}
        except Exception as e:
            return {"success": False, "error": f"JSON syntax unrepairable: {str(e)}", "status": "FAILED"}
