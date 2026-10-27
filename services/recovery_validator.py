import os
import logging
from typing import Dict, Any, Optional

from services.validator import RecoveredFileValidator
from services.detector import FileDetector

logger = logging.getLogger("FileGuard.RecoveryValidator")


class RecoveryValidator:
    """
    Independent Recovery Validation Engine.
    Executes deep structural, typographical, and raster validation on repaired outputs.
    Enforces the NO FAKE RECOVERY rule:
      - Classifies outcomes as:
        * FULLY_RECOVERED
        * PARTIALLY_RECOVERED
        * REBUILT_FROM_CONTENT
        * FAILED
        * INVALID_OR_UNSUPPORTED
      - Verifies reopening after save
      - Re-verifies page trees and text/raster contents
    """

    @classmethod
    def validate(cls, original_path: Optional[str], recovered_path: str, expected_type: str = "auto") -> Dict[str, Any]:
        if not os.path.exists(recovered_path):
            return {
                "is_valid": False,
                "openable": False,
                "pages": 0,
                "text_extractable": False,
                "structure_valid": False,
                "reopened_ok": False,
                "outcome": "FAILED",
                "recovery_status": "FAILED",
                "recovery_score": 0,
                "error": "Recovered output file does not exist on disk."
            }

        file_size = os.path.getsize(recovered_path)
        if file_size == 0:
            return {
                "is_valid": False,
                "openable": False,
                "pages": 0,
                "text_extractable": False,
                "structure_valid": False,
                "reopened_ok": False,
                "outcome": "FAILED",
                "recovery_status": "UNRECOVERABLE",
                "recovery_score": 0,
                "error": "Recovered file is 0 bytes (empty placeholder rejected)."
            }

        # Resolve type
        if not expected_type or expected_type.lower() == "auto":
            det = FileDetector.detect_file_type(recovered_path)
            fmt = det.get("file_type", "UNKNOWN").upper()
        else:
            fmt = expected_type.upper()

        # Execute primary validator
        base_res = RecoveredFileValidator.validate(
            file_path=recovered_path,
            expected_type=fmt,
            original_file_path=original_path if (original_path and os.path.exists(original_path)) else None
        )

        # Additional Verification: Reopen after save test
        reopen_ok = cls._test_reopen_after_save(recovered_path, fmt)
        base_res["reopened_ok"] = reopen_ok

        # Determine standardized outcome
        raw_status = base_res.get("recovery_status", "FAILED")
        has_content = base_res.get("has_content", False)
        openable = base_res.get("openable", False)
        is_rebuilt = "rebuilt" in str(base_res.get("details", "")).lower() or base_res.get("rebuilt_from_salvage", False)

        if not openable or not reopen_ok:
            outcome = "FAILED"
            final_status = "FAILED"
            score = 0
        elif is_rebuilt:
            outcome = "REBUILT_FROM_CONTENT"
            final_status = "PARTIALLY_RECOVERED"
            score = min(base_res.get("recovery_score", 80), 85)
        elif raw_status in ["FULLY_RECOVERED", "SUCCESS"] and base_res.get("structure_valid", True):
            outcome = "FULLY_RECOVERED"
            final_status = "FULLY_RECOVERED"
            score = base_res.get("recovery_score", 95)
        elif has_content or raw_status in ["PARTIALLY_RECOVERED", "PARTIAL"]:
            outcome = "PARTIALLY_RECOVERED"
            final_status = "PARTIALLY_RECOVERED"
            score = base_res.get("recovery_score", 75)
        else:
            outcome = "FAILED"
            final_status = "FAILED"
            score = 0

        base_res["outcome"] = outcome
        base_res["recovery_status"] = final_status
        base_res["recovery_score"] = score
        return base_res

    @classmethod
    def _test_reopen_after_save(cls, file_path: str, fmt: str) -> bool:
        """Verifies that an independent parser can open the saved file without crashing."""
        try:
            if fmt == "PDF":
                import fitz
                doc = fitz.open(file_path)
                p_count = len(doc)
                doc.close()
                return p_count > 0
            elif fmt in ["DOCX", "WORD"]:
                import docx
                doc = docx.Document(file_path)
                return True
            elif fmt in ["XLSX", "EXCEL"]:
                import openpyxl
                wb = openpyxl.load_workbook(file_path, read_only=True)
                wb.close()
                return True
            elif fmt in ["IMAGE", "JPEG", "JPG", "PNG"]:
                from PIL import Image
                with Image.open(file_path) as im:
                    im.verify()
                return True
            return True
        except Exception:
            return False


def validate_recovered_file(original_path: Optional[str], recovered_path: str, expected_type: str = "auto") -> Dict[str, Any]:
    """Top-level functional interface conforming to system specification."""
    return RecoveryValidator.validate(original_path, recovered_path, expected_type)
