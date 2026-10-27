import os
from config import Config
from services.file_detection_service import FileDetectionService
from services.integrity_service import IntegrityService
from services.document_service import DocumentService
from services.security_service import SecurityService
from services.ai_service import AIService
from services.history_service import HistoryService
from utils.file_utils import format_size, cleanup_file

class ValidationService:
    """
    Master Validation Orchestrator.
    Enforces deterministic validation decisions while utilizing AI for rule interpretation,
    document classification, and natural language explanations.
    """

    @classmethod
    def validate_upload(cls, file_path: str, original_filename: str, prompt: str, client_mime: str = "") -> dict:
        """
        Executes end-to-end multi-layer validation pipeline.
        """
        violations = []
        warnings = []
        checks = []

        # Step 1: Parse Prompt Requirements via AI/NLP
        reqs = AIService.parse_validation_prompt(prompt)
        allowed_types = reqs.get("allowed_types", [])
        max_size_bytes = reqs.get("max_size_bytes")

        # Step 2: Deep File Inspection & Binary Signature Detection
        file_meta = FileDetectionService.inspect_file(file_path, original_filename, client_mime)
        file_size = file_meta["file_size"]
        file_size_human = format_size(file_size)
        detected_category = file_meta["detected_category"]
        detected_type = file_meta["detected_type"]
        detected_mime = file_meta["detected_mime"]
        extension = file_meta["extension"]

        # Check 1: File Type Requirement
        if file_meta.get("is_dangerous"):
            v_msg = f"Disguised or dangerous executable binary detected: {file_meta['danger_reason']}."
            violations.append(v_msg)
            checks.append({
                "name": "File Type",
                "status": "failed",
                "detail": v_msg
            })
        elif allowed_types:
            is_type_match = False
            # An unknown binary or unverified signature cannot satisfy format requirements
            if detected_category != "unknown" and file_meta.get("signature_verified", False):
                for req_type in allowed_types:
                    req_clean = req_type.lower().strip(".")
                    if detected_category.lower() == req_clean:
                        is_type_match = True
                        break
                    # Common aliases
                    if req_clean in ["spreadsheet", "sheet", "xls", "xlsx"] and detected_category == "excel":
                        is_type_match = True
                        break
                    if req_clean in ["doc", "docx"] and detected_category == "word":
                        is_type_match = True
                        break
                    if req_clean in ["jpg", "jpeg", "png", "gif", "webp"] and detected_category == "image":
                        is_type_match = True
                        break
                    if req_clean in ["presentation", "ppt", "pptx"] and detected_category == "powerpoint":
                        is_type_match = True
                        break

            if is_type_match:
                checks.append({
                    "name": "File Type",
                    "status": "passed",
                    "detail": f"File type '{detected_type}' satisfies requirement: {', '.join(allowed_types).upper()}."
                })
            else:
                expected_str = ", ".join(allowed_types).upper()
                if detected_category == "unknown":
                    v_msg = f"Expected {expected_str} document, but detected corrupted or unverified binary stream ({detected_type})."
                else:
                    v_msg = f"Expected {expected_str} format, but detected {detected_type}."
                violations.append(v_msg)
                checks.append({
                    "name": "File Type",
                    "status": "failed",
                    "detail": v_msg
                })
        else:
            # If user didn't specify a type, verify that file is within supported system formats
            is_supported_ext = any(extension in conf["extensions"] for conf in Config.FILE_TYPES.values())
            if detected_category in Config.FILE_TYPES and is_supported_ext and file_meta.get("signature_verified", False):
                checks.append({
                    "name": "File Type",
                    "status": "passed",
                    "detail": f"Detected format '{detected_type}' is supported."
                })
            else:
                v_msg = f"Unsupported, corrupted, or unrecognizable file format: '{extension or 'no-ext'}' ({detected_type})."
                violations.append(v_msg)
                checks.append({
                    "name": "File Type",
                    "status": "failed",
                    "detail": v_msg
                })

        # Check 2: File Size Requirement
        if file_size > Config.MAX_CONTENT_LENGTH:
            v_msg = f"File size ({file_size_human}) exceeds global server limit of {Config.MAX_CONTENT_LENGTH_MB} MB."
            violations.append(v_msg)
            checks.append({
                "name": "File Size",
                "status": "failed",
                "detail": v_msg
            })
        elif max_size_bytes is not None:
            req_size_human = format_size(max_size_bytes)
            if file_size > max_size_bytes:
                v_msg = f"File size ({file_size_human}) exceeds requested limit of {req_size_human}."
                violations.append(v_msg)
                checks.append({
                    "name": "File Size",
                    "status": "failed",
                    "detail": v_msg
                })
            else:
                checks.append({
                    "name": "File Size",
                    "status": "passed",
                    "detail": f"{file_size_human} is within requested maximum of {req_size_human}."
                })
        else:
            checks.append({
                "name": "File Size",
                "status": "passed",
                "detail": f"{file_size_human} is within default server capacity."
            })

        # Check 3: File Integrity & Corruption Check
        integrity_res = IntegrityService.check_integrity(file_path, detected_category, original_filename, allowed_types)
        is_corrupted = integrity_res["is_corrupted"]
        integrity_reason = integrity_res["reason"]

        if is_corrupted:
            v_msg = f"File corruption detected: {integrity_reason}"
            violations.append(v_msg)
            checks.append({
                "name": "File Integrity",
                "status": "failed",
                "detail": v_msg
            })
        else:
            checks.append({
                "name": "File Integrity",
                "status": "passed",
                "detail": f"File integrity verified: {integrity_reason}"
            })

        # Document text extraction (for metadata/classification)
        doc_analysis = DocumentService.extract_text(file_path, detected_category) if not is_corrupted else {}
        extracted_text = doc_analysis.get("text", "")

        # Document classification
        classification = AIService.classify_document(extracted_text, original_filename) if not is_corrupted else {
            "category": "Corrupted File",
            "confidence": "100%",
            "summary": "File content could not be classified due to file corruption."
        }

        # Step 3: Calculate Final Score & Status
        total_checks = len(checks)
        passed_checks = sum(1 for c in checks if c["status"] == "passed")
        
        if violations:
            score = int((passed_checks / total_checks) * 100) if total_checks > 0 else 0
            status = "failed"
        else:
            score = 100
            status = "passed"

        # Step 4: Generate AI Summary Explanation
        ai_explanation = AIService.generate_explanation(
            status=status,
            filename=original_filename,
            detected_type=detected_type,
            size_human=file_size_human,
            requirements={
                "allowed_types": allowed_types,
                "max_size_bytes": max_size_bytes,
                "max_size_human": format_size(max_size_bytes) if max_size_bytes else None
            },
            violations=violations
        )

        recommended_action = "Safe for downstream workflow." if status == "passed" else (
            "Reject damaged file. Re-export or obtain an uncorrupted copy." if is_corrupted else "Reject or review file."
        )

        response_payload = {
            "success": True,
            "validation_status": status,
            "score": score,
            "file": {
                "name": original_filename,
                "size_bytes": file_size,
                "size_human": file_size_human,
                "extension": extension,
                "mime_type": detected_mime,
                "detected_type": detected_type,
                "detected_category": detected_category,
                "signature": file_meta["signature_name"],
                "is_corrupted": is_corrupted,
                "integrity_status": "Corrupted" if is_corrupted else "Intact",
                "integrity_detail": integrity_reason
            },
            "requirements": {
                "prompt": prompt,
                "allowed_types": allowed_types,
                "max_size_bytes": max_size_bytes,
                "max_size_human": format_size(max_size_bytes) if max_size_bytes else "No limit specified",
                "check_integrity": reqs.get("check_integrity", True),
                "interpreted_by": reqs.get("interpreted_by")
            },
            "classification": classification,
            "content_metrics": {
                "char_count": doc_analysis.get("char_count", 0),
                "word_count": doc_analysis.get("word_count", 0),
                "pages": doc_analysis.get("pages", 0)
            },
            "checks": checks,
            "violations": violations,
            "warnings": warnings,
            "ai_analysis": ai_explanation,
            "recommended_action": recommended_action
        }

        # Step 5: Persist Audit Record
        val_id = HistoryService.record_validation({
            "filename": original_filename,
            "detected_type": detected_type,
            "file_size_human": file_size_human,
            "status": status,
            "score": score,
            "prompt": prompt,
            "violations": violations,
            "ai_analysis": ai_explanation
        })
        response_payload["validation_id"] = val_id

        # If corrupted, cache temporarily for 1-click AI recovery
        if is_corrupted:
            import shutil
            os.makedirs(Config.TEMP_CORRUPTED_FOLDER, exist_ok=True)
            cache_name = f"{val_id}_{original_filename}"
            cache_path = os.path.join(Config.TEMP_CORRUPTED_FOLDER, cache_name)
            try:
                shutil.copy2(file_path, cache_path)
                response_payload["file"]["corrupted_cache_id"] = val_id
            except Exception:
                pass

        # Safely clean up uploaded file from storage after processing to ensure privacy and security
        cleanup_file(file_path)

        return response_payload
