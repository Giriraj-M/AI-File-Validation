import os
import re
import shutil
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None

try:
    import pikepdf
except ImportError:
    pikepdf = None

try:
    from pypdf import PdfReader, PdfWriter
except ImportError:
    PdfReader = None
    PdfWriter = None

from utils.process_utils import run_external_command

logger = logging.getLogger("FileGuard.PDFHeaderRecovery")


class PDFHeaderRecovery:
    """
    Dedicated PDF Header Corruption Recovery Engine.
    Repairs displaced headers, leading garbage bytes, damaged magic signatures,
    and malformed version declarations while validating body integrity.
    Never blindly prepends headers without verifying valid PDF objects.
    """

    @classmethod
    def recover(cls, input_path: str, output_path: str, analysis: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Executes progressive header repair and returns structured result.
        """
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path}")

        file_size = os.path.getsize(input_path)
        if file_size == 0:
            return {
                "success": False,
                "status": "UNRECOVERABLE",
                "tool_used": "Header Inspector",
                "corruption_detected": "Zero-byte file",
                "operations_performed": ["Inspected file size (0 bytes)"],
                "validation_results": {"openable": False},
                "content_preservation": "0 bytes",
                "error": "File is empty; header cannot be reconstructed.",
                "warnings": ["0 bytes"]
            }

        with open(input_path, "rb") as f:
            raw_data = f.read()

        ops = []
        warnings = []

        # 1. Verify that valid PDF body objects exist beyond header
        has_pdf_objects = bool(
            re.search(rb"\b\d+\s+\d+\s+obj\b", raw_data) or
            b"/Catalog" in raw_data or
            b"/Pages" in raw_data or
            b"/Type" in raw_data or
            b"startxref" in raw_data
        )

        if not has_pdf_objects:
            return {
                "success": False,
                "status": "FAILED",
                "tool_used": "PDF Body Verifier",
                "corruption_detected": "Damaged header with no surviving PDF objects",
                "operations_performed": ["Inspected binary for object markers (none found)"],
                "validation_results": {"openable": False},
                "content_preservation": "0 bytes",
                "error": "No valid PDF document objects exist beyond the damaged header. Refusing blind header insertion.",
                "warnings": ["Blind header reconstruction rejected by safety policy"]
            }

        # 2. Check for displaced header (junk before %PDF-)
        pdf_pos = raw_data.find(b"%PDF-")
        if pdf_pos > 0 and pdf_pos < 65536:
            ops.append(f"Detected displaced %PDF header at offset {pdf_pos}. Stripping {pdf_pos} pre-header garbage bytes.")
            clean_slice = raw_data[pdf_pos:]
            temp_fixed = output_path + ".hdr_tmp"
            with open(temp_fixed, "wb") as f_out:
                f_out.write(clean_slice)

            # Validate slice with pikepdf or PyMuPDF
            val_ok = cls._validate_and_finalize(temp_fixed, output_path, "Displaced Header Alignment")
            if os.path.exists(temp_fixed):
                try:
                    os.remove(temp_fixed)
                except Exception:
                    pass
            if val_ok["success"]:
                return {
                    "success": True,
                    "status": "FULLY_RECOVERED",
                    "input_file": input_path,
                    "output_file": output_path,
                    "tool_used": val_ok.get("tool_used", "Header Realignment Engine"),
                    "corruption_detected": f"Displaced %PDF- signature at offset {pdf_pos}",
                    "operations_performed": ops + val_ok.get("ops", []),
                    "validation_results": val_ok.get("validation", {}),
                    "content_preservation": f"Intact ({val_ok.get('pages', 1)} pages verified)",
                    "warnings": warnings
                }

        # 3. Attempt QPDF repair if binary exists
        qpdf_bin = shutil.which("qpdf")
        if qpdf_bin:
            ops.append("Executing QPDF structural linearization & header recovery")
            ok, out, err = run_external_command([qpdf_bin, "--repair-file", input_path, output_path], timeout=15)
            if ok and os.path.exists(output_path) and os.path.getsize(output_path) > 100:
                val = cls._quick_verify(output_path)
                if val["openable"]:
                    return {
                        "success": True,
                        "status": "FULLY_RECOVERED",
                        "input_file": input_path,
                        "output_file": output_path,
                        "tool_used": "QPDF CLI",
                        "corruption_detected": "Malformed header",
                        "operations_performed": ops,
                        "validation_results": val,
                        "content_preservation": f"{val.get('pages', 1)} pages verified",
                        "warnings": warnings
                    }

        # 4. Attempt pikepdf C++ parser recovery
        if pikepdf:
            try:
                ops.append("Attempting pikepdf permissive load & header normalization")
                with pikepdf.open(input_path, recover=True) as pdf:
                    pdf.save(output_path)
                val = cls._quick_verify(output_path)
                if val["openable"]:
                    return {
                        "success": True,
                        "status": "FULLY_RECOVERED",
                        "input_file": input_path,
                        "output_file": output_path,
                        "tool_used": "pikepdf",
                        "corruption_detected": "Header signature defect",
                        "operations_performed": ops,
                        "validation_results": val,
                        "content_preservation": f"{val.get('pages', 1)} pages verified",
                        "warnings": warnings
                    }
            except Exception as e:
                warnings.append(f"pikepdf recovery attempt: {str(e)[:60]}")

        # 5. Fallback: Safe Header Synthesis & PyMuPDF Re-save
        # Determine likely version from internal objects or default to 1.7
        v_match = re.search(rb"/Version\s*/(\d+\.\d+)", raw_data) or re.search(rb"%PDF-(\d+\.\d+)", raw_data)
        detected_version = v_match.group(1).decode("ascii") if v_match else "1.7"
        ops.append(f"Synthesizing standard %PDF-{detected_version} magic header with binary comment")

        # Strip any corrupted initial bytes up to the first valid object marker
        first_obj = re.search(rb"\b\d+\s+\d+\s+obj\b", raw_data)
        body_slice = raw_data[first_obj.start():] if first_obj else raw_data
        synthesized_data = f"%PDF-{detected_version}\n%\xe2\xe3\xcf\xd3\n".encode("latin1") + body_slice

        temp_synth = output_path + ".synth_tmp"
        with open(temp_synth, "wb") as f_synth:
            f_synth.write(synthesized_data)

        val_synth = cls._validate_and_finalize(temp_synth, output_path, "Safe Header Reconstructor")
        if os.path.exists(temp_synth):
            try:
                os.remove(temp_synth)
            except Exception:
                pass

        if val_synth["success"]:
            return {
                "success": True,
                "status": "FULLY_RECOVERED",
                "input_file": input_path,
                "output_file": output_path,
                "tool_used": val_synth.get("tool_used", "Header Synthesis Engine"),
                "corruption_detected": "Destroyed header signature",
                "operations_performed": ops + val_synth.get("ops", []),
                "validation_results": val_synth.get("validation", {}),
                "content_preservation": f"Verified ({val_synth.get('pages', 1)} pages)",
                "warnings": warnings
            }

        return {
            "success": False,
            "status": "FAILED",
            "input_file": input_path,
            "output_file": output_path,
            "tool_used": "PDFHeaderRecovery",
            "corruption_detected": "Severe header and object graph corruption",
            "operations_performed": ops,
            "validation_results": {"openable": False},
            "content_preservation": "0 bytes",
            "error": "Header recovery could not produce a valid document. Handing off to content salvage pipeline.",
            "warnings": warnings
        }

    @classmethod
    def _validate_and_finalize(cls, candidate_path: str, target_path: str, tool_label: str) -> Dict[str, Any]:
        """Validates candidate PDF using PyMuPDF and pikepdf, re-saving to target_path."""
        ops = []
        if fitz:
            try:
                doc = fitz.open(candidate_path)
                pages = len(doc)
                if pages > 0:
                    doc.save(target_path, garbage=4, deflate=True)
                    doc.close()
                    ops.append(f"PyMuPDF validated and linearized {pages} pages")
                    return {
                        "success": True,
                        "tool_used": f"{tool_label} + PyMuPDF",
                        "pages": pages,
                        "ops": ops,
                        "validation": {"openable": True, "pages": pages, "structure_valid": True}
                    }
            except Exception:
                pass

        if pikepdf:
            try:
                with pikepdf.open(candidate_path, recover=True) as p:
                    pages = len(p.pages)
                    p.save(target_path)
                    ops.append(f"pikepdf validated and saved {pages} pages")
                    return {
                        "success": True,
                        "tool_used": f"{tool_label} + pikepdf",
                        "pages": pages,
                        "ops": ops,
                        "validation": {"openable": True, "pages": pages, "structure_valid": True}
                    }
            except Exception:
                pass

        return {"success": False}

    @classmethod
    def _quick_verify(cls, path: str) -> Dict[str, Any]:
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return {"openable": False, "pages": 0}
        if fitz:
            try:
                d = fitz.open(path)
                p = len(d)
                d.close()
                return {"openable": p > 0, "pages": p}
            except Exception:
                pass
        if PdfReader:
            try:
                r = PdfReader(path)
                p = len(r.pages)
                return {"openable": p > 0, "pages": p}
            except Exception:
                pass
        return {"openable": False, "pages": 0}
