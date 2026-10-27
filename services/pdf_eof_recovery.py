import os
import re
import shutil
import logging
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

logger = logging.getLogger("FileGuard.PDFEOFRecovery")


class PDFEOFRecovery:
    """
    Dedicated PDF EOF and Truncation Corruption Recovery Engine.
    Stabilizes truncated document streams, repairs damaged trailers and missing %%EOF markers.
    Enforces strict rule: Never simply append %%EOF without validating that internal objects
    and page trees are structurally readable.
    """

    @classmethod
    def recover(cls, input_path: str, output_path: str, analysis: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path}")

        file_size = os.path.getsize(input_path)
        if file_size == 0:
            return {
                "success": False,
                "status": "UNRECOVERABLE",
                "tool_used": "EOF Inspector",
                "corruption_detected": "Zero-byte file",
                "operations_performed": [],
                "validation_results": {"openable": False},
                "content_preservation": "0 bytes",
                "error": "Cannot recover EOF for 0-byte file."
            }

        with open(input_path, "rb") as f:
            raw_data = f.read()

        ops = []
        warnings = []

        # 1. Inspect file termination
        eof_pos = raw_data.rfind(b"%%EOF")
        is_missing_eof = (eof_pos == -1 or eof_pos < len(raw_data) - 1024)

        # 2. Check if file has genuine surviving PDF objects
        obj_matches = list(re.finditer(rb"\b\d+\s+\d+\s+obj\b", raw_data))
        if not obj_matches:
            return {
                "success": False,
                "status": "FAILED",
                "tool_used": "EOF Validator",
                "corruption_detected": "Truncated data with no surviving PDF objects",
                "operations_performed": ["Inspected document objects (0 found)"],
                "validation_results": {"openable": False},
                "content_preservation": "0 bytes",
                "error": "File does not contain recoverable PDF objects; appending %%EOF is disallowed.",
                "warnings": ["Empty/non-PDF payload rejected"]
            }

        # 3. Attempt QPDF Structural Linearization (Primary Tool)
        qpdf_bin = shutil.which("qpdf")
        if qpdf_bin:
            ops.append("Executing QPDF structural reconstruction to resolve truncated xref/trailer")
            ok, out, err = run_external_command([qpdf_bin, "--repair-file", input_path, output_path], timeout=15)
            if ok and os.path.exists(output_path) and os.path.getsize(output_path) > 100:
                val = cls._verify(output_path)
                if val["openable"]:
                    return {
                        "success": True,
                        "status": "FULLY_RECOVERED",
                        "input_file": input_path,
                        "output_file": output_path,
                        "tool_used": "QPDF CLI",
                        "corruption_detected": "Missing %%EOF / Truncated trailer",
                        "operations_performed": ops,
                        "validation_results": val,
                        "content_preservation": f"{val.get('pages', 1)} pages verified",
                        "warnings": warnings
                    }

        # 4. Attempt pikepdf C++ parser recovery
        if pikepdf:
            try:
                ops.append("Attempting pikepdf permissive load & rewrite with recover=True")
                with pikepdf.open(input_path, recover=True) as pdf:
                    pdf.save(output_path)
                val = cls._verify(output_path)
                if val["openable"]:
                    return {
                        "success": True,
                        "status": "FULLY_RECOVERED",
                        "input_file": input_path,
                        "output_file": output_path,
                        "tool_used": "pikepdf",
                        "corruption_detected": "Truncated file ending",
                        "operations_performed": ops,
                        "validation_results": val,
                        "content_preservation": f"{val.get('pages', 1)} pages verified",
                        "warnings": warnings
                    }
            except Exception as e:
                warnings.append(f"pikepdf EOF load exception: {str(e)[:60]}")

        # 5. Attempt PyMuPDF stream repair
        if fitz:
            try:
                ops.append("Opening truncated stream with PyMuPDF to salvage renderable pages")
                doc = fitz.open(input_path)
                pages = len(doc)
                if pages > 0:
                    doc.save(output_path, garbage=4, deflate=True)
                    doc.close()
                    val = cls._verify(output_path)
                    if val["openable"]:
                        return {
                            "success": True,
                            "status": "FULLY_RECOVERED",
                            "input_file": input_path,
                            "output_file": output_path,
                            "tool_used": "PyMuPDF Stream Engine",
                            "corruption_detected": "Truncated trailer/EOF",
                            "operations_performed": ops,
                            "validation_results": val,
                            "content_preservation": f"{pages} pages verified",
                            "warnings": warnings
                        }
            except Exception as e:
                warnings.append(f"PyMuPDF EOF exception: {str(e)[:60]}")

        # 6. Safe Structural Termination: Locate last complete object, seal open stream, and synthesize valid trailer
        ops.append("Analyzing byte stream: sealing unclosed streams and synthesizing valid trailer and %%EOF")
        terminated_bytes = cls._safely_terminate_pdf_bytes(raw_data)
        if terminated_bytes:
            temp_path = output_path + ".term_tmp"
            with open(temp_path, "wb") as f_tmp:
                f_tmp.write(terminated_bytes)

            # Re-read and re-linearize with fitz or pikepdf
            val_ok = False
            if fitz:
                try:
                    d = fitz.open(temp_path)
                    if len(d) > 0:
                        d.save(output_path, garbage=4, deflate=True)
                        d.close()
                        val_ok = True
                except Exception:
                    pass

            if not val_ok and pikepdf:
                try:
                    with pikepdf.open(temp_path, recover=True) as p:
                        if len(p.pages) > 0:
                            p.save(output_path)
                            val_ok = True
                except Exception:
                    pass

            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass

            if val_ok:
                val = cls._verify(output_path)
                return {
                    "success": True,
                    "status": "PARTIALLY_RECOVERED" if is_missing_eof else "FULLY_RECOVERED",
                    "input_file": input_path,
                    "output_file": output_path,
                    "tool_used": "Structural Stream Terminator",
                    "corruption_detected": "Truncated ending & missing %%EOF",
                    "operations_performed": ops,
                    "validation_results": val,
                    "content_preservation": f"{val.get('pages', 1)} pages verified",
                    "warnings": warnings + ["Document ended abruptly; surviving pages stabilized."]
                }

        return {
            "success": False,
            "status": "FAILED",
            "input_file": input_path,
            "output_file": output_path,
            "tool_used": "PDFEOFRecovery",
            "corruption_detected": "Severe truncation with damaged root structures",
            "operations_performed": ops,
            "validation_results": {"openable": False},
            "content_preservation": "0 bytes",
            "error": "Document truncation destroyed page tree root; handing off to content rebuild engine.",
            "warnings": warnings
        }

    @classmethod
    def _safely_terminate_pdf_bytes(cls, data: bytes) -> Optional[bytes]:
        """
        Inspects whether stream or object was cut off mid-declaration.
        Appends matching endstream / endobj, recalculates XREF and synthesizes clean trailer.
        """
        clean_data = bytearray(data)

        # Check if stream opened without endstream
        last_stream = clean_data.rfind(b"stream")
        last_endstream = clean_data.rfind(b"endstream")
        if last_stream != -1 and (last_endstream == -1 or last_endstream < last_stream):
            clean_data.extend(b"\r\nendstream\r\nendobj\r\n")

        # Check if obj opened without endobj
        last_obj = clean_data.rfind(b"obj")
        last_endobj = clean_data.rfind(b"endobj")
        if last_obj != -1 and (last_endobj == -1 or last_endobj < last_obj):
            clean_data.extend(b"\r\nendobj\r\n")

        # Import XRef rebuilder to synthesize xref and trailer
        from services.pdf_xref_recovery import PDFXRefRecovery
        temp_out = "temp_eof_rebuild.tmp"
        ok = PDFXRefRecovery._synthesize_xref_table(bytes(clean_data), temp_out)
        if ok and os.path.exists(temp_out):
            with open(temp_out, "rb") as f:
                res_bytes = f.read()
            try:
                os.remove(temp_out)
            except Exception:
                pass
            return res_bytes

        return None

    @classmethod
    def _verify(cls, path: str) -> Dict[str, Any]:
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return {"openable": False, "pages": 0}
        if fitz:
            try:
                d = fitz.open(path)
                p = len(d)
                d.close()
                return {"openable": p > 0, "pages": p, "structure_valid": True}
            except Exception:
                pass
        if PdfReader:
            try:
                r = PdfReader(path)
                p = len(r.pages)
                return {"openable": p > 0, "pages": p, "structure_valid": True}
            except Exception:
                pass
        return {"openable": False, "pages": 0}
