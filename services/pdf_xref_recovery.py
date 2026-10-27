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

logger = logging.getLogger("FileGuard.PDFXRefRecovery")


class PDFXRefRecovery:
    """
    Dedicated Cross-Reference (XREF) and Trailer Recovery Engine.
    Repairs damaged xref tables, incorrect startxref pointers, missing xref streams,
    and corrupted trailer dictionaries by recalculating byte offsets deterministically.
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
                "tool_used": "XREF Inspector",
                "corruption_detected": "Zero-byte file",
                "operations_performed": [],
                "validation_results": {"openable": False},
                "content_preservation": "0 bytes",
                "error": "Cannot rebuild XREF for 0-byte file."
            }

        with open(input_path, "rb") as f:
            raw_data = f.read()

        ops = []
        warnings = []

        # 1. Attempt QPDF Structural Linearization (Primary Tool)
        qpdf_bin = shutil.which("qpdf")
        if qpdf_bin:
            ops.append("Executing QPDF --repair-file to rebuild XREF table and trailer dictionary")
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
                        "corruption_detected": "Damaged XREF / startxref pointer",
                        "operations_performed": ops,
                        "validation_results": val,
                        "content_preservation": f"{val.get('pages', 1)} pages verified",
                        "warnings": warnings
                    }

        # 2. Attempt pikepdf C++ QPDF Engine (Secondary Tool)
        if pikepdf:
            try:
                ops.append("Loading document into pikepdf with recover=True to re-index object graph")
                with pikepdf.open(input_path, recover=True) as pdf:
                    pdf.save(output_path)
                val = cls._verify(output_path)
                if val["openable"]:
                    return {
                        "success": True,
                        "status": "FULLY_RECOVERED",
                        "input_file": input_path,
                        "output_file": output_path,
                        "tool_used": "pikepdf C++ Engine",
                        "corruption_detected": "Corrupted XREF offsets",
                        "operations_performed": ops,
                        "validation_results": val,
                        "content_preservation": f"{val.get('pages', 1)} pages verified",
                        "warnings": warnings
                    }
            except Exception as e:
                warnings.append(f"pikepdf xref repair exception: {str(e)[:60]}")

        # 3. Attempt MuPDF mutool clean if installed (Independent External Recovery)
        mutool_bin = shutil.which("mutool")
        if mutool_bin:
            ops.append("Executing mutool clean -s to sanitize object streams and re-emit XREF")
            ok, out, err = run_external_command([mutool_bin, "clean", "-s", input_path, output_path], timeout=15)
            if ok and os.path.exists(output_path) and os.path.getsize(output_path) > 100:
                val = cls._verify(output_path)
                if val["openable"]:
                    return {
                        "success": True,
                        "status": "FULLY_RECOVERED",
                        "input_file": input_path,
                        "output_file": output_path,
                        "tool_used": "MuPDF mutool CLI",
                        "corruption_detected": "Corrupted XREF table",
                        "operations_performed": ops,
                        "validation_results": val,
                        "content_preservation": f"{val.get('pages', 1)} pages verified",
                        "warnings": warnings
                    }

        # 4. Fallback: PyMuPDF Heuristic XREF Repair
        if fitz:
            try:
                ops.append("Opening with PyMuPDF heuristic scanner and saving with garbage=4")
                doc = fitz.open(input_path)
                pages = len(doc)
                if pages > 0:
                    doc.save(output_path, garbage=4, deflate=True, clean=True)
                    doc.close()
                    val = cls._verify(output_path)
                    if val["openable"]:
                        return {
                            "success": True,
                            "status": "FULLY_RECOVERED",
                            "input_file": input_path,
                            "output_file": output_path,
                            "tool_used": "PyMuPDF Stream Engine",
                            "corruption_detected": "Damaged XREF table",
                            "operations_performed": ops,
                            "validation_results": val,
                            "content_preservation": f"{pages} pages verified",
                            "warnings": warnings
                        }
            except Exception as e:
                warnings.append(f"PyMuPDF xref exception: {str(e)[:60]}")

        # 5. Fallback: Binary Regex Object Scanning & Exact XREF Reconstruction
        ops.append("Scanning binary for object boundaries to synthesize a recalculated ASCII XREF table")
        rebuilt_ok = cls._synthesize_xref_table(raw_data, output_path)
        if rebuilt_ok:
            val = cls._verify(output_path)
            if val["openable"]:
                return {
                    "success": True,
                    "status": "FULLY_RECOVERED",
                    "input_file": input_path,
                    "output_file": output_path,
                    "tool_used": "Binary Regex XREF Synthesizer",
                    "corruption_detected": "Completely missing/invalid XREF table",
                    "operations_performed": ops,
                    "validation_results": val,
                    "content_preservation": f"{val.get('pages', 1)} pages verified",
                    "warnings": warnings
                }

        return {
            "success": False,
            "status": "FAILED",
            "input_file": input_path,
            "output_file": output_path,
            "tool_used": "PDFXRefRecovery",
            "corruption_detected": "Unrepairable cross-reference structures",
            "operations_performed": ops,
            "validation_results": {"openable": False},
            "content_preservation": "0 bytes",
            "error": "XREF table reconstruction could not produce a valid document tree.",
            "warnings": warnings
        }

    @classmethod
    def _synthesize_xref_table(cls, data: bytes, target_path: str) -> bool:
        """
        Locates all surviving 'N M obj' definitions, computes their exact byte offsets,
        synthesizes a valid ASCII xref table, trailer dictionary, and startxref pointer.
        """
        obj_matches = list(re.finditer(rb"(?:^|\r|\n)(\d+)\s+(\d+)\s+obj\b", data))
        if not obj_matches:
            return False

        # Find catalog/root object
        root_num = 1
        cat_match = re.search(rb"(\d+)\s+(\d+)\s+obj\s*<<[^>]*?/Type\s*/Catalog", data)
        if cat_match:
            root_num = int(cat_match.group(1))

        # Build table entries
        objects = {}
        for m in obj_matches:
            num = int(m.group(1))
            offset = m.start(1)
            if num not in objects:
                objects[num] = offset

        max_obj = max(objects.keys())
        # Truncate at old xref or EOF if present
        body_end = len(data)
        xref_pos = data.rfind(b"xref")
        if xref_pos != -1 and xref_pos > len(data) // 2:
            body_end = xref_pos

        base_body = data[:body_end].rstrip()
        xref_offset = len(base_body) + 1

        xref_lines = [f"xref\n0 {max_obj + 1}\n0000000000 65535 f \n"]
        for i in range(1, max_obj + 1):
            if i in objects:
                xref_lines.append(f"{objects[i]:010d} 00000 n \n")
            else:
                xref_lines.append("0000000000 00000 f \n")

        trailer_str = (
            f"trailer\n<< /Size {max_obj + 1} /Root {root_num} 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        )

        full_rebuilt = base_body + b"\n" + "".join(xref_lines).encode("ascii") + trailer_str.encode("ascii")
        try:
            with open(target_path, "wb") as f_out:
                f_out.write(full_rebuilt)
            return True
        except Exception:
            return False

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
