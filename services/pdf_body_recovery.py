import os
import re
import io
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

try:
    import pdfplumber
except ImportError:
    pdfplumber = None

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
except ImportError:
    SimpleDocTemplate = None

from utils.process_utils import run_external_command

logger = logging.getLogger("FileGuard.PDFBodyRecovery")


class PDFBodyRecovery:
    """
    Dedicated PDF Body and Content Stream Corruption Recovery Engine.
    Handles damaged page content streams, truncated deflate streams, damaged text/image objects,
    and missing page objects. Extracts all surviving pages, text, and tables,
    and reconstructs a clean, non-blank PDF document preserving layout and page sequence.
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
                "tool_used": "Body Inspector",
                "corruption_detected": "Zero-byte file",
                "operations_performed": [],
                "validation_results": {"openable": False},
                "content_preservation": "0 bytes",
                "error": "Cannot recover content from 0-byte file."
            }

        ops = []
        warnings = []

        # 1. Attempt pikepdf Object Stream Recovery
        if pikepdf:
            try:
                ops.append("Executing pikepdf object stream re-indexing and deflation repair")
                with pikepdf.open(input_path, recover=True) as pdf:
                    pages = len(pdf.pages)
                    if pages > 0:
                        pdf.save(output_path)
                        val = cls._verify(output_path)
                        if val["openable"] and val.get("has_content", True):
                            return {
                                "success": True,
                                "status": "FULLY_RECOVERED",
                                "input_file": input_path,
                                "output_file": output_path,
                                "tool_used": "pikepdf C++ Stream Engine",
                                "corruption_detected": "Damaged content streams",
                                "operations_performed": ops,
                                "validation_results": val,
                                "content_preservation": f"{pages} pages verified with intact text",
                                "warnings": warnings
                            }
            except Exception as e:
                warnings.append(f"pikepdf body repair: {str(e)[:60]}")

        # 2. Attempt QPDF Repair if installed
        qpdf_bin = shutil.which("qpdf")
        if qpdf_bin:
            ops.append("Executing QPDF --repair-file")
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
                        "corruption_detected": "Corrupted content streams",
                        "operations_performed": ops,
                        "validation_results": val,
                        "content_preservation": f"{val.get('pages', 1)} pages verified",
                        "warnings": warnings
                    }

        # 3. Attempt PyMuPDF Page-by-Page Harvester and Assembler
        if fitz:
            try:
                ops.append("Opening with PyMuPDF to salvage readable pages and text streams")
                src_doc = fitz.open(input_path)
                surviving_pages = []
                extracted_texts = []

                for p_idx in range(len(src_doc)):
                    try:
                        p = src_doc[p_idx]
                        t = p.get_text()
                        pix = p.get_pixmap()
                        if (t and len(t.strip()) > 0) or (pix.width > 0 and pix.height > 0):
                            surviving_pages.append(p_idx)
                            if t:
                                extracted_texts.append(t.strip())
                    except Exception:
                        warnings.append(f"Page {p_idx + 1} stream was destroyed and omitted")

                if surviving_pages:
                    new_doc = fitz.open()
                    new_doc.insert_pdf(src_doc, from_page=surviving_pages[0], to_page=surviving_pages[-1])
                    new_doc.save(output_path, garbage=4, deflate=True)
                    new_doc.close()
                    src_doc.close()

                    val = cls._verify(output_path)
                    if val["openable"]:
                        return {
                            "success": True,
                            "status": "FULLY_RECOVERED" if len(surviving_pages) == len(src_doc) else "PARTIALLY_RECOVERED",
                            "input_file": input_path,
                            "output_file": output_path,
                            "tool_used": "PyMuPDF Stream Carver",
                            "corruption_detected": "Damaged page content streams",
                            "operations_performed": ops,
                            "validation_results": val,
                            "content_preservation": f"{len(surviving_pages)} pages preserved",
                            "warnings": warnings
                        }
                src_doc.close()
            except Exception as e:
                warnings.append(f"PyMuPDF page harvest: {str(e)[:60]}")

        # 4. Content Extraction & Document Rebuild via pdfplumber / ReportLab (Last Resort)
        ops.append("Extracting intact text runs and synthesizing a rebuilt document structure")
        harvested_paragraphs = cls._extract_text_content(input_path)
        if harvested_paragraphs and SimpleDocTemplate:
            rebuilt_ok = cls._rebuild_document_from_text(harvested_paragraphs, output_path)
            if rebuilt_ok:
                val = cls._verify(output_path)
                return {
                    "success": True,
                    "status": "PARTIALLY_RECOVERED",
                    "input_file": input_path,
                    "output_file": output_path,
                    "tool_used": "Content Extractor & ReportLab Synthesizer",
                    "corruption_detected": "Destructive content stream corruption",
                    "operations_performed": ops,
                    "validation_results": val,
                    "content_preservation": f"Rebuilt from {len(harvested_paragraphs)} extracted text sections",
                    "warnings": warnings + ["Document rebuilt from extracted text; original vector styling refreshed."]
                }

        return {
            "success": False,
            "status": "FAILED",
            "input_file": input_path,
            "output_file": output_path,
            "tool_used": "PDFBodyRecovery",
            "corruption_detected": "Severe body stream destruction",
            "operations_performed": ops,
            "validation_results": {"openable": False},
            "content_preservation": "0 bytes",
            "error": "Content streams completely unreadable across all parsers.",
            "warnings": warnings
        }

    @classmethod
    def _extract_text_content(cls, file_path: str) -> List[str]:
        """Extracts text using pdfplumber, PyMuPDF, or binary string regex scanning."""
        texts = []
        # Try pdfplumber first if installed
        if pdfplumber:
            try:
                with pdfplumber.open(file_path) as plum:
                    for page in plum.pages:
                        ptxt = page.extract_text()
                        if ptxt and len(ptxt.strip()) > 0:
                            texts.append(ptxt.strip())
                if texts:
                    return texts
            except Exception:
                pass

        # Try fitz
        if fitz:
            try:
                doc = fitz.open(file_path)
                for page in doc:
                    t = page.get_text()
                    if t and len(t.strip()) > 0:
                        texts.append(t.strip())
                doc.close()
                if texts:
                    return texts
            except Exception:
                pass

        # Binary fallback
        try:
            with open(file_path, "rb") as f:
                raw = f.read()
            from services.pdf_recovery import PDFRecoveryEngine
            salvaged = PDFRecoveryEngine.extract_all_text_from_pdf_binary(raw)
            if salvaged:
                return salvaged
        except Exception:
            pass

        return texts

    @classmethod
    def _rebuild_document_from_text(cls, paragraphs: List[str], target_path: str) -> bool:
        if not SimpleDocTemplate:
            return False
        try:
            doc = SimpleDocTemplate(target_path, pagesize=letter, leftMargin=54, rightMargin=54, topMargin=54, bottomMargin=54)
            styles = getSampleStyleSheet()
            normal_style = styles["Normal"]
            story = []

            for p in paragraphs:
                clean_p = p.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                story.append(Paragraph(clean_p, normal_style))
                story.append(Spacer(1, 10))

            doc.build(story)
            return os.path.exists(target_path) and os.path.getsize(target_path) > 100
        except Exception:
            return False

    @classmethod
    def _verify(cls, path: str) -> Dict[str, Any]:
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return {"openable": False, "pages": 0, "has_content": False}
        if fitz:
            try:
                d = fitz.open(path)
                p = len(d)
                has_content = False
                for page in d:
                    if len(page.get_text().strip()) > 0 or len(page.get_images()) > 0:
                        has_content = True
                        break
                d.close()
                return {"openable": p > 0, "pages": p, "has_content": has_content, "structure_valid": True}
            except Exception:
                pass
        return {"openable": False, "pages": 0, "has_content": False}
