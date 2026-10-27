import os
import logging
from typing import Dict, Any, List, Optional, Callable

from services.tool_manager import ToolManager

logger = logging.getLogger("FileGuard.ToolRegistry")


class ToolRegistry:
    """
    Central Modular Recovery Tool Registry.
    Every recovery tool defines:
      - id: unique identifier
      - name: human-readable name
      - supported_formats: list of file formats (e.g. ['PDF'])
      - supported_corruption_types: list of corruption categories (e.g. ['HEADER', 'XREF'])
      - tool_key: underlying executable or python package name
      - priority: integer ranking (1 = highest priority)
      - timeout_seconds: execution timeout
      - description: technical explanation
      - install_guide: installation instructions if missing
      - recovery_function_name: function handling the recovery
      - validation_method: method used to validate the output
    """

    TOOLS: List[Dict[str, Any]] = [
        # --- PDF RECOVERY TOOLS ---
        {
            "id": "pdf_header_recovery",
            "name": "PDF Header Realignment & Magic Byte Synthesizer",
            "supported_formats": ["PDF"],
            "supported_corruption_types": ["HEADER", "PDF_HEADER_CORRUPTION"],
            "tool_key": "pikepdf",
            "priority": 1,
            "timeout_seconds": 30,
            "description": "Aligns displaced %PDF headers, trims pre-header garbage, and reconstructs damaged signatures.",
            "recovery_module": "services.pdf_header_recovery",
            "validation_method": "PyMuPDF / pikepdf page verification"
        },
        {
            "id": "pdf_xref_recovery",
            "name": "XREF Table & Trailer Recalculation Engine",
            "supported_formats": ["PDF"],
            "supported_corruption_types": ["XREF", "PDF_XREF_CORRUPTION", "TRAILER"],
            "tool_key": "pikepdf",
            "priority": 1,
            "timeout_seconds": 45,
            "description": "Recalculates exact object byte offsets and rebuilds ASCII cross-reference tables and trailers.",
            "recovery_module": "services.pdf_xref_recovery",
            "validation_method": "Parser reload and startxref pointer verification"
        },
        {
            "id": "pdf_eof_recovery",
            "name": "PDF Structural Stream & EOF Stabilizer",
            "supported_formats": ["PDF"],
            "supported_corruption_types": ["EOF", "PDF_EOF_TRUNCATION", "TRUNCATION"],
            "tool_key": "pikepdf",
            "priority": 1,
            "timeout_seconds": 30,
            "description": "Seals open streams and objects, recalculates trailers, and stabilizes truncated endings.",
            "recovery_module": "services.pdf_eof_recovery",
            "validation_method": "Independent parser open & page tree traversal"
        },
        {
            "id": "pdf_image_recovery",
            "name": "Embedded Image Carver & Raster Restorer",
            "supported_formats": ["PDF"],
            "supported_corruption_types": ["IMAGE", "PDF_IMAGE_CORRUPTION"],
            "tool_key": "pillow",
            "priority": 1,
            "timeout_seconds": 60,
            "description": "Extracts damaged embedded JPEG/PNG streams, restores markers, and reinserts into PDF.",
            "recovery_module": "services.pdf_image_recovery",
            "validation_method": "Pillow raster verification & page rendering"
        },
        {
            "id": "pdf_body_recovery",
            "name": "PDF Content Stream Salvager & Page Carver",
            "supported_formats": ["PDF"],
            "supported_corruption_types": ["BODY", "PDF_BODY_CORRUPTION", "STREAM"],
            "tool_key": "pymupdf",
            "priority": 2,
            "timeout_seconds": 60,
            "description": "Harvests readable page content, extracts surviving text & tables, and rebuilds document.",
            "recovery_module": "services.pdf_body_recovery",
            "validation_method": "PyMuPDF page rendering & text extraction"
        },
        {
            "id": "qpdf",
            "name": "QPDF Structural Linearizer & Rebuilder",
            "supported_formats": ["PDF"],
            "supported_corruption_types": ["HEADER", "XREF", "EOF", "STRUCTURAL"],
            "tool_key": "qpdf",
            "priority": 2,
            "timeout_seconds": 30,
            "description": "High-performance external PDF linearization and repair tool.",
            "recovery_module": "services.pdf_recovery",
            "validation_method": "qpdf check / independent parser reload"
        },
        {
            "id": "pikepdf",
            "name": "pikepdf C++ Object Graph Repair",
            "supported_formats": ["PDF"],
            "supported_corruption_types": ["HEADER", "BODY", "XREF", "EOF", "STRUCTURAL"],
            "tool_key": "pikepdf",
            "priority": 2,
            "timeout_seconds": 30,
            "description": "C++ QPDF Python binding for resilient object graph traversal and stream repair.",
            "recovery_module": "services.pdf_recovery",
            "validation_method": "pikepdf open & page count verification"
        },
        {
            "id": "pymupdf",
            "name": "PyMuPDF Heuristic Stream Engine",
            "supported_formats": ["PDF"],
            "supported_corruption_types": ["HEADER", "BODY", "XREF", "EOF"],
            "tool_key": "pymupdf",
            "priority": 3,
            "timeout_seconds": 30,
            "description": "Heuristic parser capable of rendering damaged streams and recovering displaced content.",
            "recovery_module": "services.pdf_recovery",
            "validation_method": "PyMuPDF pixmap rendering"
        },
        {
            "id": "pypdf",
            "name": "pypdf Permissive Object Stream Reassembler",
            "supported_formats": ["PDF"],
            "supported_corruption_types": ["XREF", "BODY", "TRAILER"],
            "tool_key": "pypdf",
            "priority": 4,
            "timeout_seconds": 30,
            "description": "Pure-Python parser reconstructing object streams and cross-reference tables.",
            "recovery_module": "services.pdf_recovery",
            "validation_method": "pypdf page count & reader verification"
        },
        {
            "id": "mutool",
            "name": "MuPDF mutool Stream Cleaner",
            "supported_formats": ["PDF"],
            "supported_corruption_types": ["XREF", "BODY", "STRUCTURAL"],
            "tool_key": "mutool",
            "priority": 4,
            "timeout_seconds": 30,
            "description": "MuPDF external CLI for deep stream sanitization and object table recovery.",
            "recovery_module": "services.pdf_xref_recovery",
            "validation_method": "mutool verification"
        },

        # --- DOCX RECOVERY TOOLS ---
        {
            "id": "docx_recovery",
            "name": "OpenXML Word Document Recovery Engine",
            "supported_formats": ["DOCX", "WORD"],
            "supported_corruption_types": ["ZIP", "XML", "HEADER", "STRUCTURAL"],
            "tool_key": "python-docx",
            "priority": 1,
            "timeout_seconds": 45,
            "description": "Repairs corrupted ZIP containers and harvests surviving Word document paragraphs.",
            "recovery_module": "services.docx_recovery",
            "validation_method": "python-docx document parse & paragraph iteration"
        },

        # --- XLSX RECOVERY TOOLS ---
        {
            "id": "xlsx_recovery",
            "name": "OpenXML Excel Spreadsheet Recovery Engine",
            "supported_formats": ["XLSX", "EXCEL"],
            "supported_corruption_types": ["ZIP", "XML", "HEADER", "STRUCTURAL"],
            "tool_key": "openpyxl",
            "priority": 1,
            "timeout_seconds": 45,
            "description": "Repairs corrupted spreadsheet ZIP packaging and harvests cell grids and shared strings.",
            "recovery_module": "services.xlsx_recovery",
            "validation_method": "openpyxl workbook load & cell validation"
        },

        # --- PPTX RECOVERY TOOLS ---
        {
            "id": "pptx_recovery",
            "name": "OpenXML PowerPoint Presentation Recovery Engine",
            "supported_formats": ["PPTX", "POWERPOINT"],
            "supported_corruption_types": ["ZIP", "XML", "HEADER", "STRUCTURAL"],
            "tool_key": "python-pptx",
            "priority": 1,
            "timeout_seconds": 45,
            "description": "Repairs PowerPoint presentation archive and reconstructs slide layouts.",
            "recovery_module": "services.pptx_recovery",
            "validation_method": "python-pptx presentation load"
        },

        # --- IMAGE RECOVERY TOOLS ---
        {
            "id": "image_recovery",
            "name": "Pillow Raster Image Recovery Engine",
            "supported_formats": ["IMAGE", "JPEG", "JPG", "PNG", "WEBP"],
            "supported_corruption_types": ["IMAGE_DATA_CORRUPTION", "HEADER", "MARKER", "TRUNCATION"],
            "tool_key": "pillow",
            "priority": 1,
            "timeout_seconds": 30,
            "description": "Restores damaged JPEG/PNG markers and salvages truncated scanlines.",
            "recovery_module": "services.image_recovery",
            "validation_method": "Pillow load & dimension verification"
        },

        # --- TEXT & DELIMITED TOOLS ---
        {
            "id": "text_recovery",
            "name": "Multi-Codec Text & Delimited Recovery Engine",
            "supported_formats": ["TEXT", "CSV", "JSON"],
            "supported_corruption_types": ["ENCODING", "SYNTAX", "DELIMITER"],
            "tool_key": "filetype",
            "priority": 1,
            "timeout_seconds": 20,
            "description": "Normalizes damaged text encodings and repairs malformed CSV / JSON syntax.",
            "recovery_module": "services.text_recovery",
            "validation_method": "UTF-8 decode & json/csv parser verification"
        }
    ]

    @classmethod
    def get_all_tools(cls) -> List[Dict[str, Any]]:
        """Returns all registered tools enriched with current installation and availability status."""
        enriched = []
        for tool in cls.TOOLS:
            t = dict(tool)
            is_avail = ToolManager.is_tool_available(t.get("tool_key", ""))
            tool_info = ToolManager.get_system_tools().get(t.get("tool_key", "").lower(), {})
            t["is_installed"] = is_avail
            t["availability_status"] = "INSTALLED" if is_avail else "MISSING"
            t["install_guide"] = tool_info.get("install_guide", f"Install via package manager or pip install {t.get('tool_key')}")
            enriched.append(t)
        return enriched

    @classmethod
    def get_tool(cls, tool_id: str) -> Optional[Dict[str, Any]]:
        """Finds a tool definition by ID."""
        for t in cls.get_all_tools():
            if t["id"].lower() == tool_id.lower() or t.get("tool_key", "").lower() == tool_id.lower():
                return t
        return None

    @classmethod
    def check_tool_availability(cls, tool_name: str) -> bool:
        """Top-level availability check interface."""
        return ToolManager.is_tool_available(tool_name)


# Functional alias for interface compliance
def check_tool_availability(tool_name: str) -> bool:
    return ToolRegistry.check_tool_availability(tool_name)
