from typing import Dict, Any, List, Optional
from services.tool_manager import ToolManager

class RecoveryToolRegistry:
    """
    Central Metadata & Registry for all Recovery Tools and Fallback Strategies.
    Decouples tool definitions from hardcoded branching logic.
    """

    TOOLS: list[dict] = [
        # --- PDF RECOVERY TOOLS ---
        {
            "id": "qpdf",
            "name": "QPDF Structural Linearizer & XREF Rebuilder",
            "supported_formats": ["PDF"],
            "corruption_types": ["HEADER", "XREF", "TRAILER", "EOF", "STRUCTURAL"],
            "priority": 1,
            "tool_key": "qpdf",
            "description": "High-performance external structural repair engine."
        },
        {
            "id": "pikepdf",
            "name": "pikepdf C++ Object Graph Repair",
            "supported_formats": ["PDF"],
            "corruption_types": ["HEADER", "BODY", "XREF", "TRAILER", "EOF"],
            "priority": 2,
            "tool_key": "pikepdf",
            "description": "Fast C++ QPDF Python binding for object stream reassembly."
        },
        {
            "id": "pymupdf",
            "name": "PyMuPDF Heuristic Stream Engine",
            "supported_formats": ["PDF"],
            "corruption_types": ["HEADER", "BODY", "XREF", "EOF"],
            "priority": 3,
            "tool_key": "pymupdf",
            "description": "PyMuPDF stream parser for displaced headers and damaged pages."
        },
        {
            "id": "pypdf",
            "name": "pypdf Permissive Object Stream Reassembler",
            "supported_formats": ["PDF"],
            "corruption_types": ["XREF", "TRAILER", "BODY"],
            "priority": 4,
            "tool_key": "pypdf",
            "description": "Pure-Python object graph parser and cross-reference rebuilder."
        },
        {
            "id": "raw_xref_rebuilder",
            "name": "Deep Binary Object Scanner & XREF Synthesizer",
            "supported_formats": ["PDF"],
            "corruption_types": ["XREF", "TRAILER", "EOF"],
            "priority": 5,
            "tool_key": "reportlab",
            "description": "Binary regex scanner synthesizing clean ASCII XREF and trailer dictionaries."
        },
        {
            "id": "zlib_stream_recovery",
            "name": "Multi-Window zlib Stream Salvager",
            "supported_formats": ["PDF"],
            "corruption_types": ["BODY", "STREAM"],
            "priority": 6,
            "tool_key": "reportlab",
            "description": "Multi-window deflate stream decompressor."
        },
        {
            "id": "page_carver",
            "name": "Isolated Page Object Carver & Multi-Page Assembler",
            "supported_formats": ["PDF"],
            "corruption_types": ["BODY", "STRUCTURAL"],
            "priority": 7,
            "tool_key": "pymupdf",
            "description": "Carves surviving renderable pages when intermediate page objects are destroyed."
        },
        {
            "id": "reportlab_reconstructor",
            "name": "Deep Stream Token Synthesis & ReportLab Rebuilder",
            "supported_formats": ["PDF"],
            "corruption_types": ["CRITICAL", "BODY", "XREF"],
            "priority": 8,
            "tool_key": "reportlab",
            "description": "Last-resort token extractor synthesizing a clean PDF via ReportLab."
        },

        # --- DOCX RECOVERY TOOLS ---
        {
            "id": "docx_zip_repair",
            "name": "ZIP Central Directory & Header Realignment",
            "supported_formats": ["DOCX", "WORD"],
            "corruption_types": ["HEADER", "ZIP", "EOF"],
            "priority": 1,
            "tool_key": "python-docx",
            "description": "Repairs ZIP packaging and extracts intact document parts."
        },
        {
            "id": "docx_xml_repair",
            "name": "XML Document Tree & Paragraph Harvester",
            "supported_formats": ["DOCX", "WORD"],
            "corruption_types": ["XML", "BODY"],
            "priority": 2,
            "tool_key": "python-docx",
            "description": "Sanitizes malformed document.xml tags and reconstructs paragraphs."
        },
        {
            "id": "docx_reconstructor",
            "name": "python-docx Document Synthesizer",
            "supported_formats": ["DOCX", "WORD"],
            "corruption_types": ["STRUCTURAL", "CRITICAL"],
            "priority": 3,
            "tool_key": "python-docx",
            "description": "Builds a fresh .docx container using harvested text runs and tables."
        },

        # --- XLSX RECOVERY TOOLS ---
        {
            "id": "xlsx_zip_repair",
            "name": "ZIP Container Realignment & OpenPyXL Loader",
            "supported_formats": ["XLSX", "EXCEL"],
            "corruption_types": ["HEADER", "ZIP", "EOF"],
            "priority": 1,
            "tool_key": "openpyxl",
            "description": "Repairs Excel ZIP container for native openpyxl loading."
        },
        {
            "id": "xlsx_xml_repair",
            "name": "Worksheet XML & SharedStrings Harvester",
            "supported_formats": ["XLSX", "EXCEL"],
            "corruption_types": ["XML", "BODY"],
            "priority": 2,
            "tool_key": "openpyxl",
            "description": "Extracts shared strings and row cells from damaged worksheets."
        },
        {
            "id": "xlsx_reconstructor",
            "name": "openpyxl Workbook Synthesizer",
            "supported_formats": ["XLSX", "EXCEL"],
            "corruption_types": ["STRUCTURAL", "CRITICAL"],
            "priority": 3,
            "tool_key": "openpyxl",
            "description": "Generates a fresh, verified .xlsx workbook."
        },

        # --- PPTX RECOVERY TOOLS ---
        {
            "id": "pptx_zip_repair",
            "name": "ZIP Header Realignment & python-pptx Loader",
            "supported_formats": ["PPTX", "POWERPOINT"],
            "corruption_types": ["HEADER", "ZIP", "EOF"],
            "priority": 1,
            "tool_key": "python-pptx",
            "description": "Repairs PPTX container for direct presentation loading."
        },
        {
            "id": "pptx_slide_repair",
            "name": "Slide XML & Shape Harvester",
            "supported_formats": ["PPTX", "POWERPOINT"],
            "corruption_types": ["XML", "BODY"],
            "priority": 2,
            "tool_key": "python-pptx",
            "description": "Extracts slide shapes and text from individual slide XMLs."
        },
        {
            "id": "pptx_reconstructor",
            "name": "python-pptx Presentation Synthesizer",
            "supported_formats": ["PPTX", "POWERPOINT"],
            "corruption_types": ["STRUCTURAL", "CRITICAL"],
            "priority": 3,
            "tool_key": "python-pptx",
            "description": "Reconstructs slides and bullet points in a fresh .pptx presentation."
        },

        # --- IMAGE RECOVERY TOOLS ---
        {
            "id": "pillow_loader",
            "name": "Pillow Truncated Stream Loader",
            "supported_formats": ["JPEG", "PNG", "WEBP", "IMAGE"],
            "corruption_types": ["EOF", "BODY", "TRUNCATION"],
            "priority": 1,
            "tool_key": "pillow",
            "description": "Loads and re-encodes truncated pixel raster streams."
        },
        {
            "id": "image_marker_repair",
            "name": "Image Header & Marker Realignment Engine",
            "supported_formats": ["JPEG", "PNG", "WEBP", "IMAGE"],
            "corruption_types": ["HEADER", "EOF", "MARKER"],
            "priority": 2,
            "tool_key": "pillow",
            "description": "Repairs displaced headers, SOI/EOI, and PNG IEND chunks."
        },
        {
            "id": "png_chunk_synthesizer",
            "name": "PNG IDAT Stream & Chunk Synthesizer",
            "supported_formats": ["PNG", "IMAGE"],
            "corruption_types": ["BODY", "STRUCTURAL"],
            "priority": 3,
            "tool_key": "pillow",
            "description": "Constructs valid PNG headers around surviving IDAT streams."
        },

        # --- TEXT & CSV TOOLS ---
        {
            "id": "encoding_normalizer",
            "name": "Multi-Encoding Normalizer",
            "supported_formats": ["TEXT", "CSV", "JSON"],
            "corruption_types": ["ENCODING"],
            "priority": 1,
            "tool_key": "pillow", # built-in Python
            "description": "Detects UTF-8/UTF-16/Latin-1 encodings and strips binary noise."
        },
        {
            "id": "csv_rebuilder",
            "name": "CSV Delimiter & Inconsistent Column Rebuilder",
            "supported_formats": ["CSV"],
            "corruption_types": ["BODY", "STRUCTURAL"],
            "priority": 1,
            "tool_key": "pillow",
            "description": "Equalizes column lengths and normalizes CSV delimiters."
        },
        {
            "id": "json_repair",
            "name": "JSON Syntax & Balanced Bracket Rebuilder",
            "supported_formats": ["JSON"],
            "corruption_types": ["BODY", "SYNTAX"],
            "priority": 1,
            "tool_key": "pillow",
            "description": "Fixes unescaped quotes, trailing commas, and unclosed brackets."
        }
    ]

    @classmethod
    def get_candidate_tools_for_analysis(cls, format_type: str, corruption_dict: dict) -> list[dict]:
        """
        Filters and ranks available candidate tools for a given format and corruption matrix.
        Only returns tools that are currently available on the system.
        """
        fmt = format_type.upper()
        candidates = []

        for tool in cls.TOOLS:
            # Check format match
            if not any(f in fmt for f in tool["supported_formats"]):
                continue

            # Check availability
            t_key = tool.get("tool_key", "")
            if t_key and not ToolManager.is_tool_available(t_key):
                continue

            # Calculate match score based on corruption types
            match_score = 0
            for c_type in tool["corruption_types"]:
                c_key = c_type.lower()
                if corruption_dict.get(c_key):
                    match_score += 10

            candidates.append({
                "id": tool["id"],
                "name": tool["name"],
                "priority": tool["priority"],
                "match_score": match_score,
                "description": tool["description"],
                "available": True
            })

        # Sort by match score (descending) and priority (ascending)
        candidates.sort(key=lambda x: (-x["match_score"], x["priority"]))
        return candidates
