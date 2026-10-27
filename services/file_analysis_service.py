import os
import re
from pathlib import Path
from typing import Dict, Any, List, Optional
from services.detector import FileDetector
from services.pdf_analyzer import PDFAnalyzer
from services.docx_analyzer import DOCXAnalyzer
from services.xlsx_analyzer import XLSXAnalyzer
from services.pptx_analyzer import PPTXAnalyzer
from services.image_analyzer import ImageAnalyzer
from services.tool_manager import ToolManager
from utils.file_utils import format_size

class FileAnalysisService:
    """
    Unified, Standardized Multi-Format File Corruption & Integrity Analysis Engine.
    Produces a standardized forensic report for any uploaded file.
    """

    @classmethod
    def analyze_file(cls, file_path: str, filename: str | None = None, file_id: str | None = None) -> Dict[str, Any]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        file_name = filename or os.path.basename(file_path)
        ext = os.path.splitext(file_name)[1].lower()
        size_bytes = os.path.getsize(file_path)
        fid = file_id or "file_001"

        # 1. 0-Byte Special Handling
        if size_bytes == 0:
            return {
                "file_id": fid,
                "filename": file_name,
                "extension": ext,
                "detected_type": "EMPTY",
                "mime_type": "application/x-empty",
                "size": 0,
                "size_human": "0 B",
                "integrity": {
                    "status": "CORRUPTED",
                    "score": 0,
                    "is_intact": False
                },
                "corruption": {
                    "header": True,
                    "body": True,
                    "xref": True,
                    "trailer": True,
                    "eof": True,
                    "zip": True,
                    "xml": True,
                    "encoding": False
                },
                "errors": ["File is completely empty (0 bytes)."],
                "recoverability": "UNRECOVERABLE",
                "classification": "UNRECOVERABLE",
                "recommended_tools": [],
                "available_tools": ToolManager.get_available_tool_names(),
                "summary": "File contains 0 bytes. No data can be recovered."
            }

        # 2. Sniff true type with magic bytes
        detection = FileDetector.detect_file_type(file_path, file_name)
        detected_category = (detection.get("file_type") or "").upper()
        detected_mime = detection.get("mime_type") or "application/octet-stream"

        with open(file_path, "rb") as f:
            raw_head = f.read(4096)

        # 3. Route to format-specific analyzer
        analysis_raw = None
        if detected_category == "PDF" or ext == ".pdf" or b"%PDF" in raw_head:
            analysis_raw = PDFAnalyzer.analyze(file_path)
            detected_category = "PDF"
        elif ext == ".docx" or (b"PK" in raw_head and (b"word/" in raw_head or detected_category == "WORD")):
            analysis_raw = DOCXAnalyzer.analyze(file_path)
            detected_category = "DOCX"
        elif ext in [".xlsx", ".xls"] or (b"PK" in raw_head and b"xl/" in raw_head):
            analysis_raw = XLSXAnalyzer.analyze(file_path)
            detected_category = "XLSX"
        elif ext in [".pptx", ".ppt"] or (b"PK" in raw_head and b"ppt/" in raw_head):
            analysis_raw = PPTXAnalyzer.analyze(file_path)
            detected_category = "PPTX"
        elif detected_category == "IMAGE" or ext in [".jpg", ".jpeg", ".png", ".webp", ".gif"]:
            analysis_raw = ImageAnalyzer.analyze(file_path)
            detected_category = analysis_raw.get("file_type", "IMAGE")
        else:
            analysis_raw = cls._analyze_generic_text_or_binary(file_path, raw_head, ext)
            detected_category = analysis_raw.get("file_type", "TEXT")

        # 4. Standardize Corruption Matrix
        corruption_dict = {
            "header": False,
            "body": False,
            "xref": False,
            "trailer": False,
            "eof": False,
            "zip": False,
            "xml": False,
            "encoding": False,
            "image": False
        }

        errors = []
        is_corrupted = analysis_raw.get("is_corrupted", False)
        regions = analysis_raw.get("corruption_regions", [])

        for r in regions:
            r_type = r.get("region", "").lower()
            r_status = r.get("status", "valid").lower()
            if r_status in ["corrupted", "warning", "error"]:
                if "header" in r_type:
                    corruption_dict["header"] = True
                if "body" in r_type or "stream" in r_type or "data" in r_type:
                    corruption_dict["body"] = True
                if "xref" in r_type or "references" in r_type:
                    corruption_dict["xref"] = True
                if "trailer" in r_type or "catalog" in r_type or "presentation" in r_type or "workbook" in r_type:
                    corruption_dict["trailer"] = True
                if "eof" in r_type or "end_of_file" in r_type:
                    corruption_dict["eof"] = True
                if "zip" in r_type or "container" in r_type:
                    corruption_dict["zip"] = True
                if "xml" in r_type or "worksheets" in r_type or "slides" in r_type:
                    corruption_dict["xml"] = True
                if "encoding" in r_type:
                    corruption_dict["encoding"] = True
                if "image" in r_type or "picture" in r_type or "raster" in r_type:
                    corruption_dict["image"] = True

                if r.get("reason"):
                    errors.append(f"[{r.get('name', r_type.title())}] {r.get('reason')}")

        # 5. Compute Severity Classification & Integrity Score
        corrupt_count = sum(1 for v in corruption_dict.values() if v)
        if not is_corrupted and corrupt_count == 0:
            classification = "NONE"
            score = 100
            recoverability = "HIGH"
            integrity_status = "HEALTHY"
        elif corrupt_count == 1:
            classification = "MINOR"
            score = 80
            recoverability = "HIGH"
            integrity_status = "CORRUPTED"
        elif corrupt_count == 2:
            classification = "MODERATE"
            score = 55
            recoverability = "HIGH"
            integrity_status = "CORRUPTED"
        elif corrupt_count in [3, 4]:
            classification = "SEVERE"
            score = 30
            recoverability = "MEDIUM"
            integrity_status = "CORRUPTED"
        else:
            classification = "CRITICAL"
            score = 10
            recoverability = "LOW"
            integrity_status = "CORRUPTED"

        # Check if totally unrecoverable
        if not analysis_raw.get("can_recover", True):
            classification = "UNRECOVERABLE"
            recoverability = "UNRECOVERABLE"
            score = 0
            integrity_status = "UNRECOVERABLE"

        # 6. Resolve recommended tools from Tool Registry
        from services.recovery_tool_registry import RecoveryToolRegistry
        recommended_tools = RecoveryToolRegistry.get_candidate_tools_for_analysis(
            detected_category,
            corruption_dict
        )

        # 7. Resolve command-level strategy tools for analysis cards
        strategy_tools = analysis_raw.get("recommended_tools") or []
        if not strategy_tools and isinstance(analysis_raw.get("details"), dict):
            for reg in analysis_raw.get("corruption_regions", []):
                for st in reg.get("suggested_tools", []):
                    if not any(t.get("tool") == st.get("tool") for t in strategy_tools):
                        strategy_tools.append({
                            "tool": st.get("tool", ""),
                            "command": st.get("command", ""),
                            "approach": st.get("action") or st.get("approach", "")
                        })

        if not strategy_tools:
            if "PDF" in detected_category:
                strategy_tools = [
                    {
                        "tool": "qpdf",
                        "command": "qpdf --check input.pdf ; qpdf --repair-file input.pdf recovered.pdf",
                        "approach": "Rebuilds cross-reference table and recalculates trailer dictionaries from surviving object graph."
                    },
                    {
                        "tool": "mutool",
                        "command": "mutool clean -d -g input.pdf recovered.pdf",
                        "approach": "MuPDF parser repairs broken xref offsets and sanitizes syntax trees."
                    }
                ]
            elif any(k in detected_category for k in ["DOC", "WORD"]):
                strategy_tools = [
                    {
                        "tool": "7-Zip / Package Salvager",
                        "command": "7z x -tzip input.docx -oextracted ; 7z a -tzip recovered.docx ./extracted/*",
                        "approach": "Extracts surviving XML parts, repairs ZIP local header CRC descriptors, and rebuilds valid package."
                    },
                    {
                        "tool": "python-docx / lxml",
                        "command": "python-docx (Deep Document XML Sanitizer)",
                        "approach": "Parses word/document.xml, balances unclosed tags, and reconstructs paragraph and table runs."
                    }
                ]
            elif any(k in detected_category for k in ["XLS", "EXCEL"]):
                strategy_tools = [
                    {
                        "tool": "openpyxl Data Carver",
                        "command": "openpyxl.load_workbook(input.xlsx, data_only=True)",
                        "approach": "Extracts surviving sheet XML cells, formulas, and dimensions into a clean workbook."
                    },
                    {
                        "tool": "7-Zip / Deflate Salvager",
                        "command": "7z t -tzip input.xlsx ; fix_deflate input.xlsx",
                        "approach": "Repairs broken ZIP compression streams and restores sheet relationship tables."
                    }
                ]
            elif any(k in detected_category for k in ["PPT", "POWERPOINT"]):
                strategy_tools = [
                    {
                        "tool": "python-pptx Presentation Carver",
                        "command": "python-pptx.Presentation(input.pptx)",
                        "approach": "Rebuilds slide layout trees, master relationships, and salvages shape components."
                    },
                    {
                        "tool": "OpenXML Slide Reconstructor",
                        "command": "zipfile.ZipFile / lxml (Slide Relationship Rebuilder)",
                        "approach": "Restores presentation.xml, repairs _rels mappings, and re-indexes slide objects."
                    }
                ]
            elif any(k in detected_category for k in ["IMAGE", "JPG", "JPEG", "PNG", "WEBP"]):
                strategy_tools = [
                    {
                        "tool": "Pillow / ImageMagick",
                        "command": "magick identify -verbose input.jpg ; magick input.jpg -auto-orient recovered.jpg",
                        "approach": "Restores missing SOI/EOI magic markers and rebuilds damaged color channel tables."
                    },
                    {
                        "tool": "jpegtran / pngcheck",
                        "command": "jpegtran -copy none -optimize input.jpg recovered.jpg",
                        "approach": "Re-encodes surviving DCT coefficients and repairs corrupted Huffman scanlines."
                    }
                ]
            else:
                strategy_tools = [
                    {
                        "tool": "ftfy / iconv Normalizer",
                        "command": "iconv -f utf-8 -t utf-8 -c input.txt recovered.txt",
                        "approach": "Normalizes multi-byte encodings and strips corrupted ASCII / BOM sequences."
                    },
                    {
                        "tool": "json_repair",
                        "command": "json_repair.repair_json(raw_input_text)",
                        "approach": "Balances unclosed quotes and brackets, removes trailing commas, and realigns syntax."
                    }
                ]

        from services.corruption_classifier import CorruptionClassifier
        classif_obj = CorruptionClassifier.classify(file_path, detected_category)
        corr_area = CorruptionClassifier.get_corruption_area(file_path, detected_category, analysis=analysis_raw, original_filename=file_name)
        
        # Synchronize structure_matrix with classification regions so both share 1:1 ground truth
        struct_matrix = dict(analysis_raw.get("structure_matrix", {}))
        for r_key, r_info in classif_obj.get("regions", {}).items():
            st = "CORRUPTED" if r_info.get("is_corrupted") or r_info.get("status") == "CORRUPTED" else "INTACT"
            defect_msg = (r_info.get("defects") or ["Region syntax & structure valid."])[0] if st == "CORRUPTED" else "Region syntax & structure valid."
            if r_key in ["image", "images"]:
                struct_matrix["images"] = {"status": st, "reason": defect_msg}
                struct_matrix["image"] = {"status": st, "reason": defect_msg}
            elif r_key not in struct_matrix:
                struct_matrix[r_key] = {"status": st, "reason": defect_msg}

        analysis_raw["structure_matrix"] = struct_matrix
        analysis_raw["corruption_classification"] = classif_obj
        analysis_raw["corruption_area"] = corr_area
        analysis_raw["regions"] = classif_obj.get("regions", {})

        return {
            "file_id": fid,
            "filename": file_name,
            "extension": ext,
            "detected_type": detected_category,
            "file_type": detected_category,
            "mime_type": detected_mime or "application/octet-stream",
            "size": size_bytes,
            "size_human": format_size(size_bytes),
            "is_corrupted": is_corrupted or classif_obj.get("is_corrupted", False),
            "can_recover": analysis_raw.get("can_recover", True),
            "structure_matrix": struct_matrix,
            "diagnosis": analysis_raw.get("diagnosis", analysis_raw.get("summary", "Analysis completed.")),
            "integrity": {
                "status": integrity_status,
                "score": score,
                "is_intact": not is_corrupted
            },
            "corruption": corruption_dict,
            "corruption_area": corr_area,
            "corruption_classification": classif_obj,
            "regions": classif_obj.get("regions", {}),
            "corruption_regions": regions,
            "errors": errors,
            "recoverability": recoverability,
            "classification": classification if isinstance(classification, list) else [classification],
            "recommended_tools": recommended_tools,
            "strategy_tools": strategy_tools,
            "recommended_strategies": strategy_tools,
            "available_tools": ToolManager.get_available_tool_names(),
            "summary": analysis_raw.get("summary", "Analysis completed."),
            "raw_analysis": analysis_raw
        }

    @classmethod
    def _analyze_generic_text_or_binary(cls, file_path: str, raw_head: bytes, ext: str) -> Dict[str, Any]:
        # Check if CSV, JSON, or Plain Text
        is_corrupted = False
        regions = []

        if ext == ".csv":
            return {
                "file_type": "CSV",
                "is_corrupted": False,
                "corruption_regions": [{"region": "body", "status": "valid", "name": "CSV Stream"}],
                "can_recover": True,
                "summary": "CSV document analyzed."
            }
        elif ext == ".json":
            import json
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    json.load(f)
                return {
                    "file_type": "JSON",
                    "is_corrupted": False,
                    "corruption_regions": [{"region": "body", "status": "valid", "name": "JSON Stream"}],
                    "can_recover": True,
                    "summary": "Valid JSON Document."
                }
            except Exception as e:
                return {
                    "file_type": "JSON",
                    "is_corrupted": True,
                    "corruption_regions": [{"region": "body", "status": "corrupted", "name": "JSON Syntax", "reason": str(e)}],
                    "can_recover": True,
                    "summary": "JSON syntax error detected."
                }

        # Test ASCII/UTF-8 decode
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                f.read(4096)
            return {
                "file_type": "TEXT",
                "is_corrupted": False,
                "corruption_regions": [{"region": "encoding", "status": "valid", "name": "UTF-8 Encoding"}],
                "can_recover": True,
                "summary": "Valid Plain Text Document."
            }
        except Exception as e:
            return {
                "file_type": "TEXT",
                "is_corrupted": True,
                "corruption_regions": [{"region": "encoding", "status": "corrupted", "name": "Encoding Stream", "reason": "Non-UTF8 or malformed characters"}],
                "can_recover": True,
                "summary": "Encoding errors detected."
            }
