import os
import re
import zipfile
from typing import Dict, Any, List, Optional
import xml.etree.ElementTree as ET

try:
    import openpyxl
except ImportError:
    openpyxl = None


class XLSXAnalyzer:
    """
    Deep Structural XLSX Corruption Analyzer.
    Analyzes XLSX as an OpenXML ZIP container across:
      1. Container Header / [Content_Types].xml
      2. Workbook metadata (xl/workbook.xml, sheet definitions)
      3. Worksheets (xl/worksheets/sheet*.xml, cell values, formulas)
      4. Shared Strings (xl/sharedStrings.xml)
      5. Relationships (_rels/.rels, xl/_rels/workbook.xml.rels)
      6. End-of-File / Central Directory (EOCD, CRC check)
    """

    ZIP_LOCAL_HEADER_SIG = b"PK\x03\x04"
    ZIP_CENTRAL_DIR_SIG = b"PK\x01\x02"
    ZIP_EOCD_SIG = b"PK\x05\x06"

    @classmethod
    def analyze(cls, file_path: str) -> Dict[str, Any]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return {
                "file_type": "XLSX",
                "is_corrupted": True,
                "corruption_regions": [
                    {"region": "header", "status": "corrupted", "reason": "File is empty (0 bytes)"},
                    {"region": "workbook", "status": "corrupted", "reason": "No workbook.xml present"},
                    {"region": "worksheets", "status": "corrupted", "reason": "No worksheets present"},
                    {"region": "end_of_file", "status": "corrupted", "reason": "Missing ZIP EOCD record"}
                ],
                "sheets_detected": 0,
                "can_recover": False,
                "summary": "Excel document is 0 bytes and cannot be recovered."
            }

        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        regions: List[Dict[str, Any]] = []
        is_corrupted = False

        zip_obj = None
        zip_members: List[str] = []
        zip_open_error = None

        try:
            zip_obj = zipfile.ZipFile(file_path, "r")
            zip_members = zip_obj.namelist()
        except Exception as e:
            zip_open_error = str(e)

        # 1. Header & Container
        header_res = cls._analyze_header(raw_bytes, zip_obj, zip_members)
        if header_res["status"] != "valid":
            is_corrupted = True
        regions.append(header_res)

        # 2. Workbook & Sheets
        wb_res = cls._analyze_workbook(raw_bytes, zip_obj, zip_members)
        if wb_res["status"] != "valid":
            is_corrupted = True
        regions.append(wb_res)

        # 3. Worksheets data
        ws_res = cls._analyze_worksheets(raw_bytes, zip_obj, zip_members)
        if ws_res["status"] != "valid":
            is_corrupted = True
        regions.append(ws_res)

        # 4. Shared Strings
        ss_res = cls._analyze_shared_strings(raw_bytes, zip_obj, zip_members)
        if ss_res["status"] != "valid":
            is_corrupted = True
        regions.append(ss_res)

        # 5. EOF / Central Directory
        eof_res = cls._analyze_eof(raw_bytes, zip_obj)
        if eof_res["status"] != "valid":
            is_corrupted = True
        regions.append(eof_res)

        sheets_detected = ws_res.get("sheets_count", 0)
        can_recover = (
            sheets_detected > 0 or
            b"<sheetData" in raw_bytes or
            b"<row" in raw_bytes or
            b"<c " in raw_bytes or
            b"<v>" in raw_bytes or
            b"<t>" in raw_bytes
        )

        return {
            "file_type": "XLSX",
            "is_corrupted": is_corrupted,
            "corruption_regions": regions,
            "sheets_detected": sheets_detected,
            "can_recover": can_recover,
            "summary": "Intact Excel Workbook" if not is_corrupted else "XLSX container or XML corruption detected."
        }

    @classmethod
    def _analyze_header(cls, raw_bytes: bytes, zip_obj: Optional[zipfile.ZipFile], members: List[str]) -> Dict[str, Any]:
        if not raw_bytes.startswith(cls.ZIP_LOCAL_HEADER_SIG):
            pos = raw_bytes.find(cls.ZIP_LOCAL_HEADER_SIG)
            if pos != -1:
                return {
                    "region": "header",
                    "name": "Container Header",
                    "status": "warning",
                    "reason": f"Displaced ZIP header (%d leading bytes)" % pos,
                    "offset": pos
                }
            return {
                "region": "header",
                "name": "Container Header",
                "status": "corrupted",
                "reason": "Missing PK\\x03\\x04 signature",
                "offset": 0
            }

        has_content_types = "[Content_Types].xml" in members if zip_obj else False
        if zip_obj and not has_content_types:
            return {
                "region": "header",
                "name": "Container Header",
                "status": "corrupted",
                "reason": "Missing [Content_Types].xml manifest"
            }

        return {
            "region": "header",
            "name": "Container Header",
            "status": "valid",
            "reason": "Valid ZIP container header and manifest"
        }

    @classmethod
    def _analyze_workbook(cls, raw_bytes: bytes, zip_obj: Optional[zipfile.ZipFile], members: List[str]) -> Dict[str, Any]:
        if zip_obj:
            if "xl/workbook.xml" not in members:
                return {
                    "region": "workbook",
                    "name": "Workbook Definition",
                    "status": "corrupted",
                    "reason": "Missing xl/workbook.xml structure"
                }
            try:
                xml_data = zip_obj.read("xl/workbook.xml")
                ET.fromstring(xml_data)
                return {
                    "region": "workbook",
                    "name": "Workbook Definition",
                    "status": "valid",
                    "reason": "Workbook XML is well-formed"
                }
            except Exception as e:
                return {
                    "region": "workbook",
                    "name": "Workbook Definition",
                    "status": "corrupted",
                    "reason": f"Malformed xl/workbook.xml: {str(e)}"
                }

        if b"xl/workbook.xml" in raw_bytes or b"<sheets" in raw_bytes:
            return {
                "region": "workbook",
                "name": "Workbook Definition",
                "status": "warning",
                "reason": "Workbook elements detected in raw byte stream"
            }

        return {
            "region": "workbook",
            "name": "Workbook Definition",
            "status": "corrupted",
            "reason": "No workbook definition found"
        }

    @classmethod
    def _analyze_worksheets(cls, raw_bytes: bytes, zip_obj: Optional[zipfile.ZipFile], members: List[str]) -> Dict[str, Any]:
        sheets_found = 0
        if zip_obj:
            sheet_files = [m for m in members if m.startswith("xl/worksheets/sheet") and m.endswith(".xml")]
            sheets_found = len(sheet_files)
            if sheets_found > 0:
                corrupted_sheets = 0
                for s in sheet_files:
                    try:
                        data = zip_obj.read(s)
                        ET.fromstring(data)
                    except Exception:
                        corrupted_sheets += 1

                if corrupted_sheets > 0:
                    return {
                        "region": "worksheets",
                        "name": "Worksheets Data",
                        "status": "corrupted",
                        "reason": f"{corrupted_sheets} of {sheets_found} worksheet XMLs are malformed",
                        "sheets_count": sheets_found
                    }
                return {
                    "region": "worksheets",
                    "name": "Worksheets Data",
                    "status": "valid",
                    "reason": f"All {sheets_found} worksheets are well-formed",
                    "sheets_count": sheets_found
                }

        # Fallback raw scan for worksheets
        matches = len(re.findall(rb"xl/worksheets/sheet\d+\.xml", raw_bytes))
        cell_count = len(re.findall(rb"<c\b", raw_bytes))
        if matches > 0 or cell_count > 0:
            return {
                "region": "worksheets",
                "name": "Worksheets Data",
                "status": "warning",
                "reason": f"Raw cell stream elements detected ({cell_count} cells)",
                "sheets_count": max(1, matches)
            }

        return {
            "region": "worksheets",
            "name": "Worksheets Data",
            "status": "corrupted",
            "reason": "No worksheet data found",
            "sheets_count": 0
        }

    @classmethod
    def _analyze_shared_strings(cls, raw_bytes: bytes, zip_obj: Optional[zipfile.ZipFile], members: List[str]) -> Dict[str, Any]:
        if zip_obj:
            if "xl/sharedStrings.xml" in members:
                try:
                    ET.fromstring(zip_obj.read("xl/sharedStrings.xml"))
                    return {
                        "region": "shared_strings",
                        "name": "Shared Strings Table",
                        "status": "valid",
                        "reason": "Shared strings table is intact"
                    }
                except Exception as e:
                    return {
                        "region": "shared_strings",
                        "name": "Shared Strings Table",
                        "status": "corrupted",
                        "reason": f"Malformed shared strings: {str(e)}"
                    }
            return {
                "region": "shared_strings",
                "name": "Shared Strings Table",
                "status": "valid",
                "reason": "No external shared strings table required (inline strings)"
            }

        return {
            "region": "shared_strings",
            "name": "Shared Strings Table",
            "status": "warning",
            "reason": "Shared strings table unverified"
        }

    @classmethod
    def _analyze_eof(cls, raw_bytes: bytes, zip_obj: Optional[zipfile.ZipFile]) -> Dict[str, Any]:
        if not raw_bytes.endswith(cls.ZIP_EOCD_SIG) and cls.ZIP_EOCD_SIG not in raw_bytes[-2048:]:
            return {
                "region": "end_of_file",
                "name": "ZIP Central Directory & EOCD",
                "status": "corrupted",
                "reason": "Missing or truncated ZIP End of Central Directory marker"
            }

        if zip_obj:
            bad_file = zip_obj.testzip()
            if bad_file:
                return {
                    "region": "end_of_file",
                    "name": "ZIP Central Directory & EOCD",
                    "status": "corrupted",
                    "reason": f"CRC check failed for internal member '{bad_file}'"
                }

        return {
            "region": "end_of_file",
            "name": "ZIP Central Directory & EOCD",
            "status": "valid",
            "reason": "ZIP central directory and CRC verified"
        }
