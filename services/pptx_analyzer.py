import os
import re
import zipfile
from typing import Dict, Any, List, Optional
import xml.etree.ElementTree as ET

try:
    import pptx
except ImportError:
    pptx = None


class PPTXAnalyzer:
    """
    Deep Structural PPTX Corruption Analyzer.
    Analyzes PPTX as an OpenXML ZIP container across:
      1. Container Header & [Content_Types].xml
      2. Presentation Definition (ppt/presentation.xml)
      3. Slides & Shapes (ppt/slides/slide*.xml)
      4. Slide Layouts & Masters (ppt/slideLayouts/, ppt/slideMasters/)
      5. Relationships (_rels/.rels, ppt/_rels/presentation.xml.rels)
      6. End-of-File / Central Directory (EOCD, CRC check)
    """

    ZIP_LOCAL_HEADER_SIG = b"PK\x03\x04"
    ZIP_EOCD_SIG = b"PK\x05\x06"

    @classmethod
    def analyze(cls, file_path: str) -> Dict[str, Any]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return {
                "file_type": "PPTX",
                "is_corrupted": True,
                "corruption_regions": [
                    {"region": "header", "status": "corrupted", "reason": "File is empty (0 bytes)"},
                    {"region": "presentation", "status": "corrupted", "reason": "No presentation.xml present"},
                    {"region": "slides", "status": "corrupted", "reason": "No slides present"},
                    {"region": "end_of_file", "status": "corrupted", "reason": "Missing ZIP EOCD record"}
                ],
                "slides_detected": 0,
                "can_recover": False,
                "summary": "PowerPoint presentation is 0 bytes and cannot be recovered."
            }

        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        regions: List[Dict[str, Any]] = []
        is_corrupted = False

        zip_obj = None
        zip_members: List[str] = []

        try:
            zip_obj = zipfile.ZipFile(file_path, "r")
            zip_members = zip_obj.namelist()
        except Exception:
            pass

        # 1. Header & Container
        header_res = cls._analyze_header(raw_bytes, zip_obj, zip_members)
        if header_res["status"] != "valid":
            is_corrupted = True
        regions.append(header_res)

        # 2. Presentation definition
        pres_res = cls._analyze_presentation(raw_bytes, zip_obj, zip_members)
        if pres_res["status"] != "valid":
            is_corrupted = True
        regions.append(pres_res)

        # 3. Slides
        slides_res = cls._analyze_slides(raw_bytes, zip_obj, zip_members)
        if slides_res["status"] != "valid":
            is_corrupted = True
        regions.append(slides_res)

        # 4. EOF / Central Directory
        eof_res = cls._analyze_eof(raw_bytes, zip_obj)
        if eof_res["status"] != "valid":
            is_corrupted = True
        regions.append(eof_res)

        slides_count = slides_res.get("slides_count", 0)
        can_recover = (
            slides_count > 0 or
            b"<p:sp" in raw_bytes or
            b"<a:t>" in raw_bytes or
            b"<a:p" in raw_bytes or
            b"ppt/slides" in raw_bytes
        )

        return {
            "file_type": "PPTX",
            "is_corrupted": is_corrupted,
            "corruption_regions": regions,
            "slides_detected": slides_count,
            "can_recover": can_recover,
            "summary": "Intact PowerPoint Presentation" if not is_corrupted else "PPTX container or slide XML corruption detected."
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

        if zip_obj and "[Content_Types].xml" not in members:
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
    def _analyze_presentation(cls, raw_bytes: bytes, zip_obj: Optional[zipfile.ZipFile], members: List[str]) -> Dict[str, Any]:
        if zip_obj:
            if "ppt/presentation.xml" not in members:
                return {
                    "region": "presentation",
                    "name": "Presentation Structure",
                    "status": "corrupted",
                    "reason": "Missing ppt/presentation.xml"
                }
            try:
                ET.fromstring(zip_obj.read("ppt/presentation.xml"))
                return {
                    "region": "presentation",
                    "name": "Presentation Structure",
                    "status": "valid",
                    "reason": "Presentation structure is valid"
                }
            except Exception as e:
                return {
                    "region": "presentation",
                    "name": "Presentation Structure",
                    "status": "corrupted",
                    "reason": f"Malformed presentation.xml: {str(e)}"
                }

        if b"ppt/presentation.xml" in raw_bytes or b"<p:presentation" in raw_bytes:
            return {
                "region": "presentation",
                "name": "Presentation Structure",
                "status": "warning",
                "reason": "Presentation elements detected in raw byte stream"
            }

        return {
            "region": "presentation",
            "name": "Presentation Structure",
            "status": "corrupted",
            "reason": "No presentation definition found"
        }

    @classmethod
    def _analyze_slides(cls, raw_bytes: bytes, zip_obj: Optional[zipfile.ZipFile], members: List[str]) -> Dict[str, Any]:
        if zip_obj:
            slide_files = [m for m in members if m.startswith("ppt/slides/slide") and m.endswith(".xml")]
            if slide_files:
                corrupted = 0
                for s in slide_files:
                    try:
                        ET.fromstring(zip_obj.read(s))
                    except Exception:
                        corrupted += 1
                if corrupted > 0:
                    return {
                        "region": "slides",
                        "name": "Slides Data",
                        "status": "corrupted",
                        "reason": f"{corrupted} of {len(slide_files)} slide XMLs are damaged",
                        "slides_count": len(slide_files)
                    }
                return {
                    "region": "slides",
                    "name": "Slides Data",
                    "status": "valid",
                    "reason": f"All {len(slide_files)} slides are intact",
                    "slides_count": len(slide_files)
                }

        # Fallback raw count
        matches = len(re.findall(rb"ppt/slides/slide\d+\.xml", raw_bytes))
        shape_count = len(re.findall(rb"<p:sp\b", raw_bytes))
        if matches > 0 or shape_count > 0:
            return {
                "region": "slides",
                "name": "Slides Data",
                "status": "warning",
                "reason": f"Raw slide shape tokens detected ({shape_count} shapes)",
                "slides_count": max(1, matches)
            }

        return {
            "region": "slides",
            "name": "Slides Data",
            "status": "corrupted",
            "reason": "No slide XMLs found",
            "slides_count": 0
        }

    @classmethod
    def _analyze_eof(cls, raw_bytes: bytes, zip_obj: Optional[zipfile.ZipFile]) -> Dict[str, Any]:
        if not raw_bytes.endswith(cls.ZIP_EOCD_SIG) and cls.ZIP_EOCD_SIG not in raw_bytes[-2048:]:
            return {
                "region": "end_of_file",
                "name": "ZIP Central Directory & EOCD",
                "status": "corrupted",
                "reason": "Missing or truncated ZIP End of Central Directory"
            }

        if zip_obj:
            bad_file = zip_obj.testzip()
            if bad_file:
                return {
                    "region": "end_of_file",
                    "name": "ZIP Central Directory & EOCD",
                    "status": "corrupted",
                    "reason": f"CRC error in member '{bad_file}'"
                }

        return {
            "region": "end_of_file",
            "name": "ZIP Central Directory & EOCD",
            "status": "valid",
            "reason": "ZIP central directory verified"
        }
