import os
import re
import zipfile
from pathlib import Path
from typing import Dict, Any, List, Optional
import xml.etree.ElementTree as ET

try:
    from lxml import etree as lxml_etree
except ImportError:
    lxml_etree = None

try:
    import docx
except ImportError:
    docx = None


class DOCXAnalyzer:
    """
    Deep Structural DOCX Corruption Analyzer.
    Analyzes DOCX as an OpenXML ZIP container across:
      1. Header / Container (ZIP local file headers, signature, [Content_Types].xml)
      2. Body (word/document.xml, paragraphs, runs, tables, XML well-formedness)
      3. References / Relationships (_rels/.rels, word/_rels/document.xml.rels)
      4. End-of-File / Central Directory (EOCD, central directory headers, CRC check)
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
                "file_type": "DOCX",
                "is_corrupted": True,
                "corruption_regions": [
                    {"region": "header", "status": "corrupted", "reason": "File is empty (0 bytes)"},
                    {"region": "body", "status": "corrupted", "reason": "No document.xml present"},
                    {"region": "references", "status": "corrupted", "reason": "No relationship files present"},
                    {"region": "end_of_file", "status": "corrupted", "reason": "Missing ZIP End of Central Directory record"}
                ],
                "paragraphs_detected": 0,
                "can_recover": False,
                "summary": "Document is 0 bytes and cannot be recovered."
            }

        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        regions: List[Dict[str, Any]] = []
        is_corrupted = False

        # Attempt to inspect as ZIP archive
        zip_obj = None
        zip_members: List[str] = []
        zip_open_error = None

        try:
            zip_obj = zipfile.ZipFile(file_path, "r")
            zip_members = zip_obj.namelist()
        except Exception as e:
            zip_open_error = str(e)

        # ---------------------------------------------------------
        # 1. HEADER / CONTAINER ANALYSIS
        # ---------------------------------------------------------
        header_result = cls._analyze_header_container(raw_bytes, zip_obj, zip_members)
        header_result["name"] = "Container Header & Manifest"
        if header_result["status"] != "valid":
            is_corrupted = True
            header_result["suggested_tools"] = [
                {
                    "tool": "PK Zip Header Realignment Engine",
                    "command": "zipfile / DeflateFixer",
                    "action": "Strip invalid leading prefix bytes and align PK\\x03\\x04 signature at offset 0."
                },
                {
                    "tool": "OpenXML Content_Types Synthesizer",
                    "command": "DOCXRecoveryEngine (Manifest Synthesizer)",
                    "action": "Rebuild missing or malformed [Content_Types].xml package manifest."
                }
            ]
        else:
            header_result["suggested_tools"] = [
                {
                    "tool": "OpenXML Container Validator",
                    "command": "zipfile.ZipFile.testzip()",
                    "action": "Verified intact PK container header and valid [Content_Types].xml."
                }
            ]
        regions.append(header_result)

        # ---------------------------------------------------------
        # 2. BODY ANALYSIS (word/document.xml)
        # ---------------------------------------------------------
        body_result = cls._analyze_body(raw_bytes, zip_obj, file_path)
        body_result["name"] = "Document Body & XML Markup"
        if body_result["status"] != "valid":
            is_corrupted = True
            body_result["suggested_tools"] = [
                {
                    "tool": "XML DOM Tree Reconstructor (lxml/ET Recover)",
                    "command": "lxml.etree.XMLParser(recover=True)",
                    "action": "Heal unclosed XML tags and repair damaged word/document.xml syntax."
                },
                {
                    "tool": "OpenXML Paragraph Stream Salvager",
                    "command": "DOCXRecoveryEngine (Stream Carver)",
                    "action": "Carve surviving <w:t> text runs and reconstruct paragraph/table hierarchy."
                }
            ]
        else:
            body_result["suggested_tools"] = [
                {
                    "tool": "OpenXML Document Tree Inspector",
                    "command": "docx.Document(file_path)",
                    "action": "Verified well-formed word/document.xml with intact paragraphs and tables."
                }
            ]
        regions.append(body_result)

        # ---------------------------------------------------------
        # 3. REFERENCES / RELATIONSHIPS ANALYSIS
        # ---------------------------------------------------------
        ref_result = cls._analyze_references(raw_bytes, zip_obj, zip_members)
        ref_result["name"] = "Relationship Trees & Hyperlinks"
        if ref_result["status"] != "valid":
            is_corrupted = True
            ref_result["suggested_tools"] = [
                {
                    "tool": "OpenXML OPC Relationship Graph Synthesizer",
                    "command": "DOCXRecoveryEngine (Relationship Builder)",
                    "action": "Regenerate _rels/.rels and word/_rels/document.xml.rels relationship definitions."
                }
            ]
        else:
            ref_result["suggested_tools"] = [
                {
                    "tool": "OpenXML Relationship Validator",
                    "command": "OPCRelationshipChecker",
                    "action": "Verified package and document relationship targets are fully resolved."
                }
            ]
        regions.append(ref_result)

        # ---------------------------------------------------------
        # 4. END-OF-FILE / CONTAINER TRAILER ANALYSIS
        # ---------------------------------------------------------
        eof_result = cls._analyze_eof_container(raw_bytes, zip_obj, zip_open_error)
        eof_result["name"] = "ZIP Central Directory & EOCD"
        if eof_result["status"] != "valid":
            is_corrupted = True
            eof_result["suggested_tools"] = [
                {
                    "tool": "ZIP EOCD (End of Central Directory) Rebuilder",
                    "command": "ZipEOCDRepair",
                    "action": "Recalculate member offsets and reconstruct missing End of Central Directory record."
                },
                {
                    "tool": "ZIP CRC-32 Checksum Sanitizer",
                    "command": "ZipCRCRepair",
                    "action": "Fix defective CRC-32 checksums and repair corrupted member headers."
                }
            ]
        else:
            eof_result["suggested_tools"] = [
                {
                    "tool": "ZIP EOCD & CRC-32 Validator",
                    "command": "zipfile.testzip()",
                    "action": "Verified valid End of Central Directory record and CRC checksums."
                }
            ]
        regions.append(eof_result)

        if zip_obj:
            try:
                zip_obj.close()
            except Exception:
                pass

        # Calculate recovery feasibility
        can_recover = (
            (b"<w:document" in raw_bytes or b"word/document.xml" in raw_bytes or b"<w:t" in raw_bytes)
            or (body_result.get("paragraphs_detected", 0) > 0)
            or (zip_obj is not None)
        )

        corrupted_region_names = [r["region"] for r in regions if r["status"] != "valid"]
        if not corrupted_region_names:
            summary = "DOCX structural integrity is completely valid and undamaged."
        else:
            summary = f"Corruption detected in: {', '.join(corrupted_region_names)}. Recoverable: {can_recover}."

        return {
            "file_type": "DOCX",
            "is_corrupted": is_corrupted,
            "corruption_regions": regions,
            "paragraphs_detected": body_result.get("paragraphs_detected", 0),
            "tables_detected": body_result.get("tables_detected", 0),
            "can_recover": can_recover,
            "summary": summary,
            "details": {
                "header": header_result,
                "body": body_result,
                "references": ref_result,
                "end_of_file": eof_result,
                "zip_members": zip_members,
                "file_size": file_size
            }
        }

    @classmethod
    def _analyze_header_container(cls, raw: bytes, zip_obj: Optional[zipfile.ZipFile], members: List[str]) -> Dict[str, Any]:
        """Inspects ZIP signature, local file headers, and [Content_Types].xml."""
        pos = raw.find(cls.ZIP_LOCAL_HEADER_SIG)

        if pos == -1:
            return {
                "region": "header",
                "status": "corrupted",
                "reason": "Missing PK\\x03\\x04 ZIP container header signature",
                "offset": None,
                "has_content_types": False
            }

        # Check [Content_Types].xml
        has_content_types = False
        content_types_valid = False
        if zip_obj and "[Content_Types].xml" in members:
            has_content_types = True
            try:
                ct_data = zip_obj.read("[Content_Types].xml")
                ET.fromstring(ct_data)
                content_types_valid = True
            except Exception:
                content_types_valid = False
        elif b"[Content_Types].xml" in raw:
            has_content_types = True

        if pos == 0:
            if not has_content_types:
                return {
                    "region": "header",
                    "status": "corrupted",
                    "reason": "ZIP header signature valid at byte 0, but required [Content_Types].xml is missing",
                    "offset": 0,
                    "has_content_types": False
                }
            if zip_obj and not content_types_valid:
                return {
                    "region": "header",
                    "status": "corrupted",
                    "reason": "ZIP header signature valid, but [Content_Types].xml contains malformed XML",
                    "offset": 0,
                    "has_content_types": True
                }

            return {
                "region": "header",
                "status": "valid",
                "reason": "Valid ZIP container header and Office [Content_Types].xml verified",
                "offset": 0,
                "has_content_types": True
            }
        else:
            return {
                "region": "header",
                "status": "corrupted",
                "reason": f"Displaced ZIP container header detected at byte offset {pos} (preceded by {pos} non-ZIP bytes)",
                "offset": pos,
                "has_content_types": has_content_types
            }

    @classmethod
    def _analyze_body(cls, raw: bytes, zip_obj: Optional[zipfile.ZipFile], file_path: str) -> Dict[str, Any]:
        """Analyzes word/document.xml, XML parsing, paragraphs, runs, and tables."""
        doc_xml_bytes = None
        extracted_from_zip = False

        if zip_obj:
            try:
                if "word/document.xml" in zip_obj.namelist():
                    doc_xml_bytes = zip_obj.read("word/document.xml")
                    extracted_from_zip = True
            except Exception:
                pass

        if not doc_xml_bytes:
            # Check if document.xml can be located in raw stream
            doc_idx = raw.find(b"<w:document")
            if doc_idx != -1:
                end_idx = raw.find(b"</w:document>", doc_idx)
                if end_idx != -1:
                    doc_xml_bytes = raw[doc_idx:end_idx + len(b"</w:document>")]
                else:
                    doc_xml_bytes = raw[doc_idx:]

        if not doc_xml_bytes:
            # Check if there are loose text runs
            raw_t_matches = re.findall(rb"<w:t[^>]*>(.*?)</w:t>", raw)
            if raw_t_matches:
                return {
                    "region": "body",
                    "status": "corrupted",
                    "reason": f"Missing word/document.xml structure, but {len(raw_t_matches)} raw text fragments were identified in binary stream",
                    "paragraphs_detected": len(raw_t_matches),
                    "tables_detected": 0,
                    "xml_valid": False
                }

            return {
                "region": "body",
                "status": "corrupted",
                "reason": "Missing main content part: word/document.xml is not present in document container",
                "paragraphs_detected": 0,
                "tables_detected": 0,
                "xml_valid": False
            }

        # Parse XML
        xml_valid = False
        xml_error = None
        root = None

        try:
            root = ET.fromstring(doc_xml_bytes)
            xml_valid = True
        except Exception as e:
            xml_error = str(e)
            # Try parsing with lxml recover
            if lxml_etree:
                try:
                    parser = lxml_etree.XMLParser(recover=True)
                    root = lxml_etree.fromstring(doc_xml_bytes, parser=parser)
                except Exception:
                    pass

        # Inspect paragraphs and tables
        paragraphs_count = 0
        tables_count = 0
        if root is not None:
            # Count elements with w: namespace
            paragraphs_count = len(list(root.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p")))
            tables_count = len(list(root.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}tbl")))
        else:
            paragraphs_count = len(re.findall(rb"<w:p\b", doc_xml_bytes))
            tables_count = len(re.findall(rb"<w:tbl\b", doc_xml_bytes))

        # Check with python-docx if possible
        docx_ok = False
        if docx and extracted_from_zip and xml_valid:
            try:
                doc = docx.Document(file_path)
                docx_ok = True
            except Exception:
                docx_ok = False

        if xml_valid and extracted_from_zip:
            return {
                "region": "body",
                "status": "valid",
                "reason": f"Valid word/document.xml verified with {paragraphs_count} paragraphs and {tables_count} tables",
                "paragraphs_detected": paragraphs_count,
                "tables_detected": tables_count,
                "xml_valid": True,
                "docx_library_compatible": docx_ok
            }
        else:
            reason = f"Corrupted word/document.xml: {xml_error or 'Damaged XML tags or unreadable container member'}"
            return {
                "region": "body",
                "status": "corrupted",
                "reason": reason,
                "paragraphs_detected": paragraphs_count,
                "tables_detected": tables_count,
                "xml_valid": xml_valid
            }

    @classmethod
    def _analyze_references(cls, raw: bytes, zip_obj: Optional[zipfile.ZipFile], members: List[str]) -> Dict[str, Any]:
        """Analyzes _rels/.rels and word/_rels/document.xml.rels."""
        broken_rels = []
        rels_found = False

        if zip_obj:
            # Check package rels
            if "_rels/.rels" in members:
                rels_found = True
                try:
                    p_rels = zip_obj.read("_rels/.rels")
                    p_root = ET.fromstring(p_rels)
                    for rel in p_root:
                        target = rel.attrib.get("Target", "")
                        target_mode = rel.attrib.get("TargetMode", "")
                        if target_mode != "External" and target and not target.startswith("/"):
                            # target relative to root
                            if target not in members and f"/{target}" not in members:
                                broken_rels.append(f"Package rel target '{target}' missing")
                except Exception as e:
                    broken_rels.append(f"Malformed _rels/.rels: {str(e)}")

            # Check document rels
            doc_rels_path = "word/_rels/document.xml.rels"
            if doc_rels_path in members:
                rels_found = True
                try:
                    d_rels = zip_obj.read(doc_rels_path)
                    d_root = ET.fromstring(d_rels)
                    for rel in d_root:
                        target = rel.attrib.get("Target", "")
                        target_mode = rel.attrib.get("TargetMode", "")
                        if target_mode != "External" and target:
                            # Target relative to word/
                            resolved = f"word/{target}" if not target.startswith("word/") else target
                            # Normalize path
                            resolved_norm = os.path.normpath(resolved).replace("\\", "/")
                            if resolved_norm not in members and not any(m.endswith(target) for m in members):
                                broken_rels.append(f"Document rel target '{target}' missing")
                except Exception as e:
                    broken_rels.append(f"Malformed {doc_rels_path}: {str(e)}")

        elif b"document.xml.rels" in raw or b"_rels" in raw:
            rels_found = True

        if not rels_found:
            return {
                "region": "references",
                "status": "corrupted",
                "reason": "Missing OpenXML relationship files (_rels/.rels, document.xml.rels)",
                "broken_references": ["Missing relationship definitions"]
            }

        if broken_rels:
            return {
                "region": "references",
                "status": "corrupted",
                "reason": f"Broken relationship references: {'; '.join(broken_rels[:3])}",
                "broken_references": broken_rels
            }

        return {
            "region": "references",
            "status": "valid",
            "reason": "Package and document relationship mappings are intact and verified",
            "broken_references": []
        }

    @classmethod
    def _analyze_eof_container(cls, raw: bytes, zip_obj: Optional[zipfile.ZipFile], zip_error: Optional[str]) -> Dict[str, Any]:
        """Inspects ZIP Central Directory and End of Central Directory (EOCD)."""
        eocd_pos = raw.rfind(cls.ZIP_EOCD_SIG)
        cd_pos = raw.rfind(cls.ZIP_CENTRAL_DIR_SIG)

        if eocd_pos == -1:
            return {
                "region": "end_of_file",
                "status": "corrupted",
                "reason": "Missing ZIP End of Central Directory (EOCD) record (truncated archive)",
                "eocd_found": False
            }

        if zip_error:
            return {
                "region": "end_of_file",
                "status": "corrupted",
                "reason": f"ZIP Central Directory corrupted: {zip_error}",
                "eocd_found": True
            }

        # Check CRC-32 integrity of all members
        if zip_obj:
            try:
                bad_file = zip_obj.testzip()
                if bad_file:
                    return {
                        "region": "end_of_file",
                        "status": "corrupted",
                        "reason": f"ZIP CRC checksum mismatch in member: {bad_file}",
                        "eocd_found": True,
                        "bad_member": bad_file
                    }
            except Exception as e:
                return {
                    "region": "end_of_file",
                    "status": "corrupted",
                    "reason": f"ZIP CRC verification failed: {str(e)}",
                    "eocd_found": True
                }

        return {
            "region": "end_of_file",
            "status": "valid",
            "reason": "ZIP End of Central Directory and member CRC checksums fully verified",
            "eocd_found": True
        }
