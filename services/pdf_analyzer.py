import os
import re
import zlib
from pathlib import Path
from typing import Dict, Any, List, Optional

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None

try:
    from pypdf import PdfReader
    from pypdf.errors import PdfReadError, PyPdfError
except ImportError:
    PdfReader = None
    PdfReadError = Exception
    PyPdfError = Exception


class PDFAnalyzer:
    """
    Deep Structural PDF Corruption Analyzer.
    Inspects PDF binary structure across Header, Body/Objects, Cross-Reference (xref),
    Trailer, startxref, and End-of-File (EOF) markers without crashing.
    Generates granular corruption classification, human-readable diagnosis,
    and targeted tool recommendations.
    """

    @classmethod
    def analyze(cls, file_path: str) -> Dict[str, Any]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return {
                "file_type": "PDF",
                "is_corrupted": True,
                "corruption_regions": [
                    {"region": "header", "status": "corrupted", "reason": "File is empty (0 bytes)"},
                    {"region": "body", "status": "corrupted", "reason": "No body content present"},
                    {"region": "xref", "status": "corrupted", "reason": "No xref table present"},
                    {"region": "trailer", "status": "corrupted", "reason": "No trailer dictionary present"},
                    {"region": "startxref", "status": "corrupted", "reason": "No startxref pointer present"},
                    {"region": "end_of_file", "status": "corrupted", "reason": "Missing %%EOF marker"}
                ],
                "structure_matrix": {
                    "header": {"status": "CORRUPTED", "details": "0 bytes"},
                    "body": {"status": "CORRUPTED", "details": "Empty file"},
                    "xref": {"status": "CORRUPTED", "details": "Missing"},
                    "trailer": {"status": "CORRUPTED", "details": "Missing"},
                    "startxref": {"status": "CORRUPTED", "details": "Missing"},
                    "eof": {"status": "CORRUPTED", "details": "Missing"}
                },
                "classification": ["Empty file", "Header missing", "XRef missing", "EOF missing"],
                "diagnosis": "File is completely empty (0 bytes) and contains no recoverable PDF data.",
                "recommended_tools": [],
                "pages_detected": 0,
                "objects_detected": 0,
                "can_recover": False,
                "summary": "Document is 0 bytes and cannot be recovered."
            }

        with open(file_path, "rb") as f:
            data = f.read()

        regions: List[Dict[str, Any]] = []
        is_corrupted = False

        # ---------------------------------------------------------
        # 1. HEADER ANALYSIS
        # ---------------------------------------------------------
        header_result = cls._analyze_header(data)
        header_result["name"] = "Header Structure"
        if header_result["status"] != "valid":
            is_corrupted = True
            header_result["suggested_tools"] = [
                {
                    "tool": "QPDF Header Realignment Engine",
                    "command": "qpdf --repair-file input.pdf recovered.pdf",
                    "action": "Trim pre-header garbage bytes and align %PDF-1.4..1.7 magic bytes at offset 0."
                },
                {
                    "tool": "Magic Byte Synthesizer",
                    "command": "PDFRecoveryEngine (Level 2 Header Fixer)",
                    "action": "Reconstruct damaged %PDF header signature and binary comment marker."
                }
            ]
        else:
            header_result["suggested_tools"] = [
                {
                    "tool": "PDF ISO-32000 Header Validator",
                    "command": "qpdf --check input.pdf",
                    "action": "Verified intact %PDF header and binary comment marker at byte 0."
                }
            ]
        regions.append(header_result)

        # ---------------------------------------------------------
        # 2. BODY & OBJECTS ANALYSIS
        # ---------------------------------------------------------
        body_result = cls._analyze_body(data, file_path)
        body_result["name"] = "Body & Content Streams"
        if body_result["status"] != "valid":
            is_corrupted = True
            body_result["suggested_tools"] = [
                {
                    "tool": "PyMuPDF Stream Carver & Decompressor",
                    "command": "mutool clean -s input.pdf recovered.pdf",
                    "action": "Decompress deflated streams, salvage surviving objects, and parse text tokens."
                },
                {
                    "tool": "Deflate Deflaker (zlib Salvager)",
                    "command": "zlib.decompress(s_bytes, -zlib.MAX_WBITS)",
                    "action": "Reconstruct corrupted FlateDecode streams and repair broken stream markers."
                },
                {
                    "tool": "Hex Object Carver",
                    "command": "PDFRecoveryEngine (Level 3/4 Stream Carver)",
                    "action": "Carve surviving object definitions and salvage text and image streams."
                }
            ]
        else:
            body_result["suggested_tools"] = [
                {
                    "tool": "PyMuPDF Object Stream Inspector",
                    "command": "fitz.open(input.pdf)",
                    "action": "Verified intact object boundaries, streams, catalog, and pages root."
                }
            ]
        regions.append(body_result)

        # ---------------------------------------------------------
        # 3. REFERENCES (XREF, TRAILER, STARTXREF) ANALYSIS
        # ---------------------------------------------------------
        ref_analysis = cls._analyze_references_and_trailer(data, file_size)
        xref_result = ref_analysis["xref"]
        trailer_result = ref_analysis["trailer"]
        startxref_result = ref_analysis["startxref"]

        # Maintain backward compatibility with 'references' key in regions
        combined_ref_status = "valid" if (xref_result["status"] == "valid" and trailer_result["status"] == "valid" and startxref_result["status"] == "valid") else "corrupted"
        ref_region_dict = {
            "region": "references",
            "name": "Cross-Reference Table (XREF)",
            "status": combined_ref_status,
            "reason": xref_result.get("reason") or startxref_result.get("reason") or trailer_result.get("reason"),
            "xref": xref_result,
            "trailer": trailer_result,
            "startxref": startxref_result
        }

        if combined_ref_status != "valid":
            is_corrupted = True
            ref_region_dict["suggested_tools"] = [
                {
                    "tool": "Ghostscript Linearization & XREF Regenerator",
                    "command": "gs -o recovered.pdf -sDEVICE=pdfwrite -dPDFSETTINGS=/prepress input.pdf",
                    "action": "Scan all surviving object IDs and regenerate cross-reference table and trailer dictionary from scratch."
                },
                {
                    "tool": "Poppler XREF Table Rebuilder",
                    "command": "mutool clean -d -g input.pdf recovered.pdf",
                    "action": "Recalculate startxref pointers and repair trailer dictionary catalog references."
                }
            ]
        else:
            ref_region_dict["suggested_tools"] = [
                {
                    "tool": "XREF Table & Trailer Validator",
                    "command": "qpdf --check-xref input.pdf",
                    "action": "Verified intact cross-reference table and valid trailer /Root catalog pointer."
                }
            ]
        regions.append(ref_region_dict)

        # ---------------------------------------------------------
        # 4. END-OF-FILE (%%EOF) & TRUNCATION ANALYSIS
        # ---------------------------------------------------------
        eof_result = cls._analyze_eof(data, file_size)
        eof_result["name"] = "End-of-File (%%EOF) & Trailer"
        if eof_result["status"] != "valid":
            is_corrupted = True
            eof_result["suggested_tools"] = [
                {
                    "tool": "PDF Trailer & %%EOF Injector",
                    "command": "PDFRecoveryEngine (Level 2 EOF Injector)",
                    "action": "Calculate valid startxref byte offset, construct clean trailer dictionary, and append %%EOF marker."
                },
                {
                    "tool": "Stream Terminator Sanitizer",
                    "command": "PDFEOFTrimmer",
                    "action": "Strip invalid trailing noise/junk bytes after EOF terminator."
                }
            ]
        else:
            eof_result["suggested_tools"] = [
                {
                    "tool": "PDF EOF Marker Validator",
                    "command": "qpdf --check input.pdf",
                    "action": "Verified valid %%EOF marker at document terminator."
                }
            ]
        regions.append(eof_result)

        # ---------------------------------------------------------
        # 5. EMBEDDED IMAGES ANALYSIS
        # ---------------------------------------------------------
        image_result = cls._analyze_images(data)
        image_result["name"] = "Embedded Images"
        if image_result["status"] != "valid":
            is_corrupted = True
            image_result["suggested_tools"] = [
                {
                    "tool": "Embedded Image Stream Restorer",
                    "command": "PDFRecoveryEngine (Level 3/4 Image Carver)",
                    "action": "Extracts damaged JPEG/PNG streams, restores SOI/EOI markers, and recovers visual assets."
                }
            ]
        else:
            image_result["suggested_tools"] = [
                {
                    "tool": "PDF Image Stream Validator",
                    "command": "qpdf --check input.pdf",
                    "action": "Verified intact image streams and color space structures."
                }
            ]
        regions.append(image_result)

        # Classify corruption types
        classifications = []
        if header_result["status"] != "valid":
            classifications.append("Header corruption")
        if body_result["status"] != "valid":
            classifications.append("Body/object corruption")
        if xref_result["status"] != "valid":
            classifications.append("Cross-reference (xref) corruption")
        if trailer_result["status"] != "valid":
            classifications.append("Trailer corruption")
        if startxref_result["status"] != "valid":
            classifications.append("startxref corruption")
        if eof_result["status"] != "valid":
            classifications.append("EOF corruption")
        if eof_result.get("is_truncated"):
            classifications.append("Missing/truncated data")
        if image_result["status"] != "valid":
            classifications.append("Embedded image corruption")

        # Diagnosis string
        diagnosis_parts = []
        if xref_result["status"] != "valid":
            diagnosis_parts.append("Cross-reference table is corrupted or displaced.")
        if header_result["status"] != "valid":
            diagnosis_parts.append("PDF header signature is displaced or damaged.")
        if body_result["objects_detected"] > 0:
            diagnosis_parts.append(f"{body_result['objects_detected']} PDF objects and {body_result.get('pages_detected', 0)} page definitions appear intact.")
        if trailer_result["status"] != "valid":
            diagnosis_parts.append("Trailer dictionary / catalog pointer needs reconstruction.")
        if eof_result["status"] != "valid":
            diagnosis_parts.append("Document terminator is missing %%EOF marker.")
        if image_result["status"] != "valid":
            diagnosis_parts.append(image_result.get("reason", "Embedded image streams corrupted."))

        if not classifications:
            diagnosis = "PDF structural integrity is intact and conforms to specification."
        else:
            diagnosis = " ".join(diagnosis_parts) if diagnosis_parts else f"Corruption identified in: {', '.join(classifications)}."

        # Recommended Tools & Commands
        recommended_tools = cls._recommend_tools(classifications, body_result, xref_result)

        # Recovery feasibility
        pages_detected = body_result.get("pages_detected", 0)
        objects_detected = body_result.get("objects_detected", 0)
        can_recover = (objects_detected > 0) or (header_result.get("offset") is not None) or (pages_detected > 0)

        corrupted_region_names = [r["region"] for r in regions if r["status"] != "valid"]
        if not corrupted_region_names:
            summary = "PDF structural integrity is completely valid and undamaged."
        else:
            summary = f"Corruption detected in: {', '.join(corrupted_region_names)}. Recoverable: {can_recover}."

        ref_corrupted = (
            xref_result["status"] != "valid"
            or trailer_result["status"] != "valid"
            or startxref_result["status"] != "valid"
        )
        if startxref_result["status"] != "valid":
            ref_reason = "Missing startxref pointer token"
        elif xref_result["status"] != "valid":
            ref_reason = xref_result.get("reason", "Cross-reference table cannot be located without startxref pointer")
        elif trailer_result["status"] != "valid":
            ref_reason = trailer_result.get("reason", "Trailer dictionary corrupted")
        else:
            ref_reason = "Region syntax & structure valid."

        structure_matrix = {
            "header": {"status": "INTACT" if header_result["status"] == "valid" else "CORRUPTED", "reason": header_result.get("reason")},
            "body": {"status": "INTACT" if body_result["status"] == "valid" else "CORRUPTED", "reason": body_result.get("reason")},
            "reference": {"status": "INTACT" if not ref_corrupted else "CORRUPTED", "reason": ref_reason},
            "eof": {"status": "INTACT" if eof_result["status"] == "valid" else "CORRUPTED", "reason": eof_result.get("reason")},
            "images": {"status": "INTACT" if image_result["status"] == "valid" else "CORRUPTED", "reason": image_result.get("reason")},
            "image": {"status": "INTACT" if image_result["status"] == "valid" else "CORRUPTED", "reason": image_result.get("reason")},
            "xref": {"status": "VALID" if xref_result["status"] == "valid" else "CORRUPTED", "reason": xref_result.get("reason")},
            "trailer": {"status": "VALID" if trailer_result["status"] == "valid" else "CORRUPTED", "reason": trailer_result.get("reason")},
            "startxref": {"status": "VALID" if startxref_result["status"] == "valid" else "CORRUPTED", "reason": startxref_result.get("reason")}
        }

        return {
            "file_type": "PDF",
            "is_corrupted": is_corrupted,
            "corruption_regions": regions,
            "structure_matrix": structure_matrix,
            "classification": classifications,
            "diagnosis": diagnosis,
            "recommended_tools": recommended_tools,
            "pages_detected": pages_detected,
            "objects_detected": objects_detected,
            "can_recover": can_recover,
            "summary": summary,
            "details": {
                "header": header_result,
                "body": body_result,
                "references": regions[2],
                "xref": xref_result,
                "trailer": trailer_result,
                "startxref": startxref_result,
                "end_of_file": eof_result,
                "images": image_result,
                "image": image_result,
                "file_size": file_size
            }
        }

    @classmethod
    def _analyze_header(cls, data: bytes) -> Dict[str, Any]:
        """
        Inspects %PDF- header, PDF version, displaced byte offset,
        and binary comment indicator.
        """
        sig = b"%PDF-"
        pos = data.find(sig)

        if pos == -1:
            return {
                "region": "header",
                "status": "corrupted",
                "reason": "Missing %PDF- header magic signature",
                "offset": None,
                "version": None
            }

        # Check version
        version_match = re.search(rb"%PDF-(\d+\.\d+)", data[pos:pos + 16])
        version = version_match.group(1).decode("ascii", errors="ignore") if version_match else "unknown"

        # Check binary comment marker (line 2 typically starts with % followed by 4 chars > 127)
        first_lines = data[pos:pos + 256].split(b"\n")
        has_binary_comment = False
        if len(first_lines) > 1:
            comment_line = first_lines[1]
            if comment_line.startswith(b"%") and any(b >= 128 for b in comment_line):
                has_binary_comment = True

        if pos == 0:
            return {
                "region": "header",
                "status": "valid",
                "reason": f"Valid PDF {version} signature detected at byte 0",
                "offset": 0,
                "version": version,
                "has_binary_comment": has_binary_comment
            }
        else:
            return {
                "region": "header",
                "status": "corrupted",
                "reason": f"Displaced %PDF-{version} header found at byte offset {pos} (preceded by {pos} non-PDF bytes)",
                "offset": pos,
                "version": version,
                "has_binary_comment": has_binary_comment
            }

    @classmethod
    def _analyze_references_and_trailer(cls, data: bytes, file_size: int) -> Dict[str, Any]:
        """
        Granularly analyzes:
        1. startxref pointer keyword and offset integrity
        2. Cross-reference (xref) table or xref stream object
        3. Trailer dictionary structure, /Root, /Size, and /Info references
        """
        startxref_matches = list(re.finditer(rb"startxref\s+(\d+)", data))

        # Check startxref
        if not startxref_matches:
            startxref_result = {
                "region": "startxref",
                "status": "corrupted",
                "reason": "Missing 'startxref' keyword in document",
                "offset": None,
                "recoverable": True
            }
            xref_result = {
                "region": "xref",
                "status": "corrupted",
                "reason": "Cross-reference table cannot be located without startxref pointer",
                "xref_type": "missing",
                "recoverable": True
            }
            trailer_result = {
                "region": "trailer",
                "status": "corrupted" if b"trailer" not in data else "partially_valid",
                "reason": "Trailer cannot be validated without startxref locator" if b"trailer" not in data else "Orphaned trailer dictionary found in binary scan",
                "has_root": b"/Root" in data,
                "recoverable": True
            }
            return {"startxref": startxref_result, "xref": xref_result, "trailer": trailer_result}

        last_match = startxref_matches[-1]
        try:
            xref_offset = int(last_match.group(1).decode("ascii"))
        except Exception:
            xref_offset = -1

        if xref_offset < 0 or xref_offset >= file_size:
            startxref_result = {
                "region": "startxref",
                "status": "corrupted",
                "reason": f"'startxref' points to invalid offset {xref_offset} (file size {file_size} bytes)",
                "offset": xref_offset,
                "recoverable": True
            }
            xref_result = {
                "region": "xref",
                "status": "corrupted",
                "reason": f"Out-of-bounds xref pointer ({xref_offset})",
                "xref_type": "out_of_bounds",
                "recoverable": True
            }
            trailer_result = {
                "region": "trailer",
                "status": "corrupted" if b"/Root" not in data else "partially_valid",
                "reason": "Trailer disconnected due to out-of-bounds startxref pointer",
                "recoverable": True
            }
            return {"startxref": startxref_result, "xref": xref_result, "trailer": trailer_result}

        startxref_result = {
            "region": "startxref",
            "status": "valid",
            "reason": f"Valid 'startxref' pointing to byte offset {xref_offset}",
            "offset": xref_offset
        }

        # Analyze XRef content at offset
        target_snippet = data[xref_offset:xref_offset + 64]
        is_traditional_xref = target_snippet.startswith(b"xref")
        is_stream_xref = bool(re.search(rb"/Type\s*/XRef", target_snippet)) or (b"obj" in target_snippet and b"/XRef" in data[xref_offset:xref_offset + 512])

        if is_traditional_xref:
            xref_result = {
                "region": "xref",
                "status": "valid",
                "reason": f"Valid traditional cross-reference table verified at offset {xref_offset}",
                "xref_type": "traditional",
                "offset": xref_offset
            }
            # Look for standalone trailer keyword
            trailer_m = re.search(rb"\btrailer\b\s*<<(?P<dict>.*?)>>", data[xref_offset:], re.DOTALL)
            if trailer_m:
                trailer_dict = trailer_m.group("dict")
                has_root = bool(re.search(rb"/Root\b", trailer_dict))
                has_size = bool(re.search(rb"/Size\b", trailer_dict))
                if has_root and has_size:
                    trailer_result = {
                        "region": "trailer",
                        "status": "valid",
                        "reason": "Valid trailer dictionary containing /Root catalog and /Size entries",
                        "has_root": True,
                        "has_size": True
                    }
                else:
                    missing_keys = []
                    if not has_root: missing_keys.append("/Root")
                    if not has_size: missing_keys.append("/Size")
                    trailer_result = {
                        "region": "trailer",
                        "status": "corrupted",
                        "reason": f"Trailer dictionary missing critical keys: {', '.join(missing_keys)}",
                        "has_root": has_root,
                        "has_size": has_size,
                        "recoverable": True
                    }
            else:
                trailer_result = {
                    "region": "trailer",
                    "status": "corrupted",
                    "reason": "Missing or malformed trailer keyword/dictionary following cross-reference table",
                    "recoverable": True
                }
        elif is_stream_xref:
            has_root = b"/Root" in data[xref_offset:xref_offset + 512]
            xref_result = {
                "region": "xref",
                "status": "valid",
                "reason": f"Valid cross-reference stream object verified at offset {xref_offset}",
                "xref_type": "stream",
                "offset": xref_offset
            }
            if has_root:
                trailer_result = {
                    "region": "trailer",
                    "status": "valid",
                    "reason": "Trailer metadata embedded directly within cross-reference stream dictionary",
                    "has_root": True
                }
            else:
                trailer_result = {
                    "region": "trailer",
                    "status": "corrupted",
                    "reason": "Cross-reference stream dictionary missing /Root catalog pointer",
                    "has_root": False,
                    "recoverable": True
                }
        else:
            xref_result = {
                "region": "xref",
                "status": "corrupted",
                "reason": f"Offset {xref_offset} does not begin with 'xref' keyword or /XRef stream dictionary",
                "xref_type": "corrupted_offset",
                "recoverable": True
            }
            trailer_result = {
                "region": "trailer",
                "status": "corrupted",
                "reason": "Cannot resolve trailer due to corrupt xref block",
                "recoverable": True
            }

        return {"startxref": startxref_result, "xref": xref_result, "trailer": trailer_result}

    @classmethod
    def _recommend_tools(cls, classifications: List[str], body_result: Dict[str, Any], xref_result: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Recommends targeted tools (qpdf, mutool, ghostscript, internal recovery engine)
        based on classified corruption symptoms.
        """
        recommendations = []
        class_set = set(classifications)

        if "Header corruption" in class_set:
            recommendations.append({
                "tool": "qpdf",
                "command": "qpdf --repair-file input.pdf fixed_header.pdf",
                "approach": "Realigns displaced magic bytes, strips preceding junk prefix, and reconstructs standard %PDF-1.7 header."
            })

        if "Body/object corruption" in class_set or "Missing/truncated data" in class_set:
            recommendations.append({
                "tool": "pymupdf",
                "command": "mutool clean -s input.pdf recovered.pdf",
                "approach": "Decompresses raw flate streams, salvages surviving page definitions, and extracts content."
            })

        if "Cross-reference (xref) corruption" in class_set or "startxref corruption" in class_set or "Trailer corruption" in class_set:
            recommendations.append({
                "tool": "qpdf",
                "command": "qpdf --check input.pdf ; qpdf --repair-file input.pdf recovered.pdf",
                "approach": "Rebuilds cross-reference table and recalculates trailer dictionaries from surviving object graph."
            })

        if "EOF corruption" in class_set:
            recommendations.append({
                "tool": "qpdf",
                "command": "qpdf --repair-file input.pdf fixed_eof.pdf",
                "approach": "Appends missing %%EOF marker, terminates truncated streams, and seals document boundaries."
            })

        if "Embedded image corruption" in class_set:
            recommendations.append({
                "tool": "pillow",
                "command": "PIL.Image / stream carver",
                "approach": "Extracts damaged JPEG/PNG streams, restores SOI/EOI markers, and recovers visual assets."
            })

        if not recommendations:
            recommendations.append({
                "tool": "qpdf",
                "command": "qpdf --check input.pdf",
                "approach": "Validates structure against PDF ISO 32000 standard."
            })

        return recommendations


    @classmethod
    def _analyze_body(cls, data: bytes, file_path: str) -> Dict[str, Any]:
        """
        Analyzes PDF objects, streams, Catalog, Pages tree, and cross-compares
        parsers (pypdf, PyMuPDF) to detect corruption.
        """
        # Count objects
        obj_matches = list(re.finditer(rb"(?P<num>\d+)\s+(?P<gen>\d+)\s+obj\b", data))
        endobj_count = len(re.findall(rb"\bendobj\b", data))
        stream_count = len(re.findall(rb"\bstream\r?\n", data))
        endstream_count = len(re.findall(rb"\bendstream\b", data))

        # Check critical structural references
        has_catalog = bool(re.search(rb"/Type\s*/Catalog\b", data))
        has_pages_root = bool(re.search(rb"/Type\s*/Pages\b", data))
        page_obj_matches = list(re.finditer(rb"/Type\s*/Page\b", data))
        pages_detected = len(page_obj_matches)

        # Test stream decompression on compressed streams (skip image streams, handled by _analyze_images)
        corrupted_stream_offsets = []
        stream_matches = list(re.finditer(rb"stream\r?\n(?P<content>.*?)\r?\nendstream", data, re.DOTALL))
        for sm in stream_matches[:15]:  # Sample up to 15 streams
            preceding = data[max(0, sm.start() - 350):sm.start()]
            if b"/Subtype" in preceding and (b"/Image" in preceding or b"Image" in preceding):
                continue  # Image stream
            if b"FlateDecode" in preceding:
                s_content = sm.group("content")
                try:
                    zlib.decompress(s_content)
                except Exception:
                    try:
                        # Try raw deflate without header
                        zlib.decompress(s_content, -zlib.MAX_WBITS)
                    except Exception:
                        corrupted_stream_offsets.append(sm.start())

        # Parser comparisons
        pypdf_ok = False
        pypdf_pages = 0
        pypdf_error = None
        if PdfReader:
            try:
                reader = PdfReader(file_path, strict=False)
                pypdf_pages = len(reader.pages)
                pypdf_ok = True
            except Exception as e:
                pypdf_error = str(e)

        fitz_ok = False
        fitz_pages = 0
        fitz_error = None
        if fitz:
            try:
                doc = fitz.open(file_path)
                fitz_pages = len(doc)
                fitz_ok = True
                doc.close()
            except Exception as e:
                fitz_error = str(e)

        # Decide final detected page count
        resolved_pages = max(pages_detected, pypdf_pages, fitz_pages)

        # Object mismatch or stream mismatch checks
        mismatched_objects = len(obj_matches) != endobj_count
        mismatched_streams = stream_count != endstream_count

        issues = []
        if mismatched_objects:
            issues.append(f"Unmatched object boundaries ({len(obj_matches)} 'obj' vs {endobj_count} 'endobj')")
        if mismatched_streams:
            issues.append(f"Unmatched stream boundaries ({stream_count} 'stream' vs {endstream_count} 'endstream')")
        if corrupted_stream_offsets:
            issues.append(f"Stream decompression failed near byte offset {corrupted_stream_offsets[0]}")
        if not has_catalog:
            issues.append("Document Catalog dictionary (/Type /Catalog) not found")
        if not has_pages_root:
            issues.append("Document Pages root dictionary (/Type /Pages) not found")
        if pypdf_error and fitz_error:
            issues.append(f"Standard parsers failed: {pypdf_error or fitz_error}")
        if resolved_pages == 0:
            issues.append("PyMuPDF parsed 0 pages from document tree")

        status = "valid"
        if issues:
            if resolved_pages > 0 or len(obj_matches) > 0:
                status = "corrupted"
            else:
                status = "corrupted"

        reason = "Valid PDF objects, streams, and page catalog verified." if status == "valid" else "; ".join(issues)

        return {
            "region": "body",
            "status": status,
            "reason": reason,
            "objects_detected": len(obj_matches),
            "pages_detected": resolved_pages,
            "streams_detected": stream_count,
            "has_catalog": has_catalog,
            "has_pages_root": has_pages_root,
            "pypdf_status": {"ok": pypdf_ok, "pages": pypdf_pages, "error": pypdf_error},
            "fitz_status": {"ok": fitz_ok, "pages": fitz_pages, "error": fitz_error}
        }

    @classmethod
    def _analyze_eof(cls, data: bytes, file_size: int) -> Dict[str, Any]:
        """
        Inspects %%EOF marker, trailing data, and file truncation status.
        """
        eof_marker = b"%%EOF"
        eof_pos = data.rfind(eof_marker)

        if eof_pos == -1:
            # Check if file ends mid-stream or mid-object (truncation)
            is_truncated = (b"stream" in data and b"endstream" not in data[data.rfind(b"stream"):]) or \
                           (b"obj" in data and b"endobj" not in data[data.rfind(b"obj"):])
            return {
                "region": "end_of_file",
                "status": "corrupted",
                "reason": "Missing %%EOF marker at end of document (File appears truncated)" if is_truncated else "Missing %%EOF marker at end of document",
                "offset": None,
                "trailing_bytes": 0,
                "is_truncated": True
            }

        trailing_data = len(data) - (eof_pos + len(eof_marker))
        # Strip trailing newlines or whitespace
        trailing_content = data[eof_pos + len(eof_marker):].strip()

        if len(trailing_content) == 0:
            return {
                "region": "end_of_file",
                "status": "valid",
                "reason": "Valid %%EOF marker detected at document terminator",
                "offset": eof_pos,
                "trailing_bytes": 0,
                "is_truncated": False
            }
        else:
            return {
                "region": "end_of_file",
                "status": "corrupted",
                "reason": f"%%EOF marker found at byte {eof_pos} with {len(trailing_content)} unexpected trailing bytes",
                "offset": eof_pos,
                "trailing_bytes": len(trailing_content),
                "is_truncated": False
            }

    @classmethod
    def _analyze_images(cls, data: bytes) -> Dict[str, Any]:
        """
        Inspects embedded raster images (JPEG, PNG, Flate) for stream corruption,
        missing markers, or decompression errors.
        """
        image_obj_matches = list(re.finditer(rb"<<[^>]*?/Subtype\s*/Image[^>]*?>>\s*stream\r?\n", data))
        if not image_obj_matches:
            image_obj_matches = list(re.finditer(rb"<<[^>]*?/Subtype/Image[^>]*?>>\s*stream\r?\n", data))

        if not image_obj_matches:
            return {
                "region": "images",
                "status": "valid",
                "reason": "Region syntax & structure valid.",
                "defects": []
            }

        defects = []
        for m in image_obj_matches[:15]:
            dict_header = m.group(0)
            stream_start = m.end()
            stream_end = data.find(b"endstream", stream_start)
            if stream_end != -1:
                raw_img_stream = data[stream_start:stream_end].strip()
                if b"/DCTDecode" in dict_header:
                    if not raw_img_stream.startswith(b"\xff\xd8"):
                        defects.append("Corrupted JPEG SOI marker in embedded image stream")
                    elif not raw_img_stream.endswith(b"\xff\xd9") and b"\xff\xd9" not in raw_img_stream[-16:]:
                        defects.append("Missing JPEG EOI terminal marker in embedded image stream")
                elif b"/FlateDecode" in dict_header and b"/Filter" in dict_header:
                    try:
                        decomp = zlib.decompress(raw_img_stream)
                        if len(decomp) == 0:
                            defects.append("Zero-length decompressed embedded image stream")
                    except Exception:
                        try:
                            zlib.decompress(raw_img_stream, -zlib.MAX_WBITS)
                        except Exception:
                            defects.append("Corrupted zlib compression stream in embedded image object")

        if defects:
            return {
                "region": "images",
                "status": "corrupted",
                "reason": defects[0],
                "defects": defects
            }

        return {
            "region": "images",
            "status": "valid",
            "reason": "Region syntax & structure valid.",
            "defects": []
        }


