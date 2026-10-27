import os
import re
import io
import zlib
from pathlib import Path
from typing import Dict, Any, List, Optional

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

try:
    from PIL import Image
except ImportError:
    Image = None

from services.detector import FileDetector


class CorruptionClassifier:
    """
    Forensic Corruption Detection & Classification Engine.
    Inspects file signatures, structural hierarchies, cross-references, stream tokens,
    and embedded multimedia to identify exact corruption categories and confidence levels.
    """

    # Category Constants
    PDF_HEADER_CORRUPTION = "PDF_HEADER_CORRUPTION"
    PDF_BODY_CORRUPTION = "PDF_BODY_CORRUPTION"
    PDF_XREF_CORRUPTION = "PDF_XREF_CORRUPTION"
    PDF_EOF_TRUNCATION = "PDF_EOF_TRUNCATION"
    PDF_IMAGE_CORRUPTION = "PDF_IMAGE_CORRUPTION"
    ZIP_CONTAINER_CORRUPTION = "ZIP_CONTAINER_CORRUPTION"
    XML_STRUCTURE_CORRUPTION = "XML_STRUCTURE_CORRUPTION"
    IMAGE_DATA_CORRUPTION = "IMAGE_DATA_CORRUPTION"
    CLEAN = "CLEAN"
    UNRECOVERABLE = "UNRECOVERABLE"
    UNSUPPORTED = "UNSUPPORTED"

    @classmethod
    def classify(cls, file_path: str, detected_type: str = "auto") -> Dict[str, Any]:
        """
        Classifies file corruption with granular defect breakdown and confidence score.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return {
                "file_type": "EMPTY",
                "corruption_type": cls.UNRECOVERABLE,
                "category": "Empty File (Zero Bytes)",
                "confidence": 1.0,
                "confidence_level": "HIGH",
                "is_corrupted": True,
                "can_recover": False,
                "details": "File is completely empty (0 bytes) with no recoverable binary content.",
                "defects": ["Zero-byte file"],
                "recommended_tools": [],
                "expected_limitations": "Permanent data loss; cannot synthesize content from 0 bytes."
            }

        # Determine type
        if not detected_type or detected_type.lower() == "auto":
            det = FileDetector.detect_file_type(file_path)
            fmt = det.get("file_type", "UNKNOWN").upper()
        else:
            fmt = detected_type.upper()

        if fmt == "PDF":
            return cls._classify_pdf(file_path, file_size)
        elif fmt in ["DOCX", "XLSX", "PPTX", "WORD", "EXCEL", "POWERPOINT"]:
            return cls._classify_ooxml(file_path, file_size, fmt)
        elif fmt in ["IMAGE", "JPEG", "JPG", "PNG", "WEBP"]:
            return cls._classify_image(file_path, file_size, fmt)
        elif fmt in ["CSV", "JSON", "TEXT"]:
            return cls._classify_text(file_path, file_size, fmt)
        else:
            return {
                "file_type": fmt,
                "corruption_type": cls.UNSUPPORTED,
                "category": "Unsupported File Format",
                "confidence": 0.8,
                "confidence_level": "MEDIUM",
                "is_corrupted": False,
                "can_recover": False,
                "details": f"Format '{fmt}' is not supported for specialized forensic recovery.",
                "defects": [],
                "recommended_tools": ["text_recovery"],
                "expected_limitations": "Generic byte preservation only."
            }

    @classmethod
    def _classify_pdf(cls, file_path: str, file_size: int) -> Dict[str, Any]:
        with open(file_path, "rb") as f:
            data = f.read()

        defects = []
        header_defects = []
        body_defects = []
        reference_defects = []
        eof_defects = []
        image_defects = []

        header_corrupted = False
        xref_corrupted = False
        eof_corrupted = False
        body_corrupted = False
        image_corrupted = False
        image_defect_details = []

        # 1. Header inspection
        header_sample = data[:min(2048, len(data))]
        pdf_pos = header_sample.find(b"%PDF-")
        if pdf_pos == -1:
            header_corrupted = True
            msg = "Missing %PDF- header magic signature"
            header_defects.append(msg)
            defects.append(msg)
        elif pdf_pos > 0:
            header_corrupted = True
            msg = f"Displaced %PDF- header signature preceded by {pdf_pos} bytes of arbitrary junk"
            header_defects.append(msg)
            defects.append(msg)
        else:
            # Check version sanity
            v_match = re.search(rb"^%PDF-(\d+\.\d+)", data[:16])
            if not v_match:
                header_corrupted = True
                msg = "Malformed or unrecognized PDF version specification in header"
                header_defects.append(msg)
                defects.append(msg)

        # 2. EOF & Trailer inspection
        trailer_search_window = data[-min(2048, len(data)):]
        eof_pos = trailer_search_window.rfind(b"%%EOF")
        if eof_pos == -1:
            eof_corrupted = True
            msg = "Missing %%EOF terminal marker (file is truncated or damaged at end)"
            eof_defects.append(msg)
            defects.append(msg)
        elif eof_pos < len(trailer_search_window) - 32:
            # Check for trailing junk after %%EOF
            post_eof = trailer_search_window[eof_pos + 5:].strip()
            if len(post_eof) > 64:
                eof_corrupted = True
                msg = f"Significant trailing garbage bytes ({len(post_eof)} bytes) after %%EOF"
                eof_defects.append(msg)
                defects.append(msg)

        # 3. References & startxref inspection
        startxref_matches = list(re.finditer(rb"startxref\s+(\d+)", data))
        if not startxref_matches:
            xref_corrupted = True
            msg = "Missing startxref pointer token"
            reference_defects.append(msg)
            defects.append(msg)
        else:
            last_startxref = int(startxref_matches[-1].group(1))
            if last_startxref >= file_size or last_startxref < 0:
                xref_corrupted = True
                msg = f"Invalid startxref offset ({last_startxref}) exceeds file length ({file_size} bytes)"
                reference_defects.append(msg)
                defects.append(msg)
            else:
                # Check target offset byte
                target_bytes = data[last_startxref:last_startxref + 16]
                if not (target_bytes.startswith(b"xref") or b"obj" in target_bytes or b"<<" in target_bytes):
                    xref_corrupted = True
                    msg = f"startxref points to invalid non-XREF byte pattern at offset {last_startxref}"
                    reference_defects.append(msg)
                    defects.append(msg)

        # 4. Check embedded image corruption
        # Scan for /Subtype /Image or /DCTDecode or /FlateDecode with image params
        image_obj_matches = list(re.finditer(rb"<<[^>]*?/Subtype\s*/Image[^>]*?>>\s*stream\r?\n", data))
        if image_obj_matches:
            for m in image_obj_matches[:10]:  # check up to 10 image streams
                dict_header = m.group(0)
                stream_start = m.end()
                stream_end = data.find(b"endstream", stream_start)
                if stream_end != -1:
                    raw_img_stream = data[stream_start:stream_end].strip()
                    # JPEG check
                    if b"/DCTDecode" in dict_header:
                        if not raw_img_stream.startswith(b"\xff\xd8"):
                            image_corrupted = True
                            image_defect_details.append("Corrupted JPEG SOI marker in embedded image stream")
                        elif not raw_img_stream.endswith(b"\xff\xd9") and b"\xff\xd9" not in raw_img_stream[-16:]:
                            image_corrupted = True
                            image_defect_details.append("Missing JPEG EOI terminal marker in embedded image stream")
                        elif Image:
                            try:
                                with Image.open(io.BytesIO(raw_img_stream)) as test_img:
                                    test_img.verify()
                            except Exception as img_err:
                                image_corrupted = True
                                image_defect_details.append(f"Embedded JPEG scan decoding error: {str(img_err)[:60]}")
                    # PNG/Flate check
                    elif b"/FlateDecode" in dict_header and b"/Filter" in dict_header:
                        try:
                            decomp = zlib.decompress(raw_img_stream)
                            if len(decomp) == 0:
                                image_corrupted = True
                                image_defect_details.append("Zero-length decompressed embedded image stream")
                        except Exception:
                            image_corrupted = True
                            image_defect_details.append("Corrupted zlib compression stream in embedded image object")

        if image_defect_details:
            image_defects.extend(image_defect_details)
            defects.extend(image_defect_details[:2])

        # 5. Body & Stream inspection
        obj_count = len(re.findall(rb"\d+\s+\d+\s+obj\b", data))
        stream_count = len(re.findall(rb"\bstream\r?\n", data))
        endstream_count = len(re.findall(rb"\bendstream\b", data))
        if stream_count != endstream_count:
            body_corrupted = True
            msg = f"Mismatched content streams ({stream_count} 'stream' vs {endstream_count} 'endstream')"
            body_defects.append(msg)
            defects.append(msg)

        # Test non-image stream decompression on compressed body streams
        body_stream_matches = list(re.finditer(rb"stream\r?\n(?P<content>.*?)\r?\nendstream", data, re.DOTALL))
        for sm in body_stream_matches[:15]:
            preceding = data[max(0, sm.start() - 350):sm.start()]
            if b"/Subtype" in preceding and (b"/Image" in preceding or b"Image" in preceding):
                continue  # Handled by image inspection
            if b"FlateDecode" in preceding:
                s_content = sm.group("content")
                try:
                    zlib.decompress(s_content)
                except Exception:
                    try:
                        zlib.decompress(s_content, -zlib.MAX_WBITS)
                    except Exception:
                        body_corrupted = True
                        msg = f"Stream decompression failed near byte offset {sm.start()}"
                        if msg not in body_defects:
                            body_defects.append(msg)
                            defects.append(msg)

        # 6. Parser Verification
        mupdf_err = None
        pypdf_err = None
        if fitz:
            try:
                doc = fitz.open(file_path)
                pages = len(doc)
                if pages == 0:
                    body_corrupted = True
                    msg = "PyMuPDF parsed 0 pages from document tree"
                    body_defects.append(msg)
                    defects.append(msg)
            except Exception as e:
                mupdf_err = str(e)
                err_lower = mupdf_err.lower()
                if "xref" in err_lower or "trailer" in err_lower:
                    xref_corrupted = True
                    reference_defects.append(f"PyMuPDF XREF parser error: {mupdf_err[:70]}")
                elif "eof" in err_lower:
                    eof_corrupted = True
                    eof_defects.append(f"PyMuPDF EOF error: {mupdf_err[:70]}")
                else:
                    body_corrupted = True
                    body_defects.append(f"PyMuPDF syntax parser error: {mupdf_err[:70]}")
        if PdfReader:
            try:
                reader = PdfReader(file_path)
                _ = len(reader.pages)
            except Exception as e:
                pypdf_err = str(e)
                err_lower = pypdf_err.lower()
                if "xref" in err_lower or "startxref" in err_lower:
                    xref_corrupted = True
                    reference_defects.append(f"pypdf XREF parser error: {pypdf_err[:70]}")
                elif "eof" in err_lower:
                    eof_corrupted = True
                    eof_defects.append(f"pypdf EOF error: {pypdf_err[:70]}")
                else:
                    body_corrupted = True
                    body_defects.append(f"pypdf parser error: {pypdf_err[:70]}")

        # Build 5-Region Forensic Diagnostic Breakdown
        regions = {
            "header": {
                "name": "Header",
                "label": "File Header & Magic Bytes",
                "status": "CORRUPTED" if header_corrupted else "INTACT",
                "is_corrupted": header_corrupted,
                "defects": header_defects,
                "recommended_tool": "qpdf",
                "tool_name": "qpdf",
                "tool_purpose": "Realigns displaced magic bytes, strips preceding junk prefix, and reconstructs standard %PDF-1.7 header." if header_corrupted else "Header is healthy and valid."
            },
            "body": {
                "name": "Body",
                "label": "Document Body & Content Streams",
                "status": "CORRUPTED" if body_corrupted else "INTACT",
                "is_corrupted": body_corrupted,
                "defects": body_defects,
                "recommended_tool": "pymupdf",
                "tool_name": "pymupdf",
                "tool_purpose": "Carves surviving page dictionaries, decompresses text streams, and reconstructs document tree." if body_corrupted else "Page content and objects are intact."
            },
            "reference": {
                "name": "Reference",
                "label": "Cross-Reference (XREF) Table",
                "status": "CORRUPTED" if xref_corrupted else "INTACT",
                "is_corrupted": xref_corrupted,
                "defects": reference_defects,
                "recommended_tool": "qpdf",
                "tool_name": "qpdf",
                "tool_purpose": "Scans object boundaries, recalculates byte offsets, and rebuilds valid XREF tables and trailer." if xref_corrupted else "Cross-reference pointers are valid."
            },
            "eof": {
                "name": "EOF",
                "label": "EOF Marker & Trailer Dictionary",
                "status": "CORRUPTED" if eof_corrupted else "INTACT",
                "is_corrupted": eof_corrupted,
                "defects": eof_defects,
                "recommended_tool": "qpdf",
                "tool_name": "qpdf",
                "tool_purpose": "Appends missing %%EOF marker, terminates truncated streams, and seals document boundaries." if eof_corrupted else "EOF marker and trailer are intact."
            },
            "image": {
                "name": "Images",
                "label": "Embedded Images & Raster Streams",
                "status": "CORRUPTED" if image_corrupted else "INTACT",
                "is_corrupted": image_corrupted,
                "defects": image_defects,
                "recommended_tool": "pillow",
                "tool_name": "pillow",
                "tool_purpose": "Extracts damaged JPEG/PNG streams, restores SOI/EOI markers, and recovers visual assets." if image_corrupted else "Embedded image streams are intact."
            }
        }
        corrupted_regions = [r["name"] for r in regions.values() if r["is_corrupted"]]

        # Classify Primary Corruption Type
        if not defects and not mupdf_err and not pypdf_err:
            return {
                "file_type": "PDF",
                "corruption_type": cls.CLEAN,
                "category": "Intact Document",
                "confidence": 0.98,
                "confidence_level": "HIGH",
                "is_corrupted": False,
                "can_recover": True,
                "details": "PDF structure is valid across Header, Body, Reference, EOF, and Image regions.",
                "defects": [],
                "regions": regions,
                "corrupted_regions": [],
                "recommended_tools": ["pikepdf"],
                "expected_limitations": "No repairs needed; document is already intact."
            }

        # Check if totally unrecoverable
        if obj_count == 0 and not any(k in data for k in [b"/Catalog", b"/Pages", b"/Type"]):
            return {
                "file_type": "PDF",
                "corruption_type": cls.UNRECOVERABLE,
                "category": "Unrecoverable PDF",
                "confidence": 0.95,
                "confidence_level": "HIGH",
                "is_corrupted": True,
                "can_recover": False,
                "details": "No PDF objects, catalog dictionaries, or page descriptors survive in file.",
                "defects": defects or ["No valid PDF structures found"],
                "regions": regions,
                "corrupted_regions": corrupted_regions or ["Body", "Reference"],
                "recommended_tools": [],
                "expected_limitations": "Permanent structural destruction; no recoverable text or pages."
            }

        # Determine primary category based on priority & defects
        if image_corrupted and not (header_corrupted or xref_corrupted or eof_corrupted):
            corr_type = cls.PDF_IMAGE_CORRUPTION
            cat_name = "Embedded Image Corruption"
            conf = 0.92
            primary_tool = "pdf_image_recovery"
            tools = ["pdf_image_recovery", "pymupdf", "pillow", "pikepdf"]
            limitations = "Corrupted embedded raster graphics will be repaired or salvaged; partial graphics will note missing scanlines."
        elif header_corrupted and not (body_corrupted and obj_count < 2):
            corr_type = cls.PDF_HEADER_CORRUPTION
            cat_name = "PDF Header Corruption"
            conf = 0.95
            primary_tool = "pdf_header_recovery"
            tools = ["pdf_header_recovery", "qpdf", "pikepdf", "pymupdf", "pypdf"]
            limitations = "Header magic bytes and pre-header garbage realigned without modifying document body."
        elif xref_corrupted:
            corr_type = cls.PDF_XREF_CORRUPTION
            cat_name = "Cross-Reference (XREF) Table Corruption"
            conf = 0.92
            primary_tool = "pdf_xref_recovery"
            tools = ["pdf_xref_recovery", "qpdf", "pikepdf", "mutool", "pymupdf", "pypdf"]
            limitations = "Cross-reference table and trailer dictionary rebuilt with recalculated byte offsets."
        elif eof_corrupted:
            corr_type = cls.PDF_EOF_TRUNCATION
            cat_name = "EOF / Truncation Corruption"
            conf = 0.90
            primary_tool = "pdf_eof_recovery"
            tools = ["pdf_eof_recovery", "qpdf", "pikepdf", "pymupdf", "pypdf"]
            limitations = "Surviving document structure stabilized; truncated final pages or streams safely terminated."
        else:
            corr_type = cls.PDF_BODY_CORRUPTION
            cat_name = "Body & Content Stream Corruption"
            conf = 0.88
            primary_tool = "pdf_body_recovery"
            tools = ["pdf_body_recovery", "pymupdf", "qpdf", "pikepdf", "pdfplumber", "pillow"]
            limitations = "Surviving pages and readable text harvested; severely corrupted streams omitted to prevent rendering crash."

        return {
            "file_type": "PDF",
            "corruption_type": corr_type,
            "category": cat_name,
            "confidence": conf,
            "confidence_level": "HIGH" if conf >= 0.85 else "MEDIUM",
            "is_corrupted": True,
            "can_recover": True,
            "details": f"Detected {cat_name}: " + "; ".join(defects[:3]),
            "defects": defects,
            "regions": regions,
            "corrupted_regions": corrupted_regions,
            "objects_count": obj_count,
            "streams_count": stream_count,
            "recommended_tools": tools,
            "primary_tool": primary_tool,
            "expected_limitations": limitations
        }

    @classmethod
    def _classify_ooxml(cls, file_path: str, file_size: int, fmt: str) -> Dict[str, Any]:
        import zipfile
        defects = []
        is_zip_corrupt = False
        is_xml_corrupt = False

        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                bad_file = zf.testzip()
                if bad_file:
                    is_zip_corrupt = True
                    defects.append(f"Corrupted CRC in ZIP archive member: {bad_file}")
                names = zf.namelist()
                if "[Content_Types].xml" not in names:
                    is_xml_corrupt = True
                    defects.append("Missing mandatory [Content_Types].xml container definition")
        except zipfile.BadZipFile as e:
            is_zip_corrupt = True
            defects.append(f"Malformed ZIP container: {str(e)}")
        except Exception as e:
            is_zip_corrupt = True
            defects.append(f"Archive error: {str(e)}")

        primary_tool_name = "docx_recovery" if "DOC" in fmt or "WORD" in fmt else ("xlsx_recovery" if "XLS" in fmt or "EXCEL" in fmt else "pptx_recovery")
        regions = {
            "header": {
                "name": "Header",
                "label": "ZIP Package Header",
                "status": "CORRUPTED" if is_zip_corrupt else "INTACT",
                "is_corrupted": is_zip_corrupt,
                "defects": [d for d in defects if "ZIP" in d or "CRC" in d],
                "recommended_tool": primary_tool_name if is_zip_corrupt else "python-docx",
                "tool_name": f"{fmt} Container Repair Engine",
                "tool_purpose": "Repairs corrupted ZIP package headers and archive member CRC records."
            },
            "body": {
                "name": "Body",
                "label": "Document XML Streams",
                "status": "CORRUPTED" if is_xml_corrupt else "INTACT",
                "is_corrupted": is_xml_corrupt,
                "defects": [d for d in defects if "XML" in d or "Content_Types" in d],
                "recommended_tool": primary_tool_name if is_xml_corrupt else "openpyxl",
                "tool_name": f"{fmt} XML Structure Engine",
                "tool_purpose": "Synthesizes missing XML content trees, balances markup tags, and restores document text/sheets."
            },
            "reference": {
                "name": "Reference",
                "label": "Package Relationships (_rels)",
                "status": "CORRUPTED" if is_xml_corrupt else "INTACT",
                "is_corrupted": is_xml_corrupt,
                "defects": [d for d in defects if "Content_Types" in d or "rels" in d],
                "recommended_tool": primary_tool_name if is_xml_corrupt else "python-docx",
                "tool_name": f"{fmt} Relationship Builder",
                "tool_purpose": "Reconstructs package relationship mapping and part targets."
            },
            "eof": {
                "name": "EOF",
                "label": "Central Directory & EOF",
                "status": "CORRUPTED" if is_zip_corrupt else "INTACT",
                "is_corrupted": is_zip_corrupt,
                "defects": [d for d in defects if "ZIP" in d],
                "recommended_tool": primary_tool_name if is_zip_corrupt else "python-docx",
                "tool_name": f"{fmt} Container Stabilizer",
                "tool_purpose": "Rebuilds End of Central Directory record and seals container."
            },
            "image": {
                "name": "Images",
                "label": "Embedded Media Parts",
                "status": "INTACT",
                "is_corrupted": False,
                "defects": [],
                "recommended_tool": "pillow",
                "tool_name": "Media Extractor",
                "tool_purpose": "Extracts and validates embedded media parts."
            }
        }
        corrupted_regions = [r["name"] for r in regions.values() if r["is_corrupted"]]

        if not defects:
            return {
                "file_type": fmt,
                "corruption_type": cls.CLEAN,
                "category": "Intact Document Container",
                "confidence": 0.95,
                "confidence_level": "HIGH",
                "is_corrupted": False,
                "can_recover": True,
                "details": f"Valid {fmt} OpenXML container structure and intact XML streams.",
                "defects": [],
                "regions": regions,
                "corrupted_regions": [],
                "recommended_tools": [],
                "expected_limitations": "Document is healthy."
            }

        corr_type = cls.ZIP_CONTAINER_CORRUPTION if is_zip_corrupt else cls.XML_STRUCTURE_CORRUPTION
        cat = "ZIP Package Corruption" if is_zip_corrupt else "OpenXML Structural Corruption"
        tools = ["docx_recovery"] if "DOC" in fmt or "WORD" in fmt else (["xlsx_recovery"] if "XLS" in fmt or "EXCEL" in fmt else ["pptx_recovery"])

        return {
            "file_type": fmt,
            "corruption_type": corr_type,
            "category": cat,
            "confidence": 0.90,
            "confidence_level": "HIGH",
            "is_corrupted": True,
            "can_recover": True,
            "details": f"{fmt} container defects: " + "; ".join(defects),
            "defects": defects,
            "regions": regions,
            "corrupted_regions": corrupted_regions,
            "recommended_tools": tools,
            "primary_tool": tools[0],
            "expected_limitations": "Recoverable XML content runs and tables will be assembled into a clean document container."
        }

    @classmethod
    def _classify_image(cls, file_path: str, file_size: int, fmt: str) -> Dict[str, Any]:
        defects = []
        is_corrupt = False
        if Image:
            try:
                with Image.open(file_path) as im:
                    im.verify()
            except Exception as e:
                is_corrupt = True
                defects.append(f"Image decoder error: {str(e)}")

        regions = {
            "header": {
                "name": "Header",
                "label": "Image Magic Signature & SOI",
                "status": "CORRUPTED" if is_corrupt else "INTACT",
                "is_corrupted": is_corrupt,
                "defects": defects if is_corrupt else [],
                "recommended_tool": "image_recovery" if is_corrupt else "pillow",
                "tool_name": "Image Header Synthesizer",
                "tool_purpose": "Restores missing SOI/PNG signature and dimensions."
            },
            "body": {
                "name": "Body",
                "label": "Raster Pixel Data Streams",
                "status": "CORRUPTED" if is_corrupt else "INTACT",
                "is_corrupted": is_corrupt,
                "defects": defects if is_corrupt else [],
                "recommended_tool": "image_recovery" if is_corrupt else "pillow",
                "tool_name": "Raster Data Salvager",
                "tool_purpose": "Stabilizes truncated scanlines and fills missing pixel blocks."
            },
            "reference": {
                "name": "Reference",
                "label": "Metadata & Chunk Headers",
                "status": "INTACT",
                "is_corrupted": False,
                "defects": [],
                "recommended_tool": "pillow",
                "tool_name": "Metadata Validator",
                "tool_purpose": "Verifies color profile chunks and metadata."
            },
            "eof": {
                "name": "EOF",
                "label": "EOI Terminal Marker",
                "status": "CORRUPTED" if is_corrupt else "INTACT",
                "is_corrupted": is_corrupt,
                "defects": ["Missing EOI terminal marker"] if is_corrupt else [],
                "recommended_tool": "image_recovery" if is_corrupt else "pillow",
                "tool_name": "Image EOF Terminal Fixer",
                "tool_purpose": "Appends standard EOI marker to prevent viewer crashes."
            },
            "image": {
                "name": "Images",
                "label": "Color Channels & Visual Bitmap",
                "status": "CORRUPTED" if is_corrupt else "INTACT",
                "is_corrupted": is_corrupt,
                "defects": defects if is_corrupt else [],
                "recommended_tool": "image_recovery" if is_corrupt else "pillow",
                "tool_name": "Image Decoder Engine",
                "tool_purpose": "Recovers color channels and restores visual bitmap."
            }
        }
        corrupted_regions = [r["name"] for r in regions.values() if r["is_corrupted"]]

        if not is_corrupt:
            return {
                "file_type": "IMAGE",
                "corruption_type": cls.CLEAN,
                "category": "Intact Image",
                "confidence": 0.95,
                "confidence_level": "HIGH",
                "is_corrupted": False,
                "can_recover": True,
                "details": "Image header and raster data verified intact.",
                "defects": [],
                "regions": regions,
                "corrupted_regions": [],
                "recommended_tools": ["pillow"],
                "expected_limitations": "No recovery needed."
            }

        return {
            "file_type": "IMAGE",
            "corruption_type": cls.IMAGE_DATA_CORRUPTION,
            "category": "Raster Image Corruption",
            "confidence": 0.88,
            "confidence_level": "HIGH",
            "is_corrupted": True,
            "can_recover": True,
            "details": "; ".join(defects),
            "defects": defects,
            "regions": regions,
            "corrupted_regions": corrupted_regions,
            "recommended_tools": ["image_recovery", "pillow", "jpegtran", "pngcheck"],
            "primary_tool": "image_recovery",
            "expected_limitations": "Truncated scanlines will be stabilized with missing raster data filled with neutral background."
        }

    @classmethod
    def _classify_text(cls, file_path: str, file_size: int, fmt: str) -> Dict[str, Any]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                _ = f.read(4096)
            is_corrupt = False
        except UnicodeDecodeError:
            is_corrupt = True

        regions = {
            "header": {
                "name": "Header",
                "label": "File BOM & Encoding Header",
                "status": "CORRUPTED" if is_corrupt else "INTACT",
                "is_corrupted": is_corrupt,
                "defects": ["Encoding decode error in preamble"] if is_corrupt else [],
                "recommended_tool": "text_recovery" if is_corrupt else "built-in",
                "tool_name": "Encoding Normalizer",
                "tool_purpose": "Normalizes UTF-8/Latin-1/CP1252 byte order marks."
            },
            "body": {
                "name": "Body",
                "label": "Text Stream Content",
                "status": "CORRUPTED" if is_corrupt else "INTACT",
                "is_corrupted": is_corrupt,
                "defects": ["Unicode decode error in UTF-8 mode"] if is_corrupt else [],
                "recommended_tool": "text_recovery" if is_corrupt else "built-in",
                "tool_name": "Text Stream Salvager",
                "tool_purpose": "Heuristically recovers text lines across multiple encodings."
            },
            "reference": {
                "name": "Reference",
                "label": "Delimiter & Syntax Structure",
                "status": "INTACT",
                "is_corrupted": False,
                "defects": [],
                "recommended_tool": "text_recovery",
                "tool_name": "Syntax Checker",
                "tool_purpose": "Validates CSV delimiters or JSON structure."
            },
            "eof": {
                "name": "EOF",
                "label": "End-of-File Termination",
                "status": "INTACT",
                "is_corrupted": False,
                "defects": [],
                "recommended_tool": "text_recovery",
                "tool_name": "Stream Terminator",
                "tool_purpose": "Ensures clean EOF line termination."
            },
            "image": {
                "name": "Image",
                "label": "Embedded Visual Media",
                "status": "INTACT",
                "is_corrupted": False,
                "defects": [],
                "recommended_tool": "pillow",
                "tool_name": "N/A",
                "tool_purpose": "Not applicable for plain text documents."
            }
        }
        corrupted_regions = [r["name"] for r in regions.values() if r["is_corrupted"]]

        if not is_corrupt:
            return {
                "file_type": fmt,
                "corruption_type": cls.CLEAN,
                "category": "Intact Text Document",
                "confidence": 0.95,
                "confidence_level": "HIGH",
                "is_corrupted": False,
                "can_recover": True,
                "details": "UTF-8 encoding validated.",
                "defects": [],
                "regions": regions,
                "corrupted_regions": [],
                "recommended_tools": [],
                "expected_limitations": "Text is intact."
            }

        return {
            "file_type": fmt,
            "corruption_type": "TEXT_ENCODING_CORRUPTION",
            "category": "Encoding / Syntax Corruption",
            "confidence": 0.85,
            "confidence_level": "MEDIUM",
            "is_corrupted": True,
            "can_recover": True,
            "details": "Non-standard byte encoding or syntax corruption detected.",
            "defects": ["Unicode decode error in UTF-8 mode"],
            "regions": regions,
            "corrupted_regions": corrupted_regions,
            "recommended_tools": ["text_recovery"],
            "primary_tool": "text_recovery",
            "expected_limitations": "Multi-codec heuristic normalization engaged."
        }

    @classmethod
    def get_corruption_area(
        cls,
        file_path: str,
        detected_type: str = "auto",
        analysis: Optional[Dict[str, Any]] = None,
        original_filename: str = ""
    ) -> str:
        """
        Determines the corrupted structural regions strictly formatted as:
        Header, Body, Reference, EOF, or Images.
        Multiple regions are joined with commas (e.g. 'Body, Reference').
        """
        ALLOWED_REGIONS = ["Header", "Body", "Reference", "EOF", "Images"]
        SEVERITY_WORDS = {"MINOR", "MODERATE", "SEVERE", "CRITICAL", "NONE", "HEALTHY", "UNRECOVERABLE", "UNKNOWN"}

        def normalize_region_name(raw: str) -> Optional[str]:
            if not raw or not isinstance(raw, str):
                return None
            clean = raw.strip()
            if clean.upper() in SEVERITY_WORDS:
                return None
            lower = clean.lower()
            if "header" in lower or "magic" in lower or "bom" in lower:
                return "Header"
            if "body" in lower or "stream" in lower or "content" in lower or "object" in lower or "xml" in lower or "sheet" in lower or "slide" in lower:
                return "Body"
            if "xref" in lower or "reference" in lower or "trailer" in lower or "startxref" in lower or "catalog" in lower or "rel" in lower:
                return "Reference"
            if "eof" in lower or "truncat" in lower or "end_of_file" in lower or "terminal" in lower:
                return "EOF"
            if "image" in lower or "raster" in lower or "jpeg" in lower or "png" in lower or "picture" in lower:
                return "Images"
            return None

        found_regions = set()

        # 1. Inspect granular classification from classifier if file exists
        if file_path and os.path.exists(file_path):
            try:
                classif = cls.classify(file_path, detected_type)
                for r_name in classif.get("corrupted_regions", []):
                    norm = normalize_region_name(r_name)
                    if norm:
                        found_regions.add(norm)

                for reg_key, reg_info in classif.get("regions", {}).items():
                    if reg_info.get("is_corrupted") or reg_info.get("status") == "CORRUPTED":
                        norm = normalize_region_name(reg_info.get("name") or reg_key)
                        if norm:
                            found_regions.add(norm)
            except Exception:
                pass

        # 2. If not found from direct file classification, inspect analysis dictionary
        if not found_regions and analysis:
            c_classif = analysis.get("corruption_classification") or analysis.get("raw_analysis", {}).get("corruption_classification")
            if c_classif and isinstance(c_classif.get("regions"), dict):
                for reg_key, reg_info in c_classif["regions"].items():
                    if reg_info.get("is_corrupted") or reg_info.get("status") == "CORRUPTED":
                        norm = normalize_region_name(reg_info.get("name") or reg_key)
                        if norm:
                            found_regions.add(norm)

            if not found_regions:
                s_matrix = analysis.get("structure_matrix", {})
                if isinstance(s_matrix, dict):
                    for layer, l_info in s_matrix.items():
                        if isinstance(l_info, dict) and l_info.get("status") in ["CORRUPTED", "PARTIALLY VALID"]:
                            norm = normalize_region_name(layer)
                            if norm:
                                found_regions.add(norm)

            if not found_regions:
                c_dict = analysis.get("corruption", {})
                if isinstance(c_dict, dict):
                    if c_dict.get("header"):
                        found_regions.add("Header")
                    if c_dict.get("body") or c_dict.get("zip") or c_dict.get("xml"):
                        found_regions.add("Body")
                    if c_dict.get("xref") or c_dict.get("trailer"):
                        found_regions.add("Reference")
                    if c_dict.get("eof"):
                        found_regions.add("EOF")
                    if c_dict.get("image") or c_dict.get("images"):
                        found_regions.add("Images")

            if not found_regions:
                for cr in analysis.get("corruption_regions", []):
                    if isinstance(cr, dict) and cr.get("status") != "valid":
                        norm = normalize_region_name(cr.get("region") or cr.get("name", ""))
                        if norm:
                            found_regions.add(norm)

        # 3. Inspect filename hints if still empty
        fname = (original_filename or (os.path.basename(file_path) if file_path else "")).lower()
        if not found_regions and fname:
            if "header" in fname:
                found_regions.add("Header")
            if "body" in fname:
                found_regions.add("Body")
            if "xref" in fname or "reference" in fname:
                found_regions.add("Reference")
            if "eof" in fname or "truncat" in fname:
                found_regions.add("EOF")
            if "image" in fname or "img" in fname:
                found_regions.add("Images")

        # 4. If still empty, determine based on corruption status
        is_corrupt = False
        if analysis:
            is_corrupt = analysis.get("integrity", {}).get("status") == "CORRUPTED" or analysis.get("is_corrupted", False)

        if not found_regions:
            if is_corrupt:
                fmt_upper = (detected_type or "").upper()
                if "PDF" in fmt_upper:
                    found_regions.add("Reference")
                elif "IMAGE" in fmt_upper or any(ext in fname for ext in [".jpg", ".jpeg", ".png", ".webp"]):
                    found_regions.add("Images")
                else:
                    found_regions.add("Body")
            else:
                return "None (Intact)"

        ordered = [r for r in ALLOWED_REGIONS if r in found_regions]
        return ", ".join(ordered) if ordered else "Body"


def classify_corruption(file_path: str, detected_type: str = "auto") -> Dict[str, Any]:
    """Top-level functional interface conforming to system specification."""
    return CorruptionClassifier.classify(file_path, detected_type)

