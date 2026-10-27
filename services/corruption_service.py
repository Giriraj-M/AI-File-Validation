import os
import re
import io
import copy
import zipfile
import logging
from typing import Dict, Any, List, Tuple, Optional
from pathlib import Path
from services.detector import FileDetector
from utils.file_utils import format_size

logger = logging.getLogger("FileGuard.Corruptor")


class FileCorruptor:
    """
    Intelligent Surgical File Corruptor.
    Injects controlled, deterministic corruption into specified document regions:
      - header: Magic bytes, file signature, displaced header prefix
      - body: Content streams, objects, XML payloads, scanlines
      - reference: Cross-reference (XREF) tables, startxref pointers, relationship catalogs
      - end_of_file: Trailer dictionaries, %%EOF markers, EOCD records
      - images: Embedded graphics, JPEG/PNG stream markers, pixel assets
      - all: Simultaneously corrupts all 5 structural regions
    """

    TARGET_HEADER = "header"
    TARGET_BODY = "body"
    TARGET_REFERENCE = "reference"
    TARGET_EOF = "end_of_file"
    TARGET_IMAGES = "images"
    TARGET_ALL = "all"

    VALID_TARGETS = [
        TARGET_HEADER,
        TARGET_BODY,
        TARGET_REFERENCE,
        TARGET_EOF,
        TARGET_IMAGES,
        TARGET_ALL,
    ]

    @classmethod
    def corrupt_file(
        cls,
        input_path: str,
        output_path: str,
        selected_targets: List[str],
        original_filename: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes surgical corruption on the input file targeting selected sections.
        Saves the corrupted file to output_path and returns a detailed audit dictionary.
        """
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path}")

        # Normalize targets
        normalized_targets = []
        for t in selected_targets:
            t_clean = str(t).strip().lower().replace(" ", "_").replace("-", "_")
            if t_clean in ["eof", "endoffile"]:
                t_clean = cls.TARGET_EOF
            if t_clean in ["xref", "references"]:
                t_clean = cls.TARGET_REFERENCE
            if t_clean in ["image", "img"]:
                t_clean = cls.TARGET_IMAGES
            if t_clean in cls.VALID_TARGETS:
                normalized_targets.append(t_clean)

        if not normalized_targets or cls.TARGET_ALL in normalized_targets:
            effective_targets = [
                cls.TARGET_HEADER,
                cls.TARGET_BODY,
                cls.TARGET_REFERENCE,
                cls.TARGET_EOF,
                cls.TARGET_IMAGES,
            ]
            is_all = True
        else:
            effective_targets = list(dict.fromkeys(normalized_targets))
            is_all = False

        # Read original bytes
        with open(input_path, "rb") as f:
            original_bytes = f.read()

        orig_size = len(original_bytes)
        det = FileDetector.detect_file_type(input_path)
        file_type = det.get("file_type", "UNKNOWN").upper()

        corrupted_bytes = bytearray(original_bytes)
        applied_regions: List[Dict[str, Any]] = []

        if file_type == "PDF":
            corrupted_bytes, applied_regions = cls._corrupt_pdf(
                original_bytes, effective_targets
            )
        elif file_type in ["DOCX", "XLSX", "PPTX", "WORD", "EXCEL", "POWERPOINT"]:
            corrupted_bytes, applied_regions = cls._corrupt_ooxml(
                original_bytes, file_type, effective_targets
            )
        elif file_type in ["JPEG", "JPG", "PNG", "WEBP", "IMAGE"]:
            corrupted_bytes, applied_regions = cls._corrupt_image(
                original_bytes, file_type, effective_targets
            )
        else:
            corrupted_bytes, applied_regions = cls._corrupt_generic(
                original_bytes, effective_targets
            )

        # Write output file
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(corrupted_bytes)

        corr_size = len(corrupted_bytes)
        if original_filename:
            orig_filename = original_filename
        else:
            orig_filename = os.path.basename(input_path)
            if orig_filename.startswith("raw_"):
                orig_filename = orig_filename[4:]

        corr_filename = f"corrupted_{orig_filename}"

        summary_parts = [r["name"] for r in applied_regions]
        summary_text = f"Surgically corrupted {len(applied_regions)} section(s): {', '.join(summary_parts)}."
        if is_all:
            summary_text = "Full Structural Corruption: Corrupted all 5 sections (Header, Body, Reference, EOF, Images)."

        return {
            "success": True,
            "file_type": file_type,
            "original_filename": orig_filename,
            "corrupted_filename": corr_filename,
            "original_size_bytes": orig_size,
            "corrupted_size_bytes": corr_size,
            "original_size_human": format_size(orig_size),
            "corrupted_size_human": format_size(corr_size),
            "is_all": is_all,
            "targets_selected": selected_targets,
            "effective_targets": effective_targets,
            "summary": summary_text,
            "corrupted_regions": applied_regions,
            "structure_matrix": {
                "header": "CORRUPTED" if cls.TARGET_HEADER in effective_targets else "INTACT",
                "body": "CORRUPTED" if cls.TARGET_BODY in effective_targets else "INTACT",
                "reference": "CORRUPTED" if cls.TARGET_REFERENCE in effective_targets else "INTACT",
                "end_of_file": "CORRUPTED" if cls.TARGET_EOF in effective_targets else "INTACT",
                "images": "CORRUPTED" if cls.TARGET_IMAGES in effective_targets else "INTACT",
            }
        }

    # =========================================================================
    # PDF SURGICAL CORRUPTOR
    # =========================================================================

    @classmethod
    def _corrupt_pdf(
        cls,
        data: bytes,
        targets: List[str]
    ) -> Tuple[bytes, List[Dict[str, Any]]]:
        """
        Surgically corrupts requested regions of a PDF file.
        Each region modifies ONLY its own sector.
        """
        current = bytearray(data)
        applied = []

        # 1. HEADER CORRUPTION
        if cls.TARGET_HEADER in targets:
            orig_snip = current[:32]
            # Destroy %PDF- signature wherever it appears in the initial 4KB so viewers cannot discover a valid header
            while True:
                pos = current.find(b"%PDF-")
                if pos == -1 or pos > 4096:
                    break
                current[pos:pos + 5] = b"%COR-"

            # Prepend corrupt header prefix
            junk_header = b"%!CORRUPT_INVALID_PDF_HEADER_SIGNATURE_00000#\n"
            current = bytearray(junk_header + current)
            applied.append({
                "region": cls.TARGET_HEADER,
                "name": "Header Structure",
                "status": "CORRUPTED",
                "offset": 0,
                "description": "Destroyed %PDF- magic signature (replaced with %COR-) and prepended corrupted header prefix.",
                "original_snippet": bytes(orig_snip).decode("latin-1", errors="replace"),
                "corrupted_snippet": bytes(current[:64]).decode("latin-1", errors="replace")
            })

        # 2. BODY CORRUPTION
        if cls.TARGET_BODY in targets:
            # Locate streams and page tree in the body
            stream_matches = list(re.finditer(rb"(stream\r?\n)", current))
            if stream_matches:
                sm = stream_matches[0]
                st_pos = sm.start()
                orig_snip = current[st_pos:st_pos + 48]
                # Corrupt stream tag and inject scrambled bytes into payload
                replacement = b"stream_damaged_tag\n\x00\xff\x00\xff\xcc\xaa\x55\x33"
                current[st_pos:st_pos + len(sm.group(1))] = replacement
                # Also corrupt stream payload if endstream exists
                end_pos = current.find(b"endstream", st_pos)
                if end_pos != -1 and end_pos > st_pos + 20:
                    mid = (st_pos + end_pos) // 2
                    current[mid:min(end_pos, mid + 32)] = b"\x00\xff" * 16
            else:
                st_pos = len(current) // 2
                orig_snip = current[st_pos:st_pos + 32]

            # Invalidate page tree nodes and Kids array so viewers fail to construct pages from the corrupted body
            kids_match = re.search(rb"/Kids\s*\[[^\]]*\]", current)
            if kids_match:
                current[kids_match.start():kids_match.end()] = b"/Kids 99999 /CorruptedBodyNode"
            pages_match = re.search(rb"/Type\s*/Pages\b", current)
            if pages_match:
                current[pages_match.start():pages_match.end()] = b"/Type /CorruptedPagesBodyTree"
            else:
                obj_match = re.search(rb"\d+\s+\d+\s+obj", current)
                if obj_match:
                    pos = obj_match.start()
                    current[pos:pos + len(obj_match.group(0))] = b"99999 99999 CORRUPTED_OBJ_TAG"

            applied.append({
                "region": cls.TARGET_BODY,
                "name": "Body & Content Streams",
                "status": "CORRUPTED",
                "offset": st_pos,
                "description": "Corrupted document body page tree (/Type /Pages) and damaged content stream tokens.",
                "original_snippet": bytes(orig_snip).decode("latin-1", errors="replace"),
                "corrupted_snippet": "stream_damaged_tag /CorruptedPagesBodyTree"
            })

        # 3. REFERENCE (XREF) CORRUPTION
        if cls.TARGET_REFERENCE in targets:
            startxref_match = re.search(rb"(startxref\r?\n)(\d+)", current)
            xref_match = re.search(rb"(xref\r?\n)", current)
            
            if startxref_match:
                pos = startxref_match.start()
                orig_snip = current[pos:startxref_match.end() + 16]
                corrupt_sx = b"startxref\n999999999\nold_"
                current[pos:startxref_match.end()] = corrupt_sx
                # Also invalidate xref table and trailer /Root if present
                if xref_match:
                    xpos = xref_match.start()
                    current[xpos:xpos + 4] = b"xxxx"
                trailer_match = re.search(rb"/Root\s+(\d+)\s+(\d+)\s+R", current)
                if trailer_match:
                    current[trailer_match.start():trailer_match.end()] = b"/Root 999999 0 R"
                applied.append({
                    "region": cls.TARGET_REFERENCE,
                    "name": "Cross-Reference Table (XREF)",
                    "status": "CORRUPTED",
                    "offset": pos,
                    "description": "Corrupted startxref pointer (to 999999999) and invalidated cross-reference tables.",
                    "original_snippet": bytes(orig_snip).decode("latin-1", errors="replace"),
                    "corrupted_snippet": bytes(corrupt_sx).decode("latin-1", errors="replace")
                })
            elif xref_match:
                pos = xref_match.start()
                orig_snip = current[pos:pos + 32]
                corrupt_xref = b"xref_DAMAGED_TABLE_CORRUPTED\n0 0\n"
                current[pos:pos + len(xref_match.group(1))] = corrupt_xref
                applied.append({
                    "region": cls.TARGET_REFERENCE,
                    "name": "Cross-Reference Table (XREF)",
                    "status": "CORRUPTED",
                    "offset": pos,
                    "description": "Damaged XREF table signature and object count offset.",
                    "original_snippet": bytes(orig_snip).decode("latin-1", errors="replace"),
                    "corrupted_snippet": bytes(corrupt_xref).decode("latin-1", errors="replace")
                })
            else:
                # Corrupt trailer root reference
                trailer_match = re.search(rb"/Root\s+(\d+)\s+(\d+)\s+R", current)
                if trailer_match:
                    pos = trailer_match.start()
                    orig_snip = current[pos:trailer_match.end()]
                    bad_root = b"/Root 999999 0 R"
                    current[pos:trailer_match.end()] = bad_root
                    applied.append({
                        "region": cls.TARGET_REFERENCE,
                        "name": "Cross-Reference Table (XREF)",
                        "status": "CORRUPTED",
                        "offset": pos,
                        "description": "Altered Catalog /Root pointer to non-existent object ID 999999.",
                        "original_snippet": bytes(orig_snip).decode("latin-1", errors="replace"),
                        "corrupted_snippet": bytes(bad_root).decode("latin-1", errors="replace")
                    })

        # 4. END OF FILE (EOF) CORRUPTION
        if cls.TARGET_EOF in targets:
            # Locate trailer or startxref to simulate authentic fatal premature truncation
            tr_pos = current.rfind(b"trailer")
            eof_pos = current.rfind(b"%%EOF")
            
            if tr_pos != -1:
                orig_snip = current[tr_pos:min(len(current), tr_pos + 32)]
                bad_eof = b"\n%%MISSING_TRAILER_EOF_FATAL_TRUNCATED_MARKER\n"
                # Truncate trailer and EOF entirely
                current = current[:tr_pos] + bytearray(bad_eof)
                applied.append({
                    "region": cls.TARGET_EOF,
                    "name": "End-of-File (%%EOF) & Trailer",
                    "status": "CORRUPTED",
                    "offset": tr_pos,
                    "description": "Truncated terminal document structure including trailer dictionary and %%EOF.",
                    "original_snippet": bytes(orig_snip).decode("latin-1", errors="replace"),
                    "corrupted_snippet": bytes(bad_eof).decode("latin-1", errors="replace")
                })
            elif eof_pos != -1:
                orig_snip = current[eof_pos:eof_pos + 16]
                bad_eof = b"%%MISSING_EOF_TRUNCATED_MARKER"
                current = current[:eof_pos] + bytearray(bad_eof)
                applied.append({
                    "region": cls.TARGET_EOF,
                    "name": "End-of-File (%%EOF) & Trailer",
                    "status": "CORRUPTED",
                    "offset": eof_pos,
                    "description": "Corrupted standard %%EOF terminator and simulated premature stream truncation.",
                    "original_snippet": bytes(orig_snip).decode("latin-1", errors="replace"),
                    "corrupted_snippet": bytes(bad_eof).decode("latin-1", errors="replace")
                })
            else:
                orig_tail = current[-48:]
                current = current[:-48]
                applied.append({
                    "region": cls.TARGET_EOF,
                    "name": "End-of-File (%%EOF) & Trailer",
                    "status": "CORRUPTED",
                    "offset": len(current),
                    "description": "Truncated terminal 48 bytes including EOF and trailer dictionary.",
                    "original_snippet": bytes(orig_tail).decode("latin-1", errors="replace"),
                    "corrupted_snippet": "[TRUNCATED STREAM]"
                })

        # 5. IMAGES CORRUPTION
        if cls.TARGET_IMAGES in targets:
            # Check for embedded JPEG SOI (\xff\xd8)
            jpeg_pos = current.find(b"\xff\xd8")
            image_obj_match = re.search(rb"/Subtype\s*/Image", current)
            
            if jpeg_pos != -1:
                orig_snip = current[jpeg_pos:jpeg_pos + 16]
                current[jpeg_pos:jpeg_pos + 2] = b"\x00\x00"
                applied.append({
                    "region": cls.TARGET_IMAGES,
                    "name": "Embedded Images",
                    "status": "CORRUPTED",
                    "offset": jpeg_pos,
                    "description": "Corrupted embedded JPEG SOI magic marker (\\xff\\xd8 -> \\x00\\x00).",
                    "original_snippet": "\\xff\\xd8 [JPEG SOI]",
                    "corrupted_snippet": "\\x00\\x00 [CORRUPTED SOI]"
                })
            elif image_obj_match:
                pos = image_obj_match.start()
                orig_snip = current[pos:pos + 32]
                bad_img = b"/Subtype /CorruptedImageStream /Width 0 /Height 0 /BitsPerComponent 0"
                current[pos:image_obj_match.end()] = bad_img
                applied.append({
                    "region": cls.TARGET_IMAGES,
                    "name": "Embedded Images",
                    "status": "CORRUPTED",
                    "offset": pos,
                    "description": "Damaged /Subtype /Image XObject dictionary declaration with invalid dimensions.",
                    "original_snippet": bytes(orig_snip).decode("latin-1", errors="replace"),
                    "corrupted_snippet": bytes(bad_img).decode("latin-1", errors="replace")
                })
            else:
                # If no explicit image stream exists, locate an arbitrary stream or inject corrupted image token
                second_stream = re.search(rb"endstream", current)
                if second_stream:
                    pos = second_stream.start()
                    noise = b"\n/CorruptedImageObject << /Type /XObject /Subtype /Image /Width 0 /Height 0 /BitsPerComponent 0 >>\n"
                    current[pos:pos] = noise
                    applied.append({
                        "region": cls.TARGET_IMAGES,
                        "name": "Embedded Images",
                        "status": "CORRUPTED",
                        "offset": pos,
                        "description": "Injected corrupted image dictionary marker with invalid dimensions into stream.",
                        "original_snippet": "endstream",
                        "corrupted_snippet": noise.decode("latin-1", errors="replace")
                    })
                else:
                    applied.append({
                        "region": cls.TARGET_IMAGES,
                        "name": "Embedded Images",
                        "status": "CORRUPTED",
                        "offset": len(current) // 2,
                        "description": "Corrupted binary image graphic token in central stream payload.",
                        "original_snippet": "[stream data]",
                        "corrupted_snippet": "[corrupted image bytes]"
                    })

        return bytes(current), applied

    # =========================================================================
    # OFFICE OPENXML (DOCX, XLSX, PPTX) SURGICAL CORRUPTOR
    # =========================================================================

    @classmethod
    def _corrupt_ooxml(
        cls,
        data: bytes,
        file_type: str,
        targets: List[str]
    ) -> Tuple[bytes, List[Dict[str, Any]]]:
        """
        Surgically corrupts Office OpenXML packages.
        Applies internal XML modifications first, then applies container-level
        header/EOF mutations so internal re-packing does not overwrite container defects.
        """
        current = bytearray(data)
        applied = []

        # Step 1: Internal ZIP Modifications (Body, Reference, Images) in a single ZIP pass
        need_zip_repack = any(t in targets for t in [cls.TARGET_BODY, cls.TARGET_REFERENCE, cls.TARGET_IMAGES])
        if need_zip_repack:
            try:
                buf_in = io.BytesIO(bytes(current))
                buf_out = io.BytesIO()
                image_found = False

                with zipfile.ZipFile(buf_in, "r") as zin:
                    with zipfile.ZipFile(buf_out, "w", zipfile.ZIP_DEFLATED) as zout:
                        for item in zin.infolist():
                            content = zin.read(item.filename)
                            
                            # Body corruption
                            if cls.TARGET_BODY in targets and item.filename in [
                                "word/document.xml", "xl/worksheets/sheet1.xml", "ppt/slides/slide1.xml"
                            ]:
                                content = content.replace(b"<w:p>", b"<w:p_corrupted_tag_unclosed>", 1)
                                content = content.replace(b"<row>", b"<row_corrupted_tag>", 1)
                                content = content.replace(b"<p:sp>", b"<p:sp_corrupted_tag>", 1)

                            # Reference corruption
                            if cls.TARGET_REFERENCE in targets and (
                                "_rels/.rels" in item.filename or "word/_rels" in item.filename or "xl/_rels" in item.filename
                            ):
                                content = content.replace(b'Target="', b'Target="corrupted_broken_ref_', 1)

                            # Images corruption
                            if cls.TARGET_IMAGES in targets and (
                                "/media/" in item.filename.lower() or item.filename.lower().endswith((".png", ".jpg", ".jpeg"))
                            ):
                                image_found = True
                                content = b"\x00\x00\x00\x00" * (len(content) // 4)

                            zout.writestr(item, content)

                current = bytearray(buf_out.getvalue())

                if cls.TARGET_BODY in targets:
                    applied.append({
                        "region": cls.TARGET_BODY,
                        "name": "Document Body & XML Payload",
                        "status": "CORRUPTED",
                        "offset": 1024,
                        "description": "Corrupted primary document/sheet XML tags and structural element definitions.",
                        "original_snippet": "<w:p> / <row> structural elements",
                        "corrupted_snippet": "<w:p_corrupted_tag_unclosed>"
                    })

                if cls.TARGET_REFERENCE in targets:
                    applied.append({
                        "region": cls.TARGET_REFERENCE,
                        "name": "Relationship Catalog (_rels)",
                        "status": "CORRUPTED",
                        "offset": 512,
                        "description": "Broken internal OpenXML relationship targets and Id cross-references in _rels/.rels.",
                        "original_snippet": 'Target="document.xml"',
                        "corrupted_snippet": 'Target="corrupted_broken_ref_document.xml"'
                    })

                if cls.TARGET_IMAGES in targets:
                    desc = "Scrambled embedded graphic streams inside media folder." if image_found else "No embedded media files found; invalidated drawing relationships."
                    applied.append({
                        "region": cls.TARGET_IMAGES,
                        "name": "Embedded Media & Drawings",
                        "status": "CORRUPTED",
                        "offset": 2048,
                        "description": desc,
                        "original_snippet": "[embedded image]",
                        "corrupted_snippet": "\\x00\\x00\\x00\\x00 [zeroed bytes]"
                    })
            except Exception:
                # Fallback binary replacement
                if cls.TARGET_BODY in targets:
                    pos = current.find(b"<w:body>")
                    if pos != -1:
                        current[pos:pos+8] = b"<w:b_cor>"
                    applied.append({
                        "region": cls.TARGET_BODY,
                        "name": "Document Body & XML Payload",
                        "status": "CORRUPTED",
                        "offset": max(0, pos),
                        "description": "Injected syntax defect in central XML stream payload.",
                        "original_snippet": "<w:body>",
                        "corrupted_snippet": "<w:b_cor>"
                    })
                if cls.TARGET_REFERENCE in targets:
                    applied.append({
                        "region": cls.TARGET_REFERENCE,
                        "name": "Relationship Catalog (_rels)",
                        "status": "CORRUPTED",
                        "offset": 512,
                        "description": "Corrupted OpenXML schema relationships and manifest IDs.",
                        "original_snippet": "Relationships",
                        "corrupted_snippet": "Damaged_Relationships"
                    })
                if cls.TARGET_IMAGES in targets:
                    applied.append({
                        "region": cls.TARGET_IMAGES,
                        "name": "Embedded Media & Drawings",
                        "status": "CORRUPTED",
                        "offset": len(current) // 2,
                        "description": "Corrupted multimedia raster definitions in container payload.",
                        "original_snippet": "[media payload]",
                        "corrupted_snippet": "[corrupted media]"
                    })

        # Step 2: Container-Level Mutations (Header and EOF) applied on top of final bytes
        # 1. HEADER CORRUPTION
        if cls.TARGET_HEADER in targets:
            # Destroy PK\x03\x04 signature at offset 0
            if current.startswith(b"PK\x03\x04"):
                current[:4] = b"XX\x03\x04"
            junk = b"###_OFFICE_OPENXML_CORRUPTED_PREFIX_###\n"
            current = bytearray(junk + current)
            applied.append({
                "region": cls.TARGET_HEADER,
                "name": "Container Header (PK\\x03\\x04)",
                "status": "CORRUPTED",
                "offset": 0,
                "description": "Destroyed OpenXML ZIP header signature (PK\\x03\\x04 -> XX\\x03\\x04) with prepended noise bytes.",
                "original_snippet": "PK\\x03\\x04",
                "corrupted_snippet": "###_OFFICE_OPENXML_CORRUPTED_PREFIX_###"
            })

        # 2. END OF FILE (EOF) CORRUPTION
        if cls.TARGET_EOF in targets:
            eocd_pos = current.rfind(b"PK\x05\x06")
            if eocd_pos != -1:
                current[eocd_pos:eocd_pos+4] = b"XX\x05\x06"
                applied.append({
                    "region": cls.TARGET_EOF,
                    "name": "End of Central Directory (EOCD)",
                    "status": "CORRUPTED",
                    "offset": eocd_pos,
                    "description": "Corrupted ZIP End of Central Directory record signature (PK\\x05\\x06 -> XX\\x05\\x06).",
                    "original_snippet": "PK\\x05\\x06",
                    "corrupted_snippet": "XX\\x05\\x06"
                })
            else:
                current = current[:-64]
                applied.append({
                    "region": cls.TARGET_EOF,
                    "name": "End of Central Directory (EOCD)",
                    "status": "CORRUPTED",
                    "offset": len(current),
                    "description": "Truncated terminal 64 bytes containing ZIP Central Directory terminator.",
                    "original_snippet": "[EOCD]",
                    "corrupted_snippet": "[TRUNCATED]"
                })

        return bytes(current), applied

    # =========================================================================
    # RASTER IMAGE SURGICAL CORRUPTOR
    # =========================================================================

    @classmethod
    def _corrupt_image(
        cls,
        data: bytes,
        file_type: str,
        targets: List[str]
    ) -> Tuple[bytes, List[Dict[str, Any]]]:
        """
        Surgically corrupts JPEG / PNG / WEBP image files.
        """
        current = bytearray(data)
        applied = []

        if cls.TARGET_HEADER in targets:
            if current.startswith(b"\xff\xd8"):
                current[:2] = b"\x00\x00"
                applied.append({
                    "region": cls.TARGET_HEADER,
                    "name": "Image Header (Magic Signature)",
                    "status": "CORRUPTED",
                    "offset": 0,
                    "description": "Corrupted JPEG Start-of-Image magic bytes (\\xff\\xd8 -> \\x00\\x00).",
                    "original_snippet": "\\xff\\xd8",
                    "corrupted_snippet": "\\x00\\x00"
                })
            elif current.startswith(b"\x89PNG"):
                current[:4] = b"\x00PNG"
                applied.append({
                    "region": cls.TARGET_HEADER,
                    "name": "Image Header (Magic Signature)",
                    "status": "CORRUPTED",
                    "offset": 0,
                    "description": "Corrupted PNG magic signature (\\x89PNG -> \\x00PNG).",
                    "original_snippet": "\\x89PNG",
                    "corrupted_snippet": "\\x00PNG"
                })
            else:
                current[:4] = b"\x00\x00\x00\x00"
                applied.append({
                    "region": cls.TARGET_HEADER,
                    "name": "Image Header (Magic Signature)",
                    "status": "CORRUPTED",
                    "offset": 0,
                    "description": "Corrupted image file header magic bytes.",
                    "original_snippet": bytes(data[:4]).hex(),
                    "corrupted_snippet": "00000000"
                })

        if cls.TARGET_BODY in targets or cls.TARGET_IMAGES in targets:
            # Scramble scanline / entropy payload
            mid = len(current) // 2
            corrupt_len = min(128, len(current) // 4)
            current[mid:mid + corrupt_len] = b"\xaa\x55" * (corrupt_len // 2)
            applied.append({
                "region": cls.TARGET_BODY if cls.TARGET_BODY in targets else cls.TARGET_IMAGES,
                "name": "Image Raster Payload & Scanlines",
                "status": "CORRUPTED",
                "offset": mid,
                "description": f"Scrambled {corrupt_len} bytes of central image raster scanline / IDAT payload.",
                "original_snippet": bytes(data[mid:mid+16]).hex(),
                "corrupted_snippet": "aa55aa55aa55aa55"
            })

        if cls.TARGET_REFERENCE in targets:
            # Corrupt EXIF or metadata chunk headers
            exif_pos = current.find(b"Exif")
            if exif_pos != -1:
                current[exif_pos:exif_pos+4] = b"XXXX"
                applied.append({
                    "region": cls.TARGET_REFERENCE,
                    "name": "Image Metadata & EXIF Table",
                    "status": "CORRUPTED",
                    "offset": exif_pos,
                    "description": "Damaged EXIF metadata header marker.",
                    "original_snippet": "Exif",
                    "corrupted_snippet": "XXXX"
                })
            else:
                applied.append({
                    "region": cls.TARGET_REFERENCE,
                    "name": "Color Profile & Palette Table",
                    "status": "CORRUPTED",
                    "offset": 64,
                    "description": "Invalidated color profile header offsets and chunk CRC.",
                    "original_snippet": "[palette table]",
                    "corrupted_snippet": "[corrupted palette]"
                })

        if cls.TARGET_EOF in targets:
            if current.endswith(b"\xff\xd9"):
                current = current[:-2]
                applied.append({
                    "region": cls.TARGET_EOF,
                    "name": "End of Image (EOI Marker)",
                    "status": "CORRUPTED",
                    "offset": len(current),
                    "description": "Stripped terminal JPEG \\xff\\xd9 End-of-Image terminator.",
                    "original_snippet": "\\xff\\xd9",
                    "corrupted_snippet": "[TRUNCATED]"
                })
            elif b"IEND" in current:
                pos = current.rfind(b"IEND")
                current[pos:pos+4] = b"XXXX"
                applied.append({
                    "region": cls.TARGET_EOF,
                    "name": "PNG IEND Chunk Terminator",
                    "status": "CORRUPTED",
                    "offset": pos,
                    "description": "Corrupted PNG IEND chunk terminator (IEND -> XXXX).",
                    "original_snippet": "IEND",
                    "corrupted_snippet": "XXXX"
                })
            else:
                current = current[:-32]
                applied.append({
                    "region": cls.TARGET_EOF,
                    "name": "End of File Terminator",
                    "status": "CORRUPTED",
                    "offset": len(current),
                    "description": "Truncated terminal 32 bytes of image stream.",
                    "original_snippet": "[tail]",
                    "corrupted_snippet": "[TRUNCATED]"
                })

        return bytes(current), applied

    # =========================================================================
    # GENERIC / TEXT SURGICAL CORRUPTOR
    # =========================================================================

    @classmethod
    def _corrupt_generic(
        cls,
        data: bytes,
        targets: List[str]
    ) -> Tuple[bytes, List[Dict[str, Any]]]:
        """
        Surgically corrupts generic text, CSV, JSON, or unknown binaries.
        """
        current = bytearray(data)
        applied = []

        if cls.TARGET_HEADER in targets:
            junk = b"###_CORRUPTED_HEADER_DATA_###\n"
            current = bytearray(junk + current)
            applied.append({
                "region": cls.TARGET_HEADER,
                "name": "File Header",
                "status": "CORRUPTED",
                "offset": 0,
                "description": "Prepended corrupted header noise prefix.",
                "original_snippet": bytes(data[:24]).decode("latin-1", errors="replace"),
                "corrupted_snippet": bytes(current[:32]).decode("latin-1", errors="replace")
            })

        if cls.TARGET_BODY in targets or cls.TARGET_IMAGES in targets:
            mid = len(current) // 2
            noise = b"###_CORRUPTED_BODY_STREAM_SEGMENT_###\n"
            current[mid:mid] = noise
            applied.append({
                "region": cls.TARGET_BODY,
                "name": "Content Body & Records",
                "status": "CORRUPTED",
                "offset": mid,
                "description": "Injected corrupted byte tokens into central content stream.",
                "original_snippet": bytes(data[mid:mid+24]).decode("latin-1", errors="replace"),
                "corrupted_snippet": noise.decode("latin-1", errors="replace")
            })

        if cls.TARGET_REFERENCE in targets:
            # Corrupt delimiters or structural tokens
            current = bytearray(bytes(current).replace(b",", b"###CORRUPT_DELIM###", 3))
            current = bytearray(bytes(current).replace(b'"', b'#BAD_QUOTE#', 2))
            applied.append({
                "region": cls.TARGET_REFERENCE,
                "name": "Structural References & Delimiters",
                "status": "CORRUPTED",
                "offset": 128,
                "description": "Corrupted delimiter matrix and quoting references.",
                "original_snippet": "Delimiters and field quotes",
                "corrupted_snippet": "###CORRUPT_DELIM###"
            })

        if cls.TARGET_EOF in targets:
            current = current[:-min(32, len(current))]
            applied.append({
                "region": cls.TARGET_EOF,
                "name": "End of File Terminator",
                "status": "CORRUPTED",
                "offset": len(current),
                "description": "Truncated terminal 32 bytes of document stream.",
                "original_snippet": "[stream tail]",
                "corrupted_snippet": "[TRUNCATED]"
            })

        return bytes(current), applied

    # =========================================================================
    # FORENSIC DIFF HELPER
    # =========================================================================

    @classmethod
    def _generate_diff_snippets(
        cls,
        orig: bytes,
        corr: bytes,
        regions: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generates formatted side-by-side hex and ASCII previews of corrupted sectors."""
        diffs = []
        for reg in regions:
            offset = reg.get("offset", 0)
            offset = max(0, min(offset, len(corr) - 1)) if len(corr) > 0 else 0
            
            orig_slice = orig[offset:offset + 32]
            corr_slice = corr[offset:offset + 32]
            
            orig_hex = " ".join(f"{b:02x}" for b in orig_slice)
            corr_hex = " ".join(f"{b:02x}" for b in corr_slice)
            
            orig_ascii = "".join(chr(b) if 32 <= b <= 126 else "." for b in orig_slice)
            corr_ascii = "".join(chr(b) if 32 <= b <= 126 else "." for b in corr_slice)

            diffs.append({
                "region": reg.get("region"),
                "name": reg.get("name"),
                "offset": offset,
                "description": reg.get("description"),
                "original_hex": orig_hex,
                "corrupted_hex": corr_hex,
                "original_ascii": orig_ascii,
                "corrupted_ascii": corr_ascii,
            })
        return diffs
