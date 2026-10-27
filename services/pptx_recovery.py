import os
import io
import re
import zipfile
import zlib
import logging
from typing import Dict, Any, List, Optional
import xml.etree.ElementTree as ET

try:
    from pptx import Presentation
    from pptx.util import Inches, Pt
except ImportError:
    Presentation = None

logger = logging.getLogger("FileGuard.PPTXRecovery")

class PPTXRecoveryEngine:
    """
    Deterministic Multi-Strategy PPTX Recovery Engine.
    Repairs broken OpenXML PowerPoint presentations:
      Strategy 1: ZIP Header Realignment & Direct python-pptx Load
      Strategy 2: Archive Stream Decompression & Slide XML Reassembly
      Strategy 3: Slide Text & Shape Harvester + python-pptx Presentation Synthesis
    """

    @classmethod
    def recover(cls, corrupted_path: str, output_path: str) -> Dict[str, Any]:
        if not os.path.exists(corrupted_path):
            return {
                "success": False,
                "strategy": "none",
                "error": "Source file not found",
                "status": "FAILED"
            }

        file_size = os.path.getsize(corrupted_path)
        if file_size == 0:
            return {
                "success": False,
                "strategy": "none",
                "error": "File is empty (0 bytes). Recovery impossible.",
                "status": "UNRECOVERABLE"
            }

        with open(corrupted_path, "rb") as f:
            raw_data = f.read()

        if not (b"PK" in raw_data or b"presentation" in raw_data or b"slide" in raw_data or b"<a:t" in raw_data or b"<p:sp" in raw_data):
            return {
                "success": False,
                "strategy": "none",
                "error": "Binary payload contains no recognizable PowerPoint or OpenXML structures.",
                "status": "UNRECOVERABLE"
            }

        strategies = [
            ("Strategy 1: ZIP Header Realignment & python-pptx Load", cls._strategy_header_pptx),
            ("Strategy 2: Archive Decompression & Slide XML Extraction", cls._strategy_archive_slide_extract),
            ("Strategy 3: Slide Text Token Harvester & Presentation Builder", cls._strategy_token_synthesizer),
        ]

        attempt_log = []

        for strat_name, strat_func in strategies:
            try:
                res = strat_func(raw_data, output_path)
                if res.get("success"):
                    val = cls._validate_recovered_pptx(output_path)
                    if val.get("valid"):
                        attempt_log.append({"strategy": strat_name, "status": "SUCCESS", "details": res})
                        return {
                            "success": True,
                            "strategy": strat_name,
                            "status": "FULLY_RECOVERED" if val.get("slides_count", 0) > 0 else "PARTIALLY_RECOVERED",
                            "slides_recovered": val.get("slides_count", 1),
                            "attempts": attempt_log
                        }
                    else:
                        attempt_log.append({"strategy": strat_name, "status": "VALIDATION_FAILED", "error": val.get("error")})
                else:
                    attempt_log.append({"strategy": strat_name, "status": "FAILED", "error": res.get("error")})
            except Exception as e:
                attempt_log.append({"strategy": strat_name, "status": "EXCEPTION", "error": str(e)})

        return {
            "success": False,
            "strategy": "none",
            "status": "FAILED",
            "error": "All PPTX recovery strategies failed to rebuild a valid presentation.",
            "attempts": attempt_log
        }

    @classmethod
    def _validate_recovered_pptx(cls, file_path: str) -> Dict[str, Any]:
        if not os.path.exists(file_path) or os.path.getsize(file_path) < 100:
            return {"valid": False, "error": "Output file does not exist or is too small"}

        if Presentation is None:
            # Basic zip check if python-pptx is unavailable
            try:
                with zipfile.ZipFile(file_path, "r") as z:
                    if "ppt/presentation.xml" in z.namelist():
                        return {"valid": True, "slides_count": 1}
            except Exception as e:
                return {"valid": False, "error": str(e)}

        try:
            prs = Presentation(file_path)
            slide_count = len(prs.slides)
            return {"valid": True, "slides_count": slide_count}
        except Exception as e:
            return {"valid": False, "error": str(e)}

    @classmethod
    def _strategy_header_pptx(cls, raw_data: bytes, output_path: str) -> Dict[str, Any]:
        pk_pos = raw_data.find(b"PK\x03\x04")
        if pk_pos == -1:
            return {"success": False, "error": "No PK signature found"}

        cleaned = raw_data[pk_pos:] if pk_pos > 0 else raw_data
        try:
            with zipfile.ZipFile(io.BytesIO(cleaned), 'r') as z:
                if "ppt/presentation.xml" in z.namelist():
                    with open(output_path, "wb") as f:
                        f.write(cleaned)
                    return {"success": True, "method": "ZIP Header Realignment"}
        except Exception:
            pass

        return {"success": False, "error": "Direct ZIP load failed"}

    @classmethod
    def _strategy_archive_slide_extract(cls, raw_data: bytes, output_path: str) -> Dict[str, Any]:
        members = {}
        pk_matches = list(re.finditer(rb"PK\x03\x04", raw_data))
        for i, match in enumerate(pk_matches):
            start = match.start()
            end = pk_matches[i+1].start() if i+1 < len(pk_matches) else len(raw_data)
            chunk = raw_data[start:end]
            if len(chunk) > 30:
                try:
                    fname_len = int.from_bytes(chunk[26:28], 'little')
                    extra_len = int.from_bytes(chunk[28:30], 'little')
                    fname = chunk[30:30+fname_len].decode('utf-8', errors='ignore')
                    body = chunk[30+fname_len+extra_len:]
                    try:
                        decomp = zlib.decompress(body, -zlib.MAX_WBITS)
                        members[fname] = decomp
                    except Exception:
                        try:
                            decomp = zlib.decompress(body)
                            members[fname] = decomp
                        except Exception:
                            members[fname] = body
                except Exception:
                    pass

        slides_text = []
        for fname, data in members.items():
            if "ppt/slides/slide" in fname and fname.endswith(".xml"):
                slide_texts = []
                try:
                    root = ET.fromstring(data)
                    for t_elem in root.iter("{http://schemas.openxmlformats.org/drawingml/2006/main}t"):
                        if t_elem.text:
                            slide_texts.append(t_elem.text.strip())
                except Exception:
                    pass
                if slide_texts:
                    slides_text.append(slide_texts)

        if slides_text:
            return cls._build_presentation_from_slides(slides_text, output_path)

        return {"success": False, "error": "No slide text found in archive members"}

    @classmethod
    def _strategy_token_synthesizer(cls, raw_data: bytes, output_path: str) -> Dict[str, Any]:
        # Extract <a:t> text nodes from binary stream
        tokens = []
        for m in re.finditer(rb"<a:t[^>]*>(.*?)</a:t>", raw_data, re.DOTALL):
            txt = m.group(1).decode("utf-8", errors="ignore").strip()
            if txt and len(txt) > 1 and not txt.startswith("<?xml"):
                tokens.append(txt)

        if not tokens:
            return {"success": False, "error": "No slide text tokens found in stream"}

        # Group tokens into slides (approx 5 bullet points per slide)
        slides_data = []
        chunk = 5
        for i in range(0, len(tokens), chunk):
            slides_data.append(tokens[i:i+chunk])

        return cls._build_presentation_from_slides(slides_data, output_path)

    @classmethod
    def _build_presentation_from_slides(cls, slides_content: List[List[str]], output_path: str) -> Dict[str, Any]:
        if Presentation is None:
            return {"success": False, "error": "python-pptx library is required"}

        try:
            prs = Presentation()
            blank_slide_layout = prs.slide_layouts[6] if len(prs.slide_layouts) > 6 else prs.slide_layouts[0]

            for s_idx, texts in enumerate(slides_content, start=1):
                slide = prs.slides.add_slide(blank_slide_layout)
                
                # Add title
                tx_box = slide.shapes.add_textbox(Inches(1), Inches(0.8), Inches(8), Inches(1))
                tf = tx_box.text_frame
                tf.text = f"Recovered Slide {s_idx}"
                
                # Add body text
                body_box = slide.shapes.add_textbox(Inches(1), Inches(2), Inches(8), Inches(4.5))
                body_tf = body_box.text_frame
                for line in texts:
                    p = body_tf.add_paragraph()
                    p.text = f"• {line}"
                    p.space_after = Pt(8)

            prs.save(output_path)
            return {"success": True, "method": "python-pptx Presentation Synthesis", "slides_count": len(slides_content)}
        except Exception as e:
            return {"success": False, "error": f"Presentation build error: {str(e)}"}
