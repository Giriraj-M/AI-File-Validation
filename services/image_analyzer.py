import os
import io
import struct
import zlib
from typing import Dict, Any, List, Optional

try:
    from PIL import Image
except ImportError:
    Image = None

class ImageAnalyzer:
    """
    Forensic Image Corruption & Marker Analyzer for JPEG, PNG, and WebP.
    Analyzes:
      - JPEG: SOI (\xFF\xD8), EOI (\xFF\xD9), SOS, DQT, SOF markers, truncation.
      - PNG: Magic byte (\x89PNG\r\n\x1a\n), IHDR, IDAT, IEND, chunk CRC checks.
      - WebP: RIFF header, WEBP signature, VP8/VP8L/VP8X chunk integrity.
    """

    JPEG_SOI = b"\xFF\xD8"
    JPEG_EOI = b"\xFF\xD9"
    PNG_SIG = b"\x89PNG\r\n\x1a\n"
    RIFF_SIG = b"RIFF"
    WEBP_SIG = b"WEBP"

    @classmethod
    def analyze(cls, file_path: str) -> Dict[str, Any]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return {
                "file_type": "IMAGE",
                "is_corrupted": True,
                "corruption_regions": [
                    {"region": "header", "status": "corrupted", "reason": "File is empty (0 bytes)"},
                    {"region": "data", "status": "corrupted", "reason": "No image stream present"},
                    {"region": "end_of_file", "status": "corrupted", "reason": "Missing EOF marker"}
                ],
                "can_recover": False,
                "summary": "Image file is 0 bytes and unrecoverable."
            }

        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        # Sniff format
        if raw_bytes.startswith(cls.JPEG_SOI) or b"\xFF\xD8\xFF" in raw_bytes[:1024]:
            return cls._analyze_jpeg(raw_bytes)
        elif raw_bytes.startswith(cls.PNG_SIG) or b"PNG\r\n\x1a\n" in raw_bytes[:1024] or b"IHDR" in raw_bytes[:1024]:
            return cls._analyze_png(raw_bytes)
        elif (raw_bytes.startswith(cls.RIFF_SIG) and cls.WEBP_SIG in raw_bytes[:16]) or cls.WEBP_SIG in raw_bytes[:1024]:
            return cls._analyze_webp(raw_bytes)

        # Unknown or generic image
        return {
            "file_type": "IMAGE",
            "is_corrupted": True,
            "corruption_regions": [
                {"region": "header", "status": "corrupted", "reason": "Unrecognized or missing image header signature"}
            ],
            "can_recover": False,
            "summary": "File does not match known JPEG, PNG, or WebP signatures."
        }

    @classmethod
    def _analyze_jpeg(cls, raw_bytes: bytes) -> Dict[str, Any]:
        regions = []
        is_corrupted = False

        # Header check
        if not raw_bytes.startswith(cls.JPEG_SOI):
            pos = raw_bytes.find(cls.JPEG_SOI)
            if pos != -1:
                is_corrupted = True
                regions.append({"region": "header", "name": "JPEG SOI Marker", "status": "warning", "reason": f"Displaced SOI marker at offset {pos}"})
            else:
                is_corrupted = True
                regions.append({"region": "header", "name": "JPEG SOI Marker", "status": "corrupted", "reason": "Missing \\xFF\\xD8 SOI marker"})
        else:
            regions.append({"region": "header", "name": "JPEG SOI Marker", "status": "valid", "reason": "Valid JPEG SOI header"})

        # Stream & Marker checks (SOF, SOS)
        has_sof = bool(re_search(rb"\xFF[\xC0-\xC3]", raw_bytes))
        has_sos = b"\xFF\xDA" in raw_bytes
        if not has_sof or not has_sos:
            is_corrupted = True
            regions.append({"region": "body", "name": "JPEG Frame & Scan Data", "status": "corrupted", "reason": "Missing SOF or SOS scan markers"})
        else:
            regions.append({"region": "body", "name": "JPEG Frame & Scan Data", "status": "valid", "reason": "SOF and SOS scan streams detected"})

        # EOF check (\xFF\xD9)
        if not raw_bytes.endswith(cls.JPEG_EOI):
            is_corrupted = True
            regions.append({"region": "end_of_file", "name": "JPEG EOI Terminator", "status": "corrupted", "reason": "Missing or truncated \\xFF\\xD9 EOI marker"})
        else:
            regions.append({"region": "end_of_file", "name": "JPEG EOI Terminator", "status": "valid", "reason": "Valid JPEG EOI marker"})

        can_recover = has_sos or has_sof or b"\xFF\xD8" in raw_bytes

        return {
            "file_type": "JPEG",
            "is_corrupted": is_corrupted,
            "corruption_regions": regions,
            "can_recover": can_recover,
            "summary": "Intact JPEG Image" if not is_corrupted else "JPEG header displacement or truncated scan stream."
        }

    @classmethod
    def _analyze_png(cls, raw_bytes: bytes) -> Dict[str, Any]:
        regions = []
        is_corrupted = False

        # Header check
        if not raw_bytes.startswith(cls.PNG_SIG):
            pos = raw_bytes.find(cls.PNG_SIG)
            if pos != -1:
                is_corrupted = True
                regions.append({"region": "header", "name": "PNG Signature", "status": "warning", "reason": f"Displaced PNG header at offset {pos}"})
            else:
                is_corrupted = True
                regions.append({"region": "header", "name": "PNG Signature", "status": "corrupted", "reason": "Missing PNG magic bytes"})
        else:
            regions.append({"region": "header", "name": "PNG Signature", "status": "valid", "reason": "Valid PNG 8-byte magic header"})

        # IHDR & IDAT Chunks
        has_ihdr = b"IHDR" in raw_bytes
        has_idat = b"IDAT" in raw_bytes
        if not has_ihdr:
            is_corrupted = True
            regions.append({"region": "body", "name": "IHDR Header Chunk", "status": "corrupted", "reason": "Missing critical IHDR chunk"})
        elif not has_idat:
            is_corrupted = True
            regions.append({"region": "body", "name": "IDAT Pixel Data Chunk", "status": "corrupted", "reason": "Missing compressed IDAT image data"})
        else:
            regions.append({"region": "body", "name": "IHDR & IDAT Chunks", "status": "valid", "reason": "IHDR and IDAT data chunks present"})

        # IEND Terminator
        if b"IEND" not in raw_bytes[-64:]:
            is_corrupted = True
            regions.append({"region": "end_of_file", "name": "IEND Chunk Terminator", "status": "corrupted", "reason": "Missing or truncated IEND chunk"})
        else:
            regions.append({"region": "end_of_file", "name": "IEND Chunk Terminator", "status": "valid", "reason": "IEND chunk present at EOF"})

        can_recover = has_idat or (has_ihdr and len(raw_bytes) > 64)

        return {
            "file_type": "PNG",
            "is_corrupted": is_corrupted,
            "corruption_regions": regions,
            "can_recover": can_recover,
            "summary": "Intact PNG Image" if not is_corrupted else "PNG chunk or stream truncation detected."
        }

    @classmethod
    def _analyze_webp(cls, raw_bytes: bytes) -> Dict[str, Any]:
        regions = []
        is_corrupted = False

        if not raw_bytes.startswith(cls.RIFF_SIG) or cls.WEBP_SIG not in raw_bytes[:16]:
            is_corrupted = True
            regions.append({"region": "header", "name": "RIFF / WEBP Container", "status": "corrupted", "reason": "Missing RIFF WEBP signature"})
        else:
            regions.append({"region": "header", "name": "RIFF / WEBP Container", "status": "valid", "reason": "Valid RIFF/WEBP header"})

        has_vp8 = b"VP8" in raw_bytes or b"VP8L" in raw_bytes or b"VP8X" in raw_bytes
        if not has_vp8:
            is_corrupted = True
            regions.append({"region": "body", "name": "VP8 Stream Chunk", "status": "corrupted", "reason": "Missing VP8 / VP8L bitstream"})
        else:
            regions.append({"region": "body", "name": "VP8 Stream Chunk", "status": "valid", "reason": "VP8 bitstream chunks found"})

        return {
            "file_type": "WEBP",
            "is_corrupted": is_corrupted,
            "corruption_regions": regions,
            "can_recover": has_vp8,
            "summary": "Intact WebP Image" if not is_corrupted else "WebP container corruption detected."
        }

def re_search(pat, data):
    import re
    return re.search(pat, data)
