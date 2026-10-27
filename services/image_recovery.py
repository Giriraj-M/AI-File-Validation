import os
import io
import struct
import zlib
import logging
from typing import Dict, Any, List, Optional

try:
    from PIL import Image, ImageFile
    ImageFile.LOAD_TRUNCATED_IMAGES = True
except ImportError:
    Image = None

logger = logging.getLogger("FileGuard.ImageRecovery")

class ImageRecoveryEngine:
    """
    Deterministic Multi-Strategy Image Recovery Engine for JPEG, PNG, and WebP.
    Repairs damaged, truncated, or header-displaced raster images.
    """

    @classmethod
    def recover(cls, corrupted_path: str, output_path: str) -> Dict[str, Any]:
        if not os.path.exists(corrupted_path):
            return {
                "success": False,
                "strategy": "none",
                "error": "Source image not found",
                "status": "FAILED"
            }

        file_size = os.path.getsize(corrupted_path)
        if file_size == 0:
            return {
                "success": False,
                "strategy": "none",
                "error": "Image file is empty (0 bytes). Recovery impossible.",
                "status": "UNRECOVERABLE"
            }

        with open(corrupted_path, "rb") as f:
            raw_data = f.read()

        if Image is None:
            return {
                "success": False,
                "strategy": "none",
                "error": "Pillow (PIL) library is required for image recovery.",
                "status": "FAILED"
            }

        strategies = [
            ("Strategy 1: Pillow Truncated Stream Loader", cls._strategy_pillow_truncated),
            ("Strategy 2: Header Realignment & Magic Byte Normalization", cls._strategy_header_realignment),
            ("Strategy 3: JPEG / PNG Terminator Injection", cls._strategy_terminator_injection),
            ("Strategy 4: PNG Chunk Reconstruction", cls._strategy_png_chunk_repair)
        ]

        attempt_log = []

        for strat_name, strat_func in strategies:
            try:
                res = strat_func(raw_data, output_path)
                if res.get("success"):
                    val = cls._validate_recovered_image(output_path)
                    if val.get("valid"):
                        attempt_log.append({"strategy": strat_name, "status": "SUCCESS", "details": res})
                        return {
                            "success": True,
                            "strategy": strat_name,
                            "status": "FULLY_RECOVERED",
                            "dimensions": f"{val.get('width')}x{val.get('height')}",
                            "format": val.get("format"),
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
            "error": "Could not salvage renderable pixel data from corrupted image.",
            "attempts": attempt_log
        }

    @classmethod
    def _validate_recovered_image(cls, file_path: str) -> Dict[str, Any]:
        if not os.path.exists(file_path) or os.path.getsize(file_path) < 32:
            return {"valid": False, "error": "Output image does not exist or is too small"}

        try:
            with Image.open(file_path) as im:
                im.load()  # Force load pixel raster
                w, h = im.size
                if w <= 0 or h <= 0:
                    return {"valid": False, "error": "Invalid pixel dimensions"}
                return {"valid": True, "width": w, "height": h, "format": im.format}
        except Exception as e:
            return {"valid": False, "error": f"Image load failed: {str(e)}"}

    @classmethod
    def _strategy_pillow_truncated(cls, raw_data: bytes, output_path: str) -> Dict[str, Any]:
        try:
            with Image.open(io.BytesIO(raw_data)) as im:
                im.load()
                fmt = im.format or "PNG"
                im.save(output_path, format=fmt)
                return {"success": True, "method": "Pillow Truncated Stream Loader", "format": fmt}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @classmethod
    def _strategy_header_realignment(cls, raw_data: bytes, output_path: str) -> Dict[str, Any]:
        # Search for JPEG SOI
        soi_pos = raw_data.find(b"\xFF\xD8")
        if soi_pos > 0:
            cleaned = raw_data[soi_pos:]
            try:
                with Image.open(io.BytesIO(cleaned)) as im:
                    im.load()
                    im.save(output_path, format="JPEG")
                    return {"success": True, "method": "JPEG Header Realignment", "offset": soi_pos}
            except Exception:
                pass

        # Search for PNG signature
        png_pos = raw_data.find(b"\x89PNG\r\n\x1a\n")
        if png_pos > 0:
            cleaned = raw_data[png_pos:]
            try:
                with Image.open(io.BytesIO(cleaned)) as im:
                    im.load()
                    im.save(output_path, format="PNG")
                    return {"success": True, "method": "PNG Header Realignment", "offset": png_pos}
            except Exception:
                pass

        return {"success": False, "error": "No displaced image header found"}

    @classmethod
    def _strategy_terminator_injection(cls, raw_data: bytes, output_path: str) -> Dict[str, Any]:
        # If JPEG missing EOI (\xFF\xD9)
        if b"\xFF\xD8" in raw_data and not raw_data.endswith(b"\xFF\xD9"):
            soi_pos = raw_data.find(b"\xFF\xD8")
            base = raw_data[soi_pos:] if soi_pos >= 0 else raw_data
            patched = base + b"\xFF\xD9"
            try:
                with Image.open(io.BytesIO(patched)) as im:
                    im.load()
                    im.save(output_path, format="JPEG")
                    return {"success": True, "method": "JPEG EOI Injection"}
            except Exception:
                pass

        # If PNG missing IEND
        if (b"PNG" in raw_data or b"IHDR" in raw_data) and b"IEND" not in raw_data[-64:]:
            png_pos = raw_data.find(b"\x89PNG\r\n\x1a\n")
            base = raw_data[png_pos:] if png_pos >= 0 else b"\x89PNG\r\n\x1a\n" + raw_data
            # Synthesize IEND chunk (0 length, 'IEND', CRC)
            iend_chunk = b"\x00\x00\x00\x00IEND\xaeB`\x82"
            patched = base + iend_chunk
            try:
                with Image.open(io.BytesIO(patched)) as im:
                    im.load()
                    im.save(output_path, format="PNG")
                    return {"success": True, "method": "PNG IEND Chunk Injection"}
            except Exception:
                pass

        return {"success": False, "error": "Terminator injection failed"}

    @classmethod
    def _strategy_png_chunk_repair(cls, raw_data: bytes, output_path: str) -> Dict[str, Any]:
        # Search for IHDR and IDAT chunks
        ihdr_pos = raw_data.find(b"IHDR")
        idat_pos = raw_data.find(b"IDAT")

        if ihdr_pos == -1 and idat_pos == -1:
            return {"success": False, "error": "No PNG chunks found"}

        # Construct minimal valid PNG container around IDAT if present
        if idat_pos != -1:
            # Extract IDAT body
            try:
                # Find all IDAT chunks
                idat_chunks = []
                for m in re_finditer(rb"IDAT", raw_data):
                    pos = m.start()
                    if pos >= 4:
                        chunk_len = int.from_bytes(raw_data[pos-4:pos], 'big')
                        if chunk_len < len(raw_data) - pos:
                            idat_chunks.append(raw_data[pos-4:pos+4+chunk_len+4])

                if idat_chunks:
                    png_stream = b"\x89PNG\r\n\x1a\n"
                    # Default 100x100 IHDR if original IHDR lost
                    if ihdr_pos >= 4:
                        ihdr_len = int.from_bytes(raw_data[ihdr_pos-4:ihdr_pos], 'big')
                        png_stream += raw_data[ihdr_pos-4:ihdr_pos+4+ihdr_len+4]
                    else:
                        ihdr_data = struct.pack(">IIBBBBB", 200, 200, 8, 2, 0, 0, 0)
                        crc = zlib.crc32(b"IHDR" + ihdr_data)
                        png_stream += struct.pack(">I", 13) + b"IHDR" + ihdr_data + struct.pack(">I", crc)

                    for chunk in idat_chunks:
                        png_stream += chunk

                    png_stream += b"\x00\x00\x00\x00IEND\xaeB`\x82"

                    with Image.open(io.BytesIO(png_stream)) as im:
                        im.load()
                        im.save(output_path, format="PNG")
                        return {"success": True, "method": "PNG Synthesized Stream Reconstruction"}
            except Exception as e:
                return {"success": False, "error": f"PNG chunk repair failed: {str(e)}"}

        return {"success": False, "error": "PNG chunk repair unviable"}

def re_finditer(pat, data):
    import re
    return re.finditer(pat, data)
