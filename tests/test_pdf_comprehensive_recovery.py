import os
import io
import random
import pytest
from pathlib import Path
from pypdf import PdfWriter
import pymupdf as fitz

from services.pdf_analyzer import PDFAnalyzer
from services.pdf_recovery import PDFRecoveryEngine
from services.recovery_engine import RecoveryEngine
from services.validator import RecoveredFileValidator
from services.recovery_report import RecoveryReportGenerator


def create_realistic_test_pdf(num_pages: int = 5) -> bytes:
    """
    Creates a realistic multi-page PDF document with text, metadata,
    and structured layout.
    """
    doc = fitz.open()
    for i in range(num_pages):
        page = doc.new_page(width=612, height=792)
        page.insert_text(
            (50, 72),
            f"FileGuard AI Comprehensive Audit Report - Page {i + 1}",
            fontsize=16,
            color=(0.1, 0.2, 0.5)
        )
        page.insert_text(
            (50, 110),
            f"Section {i + 1}.0: Performance metrics and system validation benchmarks.\n"
            f"Integrity check verified at block {1000 + i * 250}.\n"
            f"Deterministic recovery validation active for enterprise security auditing.",
            fontsize=11,
            color=(0.2, 0.2, 0.2)
        )
        # Add a visual drawing/rectangle
        page.draw_rect(fitz.Rect(50, 200, 550, 250), color=(0.2, 0.4, 0.8), fill=(0.9, 0.95, 1.0))
        page.insert_text((60, 230), f"Page {i + 1} Encoded Data Block Summary", fontsize=10, color=(0.1, 0.2, 0.4))

    doc.set_metadata({
        "title": "Comprehensive FileGuard Audit",
        "author": "Enterprise Security Team",
        "subject": "PDF Recovery Benchmarks"
    })
    pdf_bytes = doc.tobytes(garbage=3, deflate=True)
    doc.close()
    return pdf_bytes


# --------------------------------------------------------------------------
# 1. Missing EOF Marker Recovery & Validation
# --------------------------------------------------------------------------
def test_controlled_missing_eof_recovery(tmp_path):
    orig_bytes = create_realistic_test_pdf(num_pages=3)
    orig_path = tmp_path / "orig_missing_eof.pdf"
    orig_path.write_bytes(orig_bytes)

    # Strip %%EOF and trailing whitespace
    corrupted_bytes = orig_bytes.rstrip().rstrip(b"%%EOF").rstrip()
    corrupt_path = tmp_path / "corrupt_missing_eof.pdf"
    corrupt_path.write_bytes(corrupted_bytes)

    out_path = tmp_path / "rec_missing_eof.pdf"
    analysis = PDFAnalyzer.analyze(str(corrupt_path))
    assert analysis["is_corrupted"] is True
    assert analysis["structure_matrix"]["eof"]["status"] == "CORRUPTED"

    res = PDFRecoveryEngine.recover(str(corrupt_path), str(out_path), analysis)
    assert res["success"] is True
    assert res["status"] in ["SUCCESS", "PARTIAL"]

    val = RecoveredFileValidator.validate(str(out_path), "PDF", original_file_path=str(orig_path))
    assert val["openable"] is True
    assert val["structure_valid"] is True
    assert val["pages_recovered"] == 3
    assert val["text_recovery"] >= 95.0
    assert val["comparison"]["status"] == "SUCCESS"
    assert val["comparison"]["confidence"] == "HIGH"


# --------------------------------------------------------------------------
# 2. Damaged startxref Recovery & Validation
# --------------------------------------------------------------------------
def test_controlled_damaged_startxref_recovery(tmp_path):
    orig_bytes = create_realistic_test_pdf(num_pages=4)
    orig_path = tmp_path / "orig_startxref.pdf"
    orig_path.write_bytes(orig_bytes)

    # Corrupt startxref pointer offset
    corrupted_bytes = orig_bytes.replace(b"startxref", b"startxref_invalid_pointer") + b"\n9999999999\n%%EOF"
    corrupt_path = tmp_path / "corrupt_startxref.pdf"
    corrupt_path.write_bytes(corrupted_bytes)

    out_path = tmp_path / "rec_startxref.pdf"
    analysis = PDFAnalyzer.analyze(str(corrupt_path))
    assert analysis["is_corrupted"] is True

    res = PDFRecoveryEngine.recover(str(corrupt_path), str(out_path), analysis)
    assert res["success"] is True

    val = RecoveredFileValidator.validate(str(out_path), "PDF", original_file_path=str(orig_path))
    assert val["openable"] is True
    assert val["pages_recovered"] == 4
    assert val["text_recovery"] >= 90.0


# --------------------------------------------------------------------------
# 3. Damaged xref Table Recovery & Validation
# --------------------------------------------------------------------------
def test_controlled_damaged_xref_recovery(tmp_path):
    orig_bytes = create_realistic_test_pdf(num_pages=3)
    orig_path = tmp_path / "orig_xref.pdf"
    orig_path.write_bytes(orig_bytes)

    # Scramble xref table entries
    corrupted_bytes = orig_bytes.replace(b"xref", b"xxxx_scrambled_xref").replace(b"00000000", b"99999999")
    corrupt_path = tmp_path / "corrupt_xref.pdf"
    corrupt_path.write_bytes(corrupted_bytes)

    out_path = tmp_path / "rec_xref.pdf"
    analysis = PDFAnalyzer.analyze(str(corrupt_path))
    assert analysis["is_corrupted"] is True

    res = PDFRecoveryEngine.recover(str(corrupt_path), str(out_path), analysis)
    assert res["success"] is True

    val = RecoveredFileValidator.validate(str(out_path), "PDF", original_file_path=str(orig_path))
    assert val["openable"] is True
    assert val["pages_recovered"] == 3


# --------------------------------------------------------------------------
# 4. Damaged Trailer Dictionary Recovery & Validation
# --------------------------------------------------------------------------
def test_controlled_damaged_trailer_recovery(tmp_path):
    orig_bytes = create_realistic_test_pdf(num_pages=3)
    orig_path = tmp_path / "orig_trailer.pdf"
    orig_path.write_bytes(orig_bytes)

    # Scramble trailer keyword and /Root pointer
    corrupted_bytes = orig_bytes.replace(b"trailer", b"trailer_destroyed_data").replace(b"/Root", b"/Root_corrupted")
    corrupt_path = tmp_path / "corrupt_trailer.pdf"
    corrupt_path.write_bytes(corrupted_bytes)

    out_path = tmp_path / "rec_trailer.pdf"
    analysis = PDFAnalyzer.analyze(str(corrupt_path))
    assert analysis["is_corrupted"] is True

    res = PDFRecoveryEngine.recover(str(corrupt_path), str(out_path), analysis)
    assert res["success"] is True

    val = RecoveredFileValidator.validate(str(out_path), "PDF", original_file_path=str(orig_path))
    assert val["openable"] is True
    assert val["structure_valid"] is True


# --------------------------------------------------------------------------
# 5. Incorrect Object Offsets & Displaced Header
# --------------------------------------------------------------------------
def test_controlled_displaced_header_and_shifted_offsets(tmp_path):
    orig_bytes = create_realistic_test_pdf(num_pages=2)
    orig_path = tmp_path / "orig_displaced.pdf"
    orig_path.write_bytes(orig_bytes)

    # Prepend 200 bytes of arbitrary junk to displace byte 0 and all xref offsets
    junk = b"PREPENDED_ARBITRARY_NETWORK_TRANSMISSION_NOISE_BYTE_OFFSET_SHIFT_" * 4
    corrupted_bytes = junk + orig_bytes
    corrupt_path = tmp_path / "corrupt_displaced.pdf"
    corrupt_path.write_bytes(corrupted_bytes)

    out_path = tmp_path / "rec_displaced.pdf"
    analysis = PDFAnalyzer.analyze(str(corrupt_path))
    assert analysis["is_corrupted"] is True
    assert analysis["structure_matrix"]["header"]["status"] == "CORRUPTED"

    res = PDFRecoveryEngine.recover(str(corrupt_path), str(out_path), analysis)
    assert res["success"] is True

    val = RecoveredFileValidator.validate(str(out_path), "PDF", original_file_path=str(orig_path))
    assert val["openable"] is True
    assert val["pages_recovered"] == 2
    assert val["text_recovery"] >= 95.0


# --------------------------------------------------------------------------
# 6. Metadata Corruption
# --------------------------------------------------------------------------
def test_controlled_metadata_corruption_recovery(tmp_path):
    orig_bytes = create_realistic_test_pdf(num_pages=2)
    orig_path = tmp_path / "orig_meta.pdf"
    orig_path.write_bytes(orig_bytes)

    corrupted_bytes = orig_bytes.replace(b"/Title (Comprehensive FileGuard Audit)", b"/Title (Corrupted\x00\xff\xfe\x00Broken\x00)")
    corrupt_path = tmp_path / "corrupt_meta.pdf"
    corrupt_path.write_bytes(corrupted_bytes)

    out_path = tmp_path / "rec_meta.pdf"
    analysis = PDFAnalyzer.analyze(str(corrupt_path))

    res = PDFRecoveryEngine.recover(str(corrupt_path), str(out_path), analysis)
    assert res["success"] is True

    val = RecoveredFileValidator.validate(str(out_path), "PDF", original_file_path=str(orig_path))
    assert val["openable"] is True
    assert val["text_recovery"] >= 90.0


# --------------------------------------------------------------------------
# 7. Physical Truncation (Partial Data Loss)
# --------------------------------------------------------------------------
def test_controlled_truncation_partial_recovery(tmp_path):
    orig_bytes = create_realistic_test_pdf(num_pages=6)
    orig_path = tmp_path / "orig_trunc.pdf"
    orig_path.write_bytes(orig_bytes)

    # Truncate at 45% of total file size (destroying trailer, xref, and trailing pages)
    truncated_bytes = orig_bytes[:int(len(orig_bytes) * 0.45)]
    corrupt_path = tmp_path / "corrupt_trunc.pdf"
    corrupt_path.write_bytes(truncated_bytes)

    out_path = tmp_path / "rec_trunc.pdf"
    res = RecoveryEngine.recover_file(str(corrupt_path), "corrupt_trunc.pdf", requested_type="pdf", original_ref_path=str(orig_path))
    
    assert res["success"] is True
    # In truncation, partial recovery is the technically accurate result
    assert res["status"] in ["SUCCESS", "PARTIAL"]
    assert res["confidence"] in ["HIGH", "MEDIUM"]
    assert res["pages_recovered"] >= 1
    assert res["pages_original"] == 6

    val = res["validation"]
    assert val["openable"] is True


# --------------------------------------------------------------------------
# 8. Random Byte Flipping in Body Streams
# --------------------------------------------------------------------------
def test_controlled_random_byte_corruption(tmp_path):
    orig_bytes = create_realistic_test_pdf(num_pages=3)
    orig_path = tmp_path / "orig_random.pdf"
    orig_path.write_bytes(orig_bytes)

    # Introduce corrupt bytes in the middle of body data
    corrupt_array = bytearray(orig_bytes)
    midpoint = len(orig_bytes) // 2
    for offset in range(midpoint, midpoint + 60):
        corrupt_array[offset] = random.randint(0, 255)

    corrupt_path = tmp_path / "corrupt_random.pdf"
    corrupt_path.write_bytes(bytes(corrupt_array))

    out_path = tmp_path / "rec_random.pdf"
    res = RecoveryEngine.recover_file(str(corrupt_path), "corrupt_random.pdf", requested_type="pdf", original_ref_path=str(orig_path))
    
    assert res["success"] is True
    assert res["pages_recovered"] >= 1
    assert os.path.exists(res["output_path"])


# --------------------------------------------------------------------------
# 9. Multiple Simultaneous Structural Corruptions
# --------------------------------------------------------------------------
def test_controlled_multiple_simultaneous_corruptions(tmp_path):
    orig_bytes = create_realistic_test_pdf(num_pages=3)
    orig_path = tmp_path / "orig_multi.pdf"
    orig_path.write_bytes(orig_bytes)

    # Simultaneously break header, xref, startxref, and EOF
    multi_corrupt = (
        b"CORRUPTED_PREFIX_OFFSET\n" +
        orig_bytes
        .replace(b"startxref", b"startxref_lost")
        .replace(b"xref", b"xxxx_table")
        .replace(b"%%EOF", b"")
    )

    corrupt_path = tmp_path / "corrupt_multi.pdf"
    corrupt_path.write_bytes(multi_corrupt)

    out_path = tmp_path / "rec_multi.pdf"
    res = RecoveryEngine.recover_file(str(corrupt_path), "corrupt_multi.pdf", requested_type="pdf", original_ref_path=str(orig_path))
    
    val = RecoveredFileValidator.validate(res["output_path"], "PDF", original_file_path=str(orig_path))
    assert val["openable"] is True
    assert val["pages_recovered"] == 3


# --------------------------------------------------------------------------
# 10. Permanently Unrecoverable Files (Zero-Byte & Pure Random Noise)
# --------------------------------------------------------------------------
def test_unrecoverable_zero_byte_file(tmp_path):
    empty_path = tmp_path / "empty.pdf"
    empty_path.write_bytes(b"")

    out_path = tmp_path / "out_empty.pdf"
    res = RecoveryEngine.recover_file(str(empty_path), "empty.pdf", requested_type="pdf")

    # MUST accurately report unrecoverable without claiming success
    assert res["success"] is False
    assert res["status"] in ["UNRECOVERABLE", "FAILED"]
    assert res["pages_recovered"] == 0
    assert "0-byte" in res["recovery"]["error"] or "empty" in res["recovery"]["error"]


def test_unrecoverable_pure_random_noise(tmp_path):
    # Pure arbitrary random noise with zero PDF objects or streams
    noise = bytes([random.randint(0, 255) for _ in range(500)])
    noise_path = tmp_path / "noise.pdf"
    noise_path.write_bytes(noise)

    out_path = tmp_path / "out_noise.pdf"
    res = RecoveryEngine.recover_file(str(noise_path), "noise.pdf", requested_type="pdf")

    # MUST accurately report unrecoverable without claiming fake success
    assert res["success"] is False
    assert res["status"] in ["UNRECOVERABLE", "FAILED"]
    assert res["pages_recovered"] == 0
