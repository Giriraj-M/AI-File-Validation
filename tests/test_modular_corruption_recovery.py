import os
import io
import re
import pytest
import pymupdf as fitz
from PIL import Image

from app import app
from services.detector import FileDetector
from services.corruption_classifier import CorruptionClassifier, classify_corruption
from services.tool_registry import ToolRegistry, check_tool_availability
from services.tool_recommender import ToolRecommender, recommend_recovery_tools
from services.tool_manager import ToolManager
from services.pdf_header_recovery import PDFHeaderRecovery
from services.pdf_xref_recovery import PDFXRefRecovery
from services.pdf_eof_recovery import PDFEOFRecovery
from services.pdf_body_recovery import PDFBodyRecovery
from services.pdf_image_recovery import PDFImageRecovery
from services.recovery_engine import (
    RecoveryEngine,
    detect_file_type,
    recover_file,
    validate_recovered_file,
    generate_recovery_report
)
from services.recovery_validator import RecoveryValidator


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def make_sample_pdf(text: str = "Confidential Recovery Test Document") -> bytes:
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)
    page.insert_text((50, 72), text, fontsize=14)
    data = doc.tobytes(garbage=3, deflate=True)
    doc.close()
    return data


def make_pdf_with_image(format: str = "JPEG") -> bytes:
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)
    page.insert_text((50, 72), f"PDF containing embedded {format} graphic", fontsize=14)

    # Generate synthetic image
    img = Image.new("RGB", (100, 100), color=(73, 109, 137))
    buf = io.BytesIO()
    img.save(buf, format=format)
    img_bytes = buf.getvalue()

    rect = fitz.Rect(50, 120, 200, 270)
    page.insert_image(rect, stream=img_bytes)
    data = doc.tobytes(garbage=3, deflate=True)
    doc.close()
    return data


# --------------------------------------------------------------------------
# 1. Valid PDF must NOT be classified as corrupted
# --------------------------------------------------------------------------
def test_valid_pdf_not_misclassified(tmp_path):
    orig = make_sample_pdf("Valid uncorrupted PDF document.")
    f = tmp_path / "intact.pdf"
    f.write_bytes(orig)

    classif = classify_corruption(str(f))
    assert classif["is_corrupted"] is False
    assert classif["corruption_type"] == CorruptionClassifier.CLEAN
    assert "Intact" in classif["category"]


# --------------------------------------------------------------------------
# 2. Header-Corrupted PDF Recovery
# --------------------------------------------------------------------------
def test_header_corrupted_pdf_recovery(tmp_path):
    orig = make_sample_pdf("Header corruption test document.")
    # Corrupt header magic bytes with displaced junk
    corrupted = b"CORRUPTED_PREFIX_JUNK_BYTES_1234567890\n" + orig
    f = tmp_path / "corrupt_header.pdf"
    f.write_bytes(corrupted)

    # 1. Classification
    classif = classify_corruption(str(f))
    assert classif["is_corrupted"] is True
    assert classif["corruption_type"] == CorruptionClassifier.PDF_HEADER_CORRUPTION

    # 2. Recommendations
    rec = recommend_recovery_tools(str(f))
    assert rec["file_type"] == "PDF"
    assert "Header" in rec["corruption_category"]
    assert rec["primary_tool"]["id"] == "pdf_header_recovery"

    # 3. Execution
    out = tmp_path / "recovered_header.pdf"
    res = PDFHeaderRecovery.recover(str(f), str(out))
    assert res["success"] is True
    assert os.path.exists(str(out))

    # 4. Validation
    val = validate_recovered_file(str(f), str(out), "PDF")
    assert val["openable"] is True
    assert val["reopened_ok"] is True
    assert val["pages"] >= 1


# --------------------------------------------------------------------------
# 3. XREF-Corrupted PDF Recovery
# --------------------------------------------------------------------------
def test_xref_corrupted_pdf_recovery(tmp_path):
    orig = make_sample_pdf("XREF table corruption test document.")
    # Corrupt startxref offset to invalid number
    corrupted = orig.replace(b"startxref\n", b"startxref\n999999999\nold_")
    f = tmp_path / "corrupt_xref.pdf"
    f.write_bytes(corrupted)

    classif = classify_corruption(str(f))
    assert classif["is_corrupted"] is True
    assert classif["corruption_type"] == CorruptionClassifier.PDF_XREF_CORRUPTION

    out = tmp_path / "recovered_xref.pdf"
    res = PDFXRefRecovery.recover(str(f), str(out))
    assert res["success"] is True

    val = validate_recovered_file(str(f), str(out), "PDF")
    assert val["openable"] is True
    assert val["reopened_ok"] is True


# --------------------------------------------------------------------------
# 4. EOF-Corrupted / Truncated PDF Recovery
# --------------------------------------------------------------------------
def test_eof_corrupted_pdf_recovery(tmp_path):
    orig = make_sample_pdf("EOF marker truncation test document.")
    # Strip %%EOF
    corrupted = orig.rstrip(b"%%EOF\n").rstrip(b"%%EOF\r\n").rstrip()
    f = tmp_path / "corrupt_eof.pdf"
    f.write_bytes(corrupted)

    classif = classify_corruption(str(f))
    assert classif["is_corrupted"] is True
    assert classif["corruption_type"] == CorruptionClassifier.PDF_EOF_TRUNCATION

    out = tmp_path / "recovered_eof.pdf"
    res = PDFEOFRecovery.recover(str(f), str(out))
    assert res["success"] is True

    val = validate_recovered_file(str(f), str(out), "PDF")
    assert val["openable"] is True
    assert val["reopened_ok"] is True


# --------------------------------------------------------------------------
# 5. Body & Content Stream Corrupted PDF Recovery
# --------------------------------------------------------------------------
def test_body_corrupted_pdf_recovery(tmp_path):
    orig = make_sample_pdf("Content stream body damage test document.")
    # Damaged stream tags
    corrupted = orig.replace(b"stream\n", b"stream_damaged_tag\n", 1)
    f = tmp_path / "corrupt_body.pdf"
    f.write_bytes(corrupted)

    out = tmp_path / "recovered_body.pdf"
    res = PDFBodyRecovery.recover(str(f), str(out))
    assert res["success"] is True

    val = validate_recovered_file(str(f), str(out), "PDF")
    assert val["openable"] is True
    assert val["reopened_ok"] is True


# --------------------------------------------------------------------------
# 6. Embedded JPEG-Corrupted PDF Recovery
# --------------------------------------------------------------------------
def test_embedded_jpeg_corrupted_pdf_recovery(tmp_path):
    orig = make_pdf_with_image("JPEG")
    # Corrupt embedded JPEG marker inside stream
    corrupted = orig.replace(b"\xff\xd8", b"\x00\x00", 1)
    f = tmp_path / "corrupt_jpeg_img.pdf"
    f.write_bytes(corrupted)

    out = tmp_path / "recovered_jpeg.pdf"
    res = PDFImageRecovery.recover(str(f), str(out))
    assert res["success"] is True

    val = validate_recovered_file(str(f), str(out), "PDF")
    assert val["openable"] is True
    assert val["reopened_ok"] is True


# --------------------------------------------------------------------------
# 7. Embedded PNG-Corrupted PDF Recovery
# --------------------------------------------------------------------------
def test_embedded_png_corrupted_pdf_recovery(tmp_path):
    orig = make_pdf_with_image("PNG")
    f = tmp_path / "corrupt_png_img.pdf"
    f.write_bytes(orig)

    out = tmp_path / "recovered_png.pdf"
    res = PDFImageRecovery.recover(str(f), str(out))
    assert res["success"] is True

    val = validate_recovered_file(str(f), str(out), "PDF")
    assert val["openable"] is True


# --------------------------------------------------------------------------
# 8. Unsupported Format Handling
# --------------------------------------------------------------------------
def test_unsupported_format_handling(tmp_path):
    f = tmp_path / "binary.bin"
    f.write_bytes(b"\x00\x01\x02\x03\x04\x05\x06\x07" * 50)

    classif = classify_corruption(str(f))
    assert classif["corruption_type"] in [CorruptionClassifier.UNSUPPORTED, CorruptionClassifier.UNRECOVERABLE]


# --------------------------------------------------------------------------
# 9. Tool Availability and Missing External Tools Checking
# --------------------------------------------------------------------------
def test_tool_manager_and_registry_status():
    report = ToolManager.get_dependency_report()
    assert "installed_tools" in report
    assert "missing_tools" in report
    assert "all_tools" in report

    # Check python tools are active
    assert check_tool_availability("pikepdf") is True
    assert check_tool_availability("pymupdf") is True
    assert check_tool_availability("pillow") is True

    # Missing tools give graceful false without crashing
    assert check_tool_availability("nonexistent_binary_tool_xyz") is False

    tools = ToolRegistry.get_all_tools()
    assert len(tools) >= 10
    for t in tools:
        assert "is_installed" in t
        assert "install_guide" in t


# --------------------------------------------------------------------------
# 10. Standard Unified System Interfaces
# --------------------------------------------------------------------------
def test_unified_system_interfaces(tmp_path):
    orig = make_sample_pdf("Interface test document.")
    f = tmp_path / "test_doc.pdf"
    f.write_bytes(orig)

    # detect_file_type
    det = detect_file_type(str(f))
    assert det["file_type"] == "PDF"

    # classify_corruption
    cls_res = classify_corruption(str(f))
    assert "corruption_type" in cls_res

    # recommend_recovery_tools
    rec_res = recommend_recovery_tools(str(f))
    assert "primary_tool" in rec_res
    assert "alternative_tools" in rec_res

    # check_tool_availability
    assert check_tool_availability("pymupdf") is True

    # recover_file with selected_tool
    out_res = recover_file(str(f), selected_tool="pdf_header_recovery")
    assert out_res["success"] is True

    # validate_recovered_file
    val_res = validate_recovered_file(str(f), out_res["output_path"], "PDF")
    assert val_res["openable"] is True

    # generate_recovery_report
    rep_res = generate_recovery_report(out_res)
    assert "summary" in rep_res or "validation" in rep_res


# --------------------------------------------------------------------------
# 11. Multi-File Batch Recovery with Mixed Corruptions
# --------------------------------------------------------------------------
def test_multi_file_batch_recovery_api(client, tmp_path):
    pdf_hdr = b"PREFIX_GARBAGE_BYTES\n" + make_sample_pdf("Header Corrupt")
    pdf_eof = make_sample_pdf("EOF Corrupt").rstrip(b"%%EOF\n")

    data = {
        "files[]": [
            (io.BytesIO(pdf_hdr), "corrupt1_header.pdf"),
            (io.BytesIO(pdf_eof), "corrupt2_eof.pdf")
        ],
        "selected_tools": '{"corrupt1_header.pdf": "pdf_header_recovery", "corrupt2_eof.pdf": "pdf_eof_recovery"}'
    }

    res = client.post("/api/recover/batch", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data["success"] is True
    assert json_data["total_files"] == 2
    assert json_data["successful_count"] >= 1
    assert "results" in json_data
    assert len(json_data["results"]) == 2


# --------------------------------------------------------------------------
# 12. Batch Forensic Analysis API
# --------------------------------------------------------------------------
def test_batch_analyze_api(client):
    pdf_hdr = b"GARBAGE_BYTES\n" + make_sample_pdf("Pre-analysis test")

    data = {
        "files[]": [
            (io.BytesIO(pdf_hdr), "staged_sample.pdf")
        ]
    }

    res = client.post("/api/analyze/batch", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data["success"] is True
    assert len(json_data["files"]) == 1
    f_info = json_data["files"][0]
    assert "corruption_classification" in f_info
    assert "tool_recommendation" in f_info
    assert "available_candidate_tools" in f_info


# --------------------------------------------------------------------------
# 13. System Tools API and Clean Temp Session API
# --------------------------------------------------------------------------
def test_tools_and_clean_temp_endpoints(client):
    # GET /api/tools
    res = client.get("/api/tools")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "tools" in data
    assert "dependency_report" in data

    # POST /api/clean-temp
    res_clean = client.post("/api/clean-temp")
    assert res_clean.status_code == 200
    data_clean = res_clean.get_json()
    assert data_clean["success"] is True
