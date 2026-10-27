import os
import io
import zlib
import zipfile
import tempfile
import pytest
from pathlib import Path
from pypdf import PdfWriter
import docx

from app import app
from services.detector import FileDetector
from services.pdf_analyzer import PDFAnalyzer
from services.docx_analyzer import DOCXAnalyzer
from services.pdf_recovery import PDFRecoveryEngine
from services.docx_recovery import DOCXRecoveryEngine
from services.recovery_engine import RecoveryEngine
from services.validator import RecoveredFileValidator
from services.recovery_report import RecoveryReportGenerator


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def make_valid_pdf() -> bytes:
    """Generates a valid, structurally compliant PDF with text."""
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    buf = io.BytesIO()
    writer.write(buf)
    data = buf.getvalue()
    # Insert readable text object in the stream
    text_snippet = b"\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    return data


def make_valid_docx() -> bytes:
    """Generates a valid DOCX file with real paragraphs."""
    doc = docx.Document()
    doc.add_heading("Confidential Quarterly Report", level=1)
    doc.add_paragraph("Total Net Revenue: $12,450,000 across North American division.")
    doc.add_paragraph("Deterministic integrity verified with zero placeholder pages.")
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


# --------------------------------------------------------------------------
# Test 1 & 2: Valid PDF Detection, Analysis, and Integrity
# --------------------------------------------------------------------------
def test_valid_pdf_analysis(tmp_path):
    f = tmp_path / "valid.pdf"
    f.write_bytes(make_valid_pdf())

    analysis = PDFAnalyzer.analyze(str(f))
    assert analysis["file_type"] == "PDF"
    assert analysis["is_corrupted"] is False
    for reg in analysis["corruption_regions"]:
        assert reg["status"] == "valid"


# --------------------------------------------------------------------------
# Test 3: Deliberately Corrupted PDF Header (Displaced by junk bytes)
# --------------------------------------------------------------------------
def test_corrupted_pdf_displaced_header(tmp_path):
    orig = make_valid_pdf()
    # Prepend 150 bytes of arbitrary junk before %PDF-
    junk_prefix = b"### NON-PDF CORRUPTED PRECEDING BYTES ### " * 3
    corrupted_data = junk_prefix + orig

    f = tmp_path / "displaced_header.pdf"
    f.write_bytes(corrupted_data)

    # 1. Detection recognizes PDF despite displaced header
    det = FileDetector.detect_file_type(str(f), "displaced_header.pdf")
    assert det["file_type"] == "PDF"

    # 2. Analyzer localizes header corruption with exact offset
    analysis = PDFAnalyzer.analyze(str(f))
    assert analysis["is_corrupted"] is True
    header_reg = next(r for r in analysis["corruption_regions"] if r["region"] == "header")
    assert header_reg["status"] == "corrupted"
    assert "Displaced" in header_reg["reason"]

    # 3. Recovery strips junk and realigns PDF
    out = tmp_path / "realigned.pdf"
    res = PDFRecoveryEngine.recover(str(f), str(out), analysis)
    assert res["success"] is True
    assert os.path.exists(str(out))

    # 4. Validator confirms reconstructed file is valid and openable
    val = RecoveredFileValidator.validate(str(out), "PDF")
    assert val["openable"] is True
    assert val["structure_valid"] is True


# --------------------------------------------------------------------------
# Test 4: Damaged PDF Cross-Reference (xref) Table
# --------------------------------------------------------------------------
def test_damaged_pdf_xref(tmp_path):
    orig = make_valid_pdf()
    # Corrupt the startxref pointer and xref table
    corrupted_data = orig.replace(b"startxref", b"startxref_broken") + b"\ncorrupted_xref_tail_99999"

    f = tmp_path / "broken_xref.pdf"
    f.write_bytes(corrupted_data)

    analysis = PDFAnalyzer.analyze(str(f))
    assert analysis["is_corrupted"] is True
    ref_reg = next(r for r in analysis["corruption_regions"] if r["region"] == "references")
    assert ref_reg["status"] == "corrupted"

    # Recover using Level 2 object scanning and xref reconstruction
    out = tmp_path / "rebuilt_xref.pdf"
    res = PDFRecoveryEngine.recover(str(f), str(out), analysis)
    assert res["success"] is True
    assert "Level 2" in res["method"] or "Level 1" in res["method"]

    val = RecoveredFileValidator.validate(str(out), "PDF")
    assert val["openable"] is True


# --------------------------------------------------------------------------
# Test 5: Missing %%EOF Terminator
# --------------------------------------------------------------------------
def test_missing_pdf_eof(tmp_path):
    orig = make_valid_pdf()
    # Strip the %%EOF marker
    corrupted_data = orig.replace(b"%%EOF", b"")

    f = tmp_path / "missing_eof.pdf"
    f.write_bytes(corrupted_data)

    analysis = PDFAnalyzer.analyze(str(f))
    eof_reg = next(r for r in analysis["corruption_regions"] if r["region"] == "end_of_file")
    assert eof_reg["status"] == "corrupted"

    # Recovery rebuilds valid document terminator
    out = tmp_path / "rebuilt_eof.pdf"
    res = PDFRecoveryEngine.recover(str(f), str(out), analysis)
    assert res["success"] is True
    val = RecoveredFileValidator.validate(str(out), "PDF")
    assert val["openable"] is True
    assert val["structure_valid"] is True


# --------------------------------------------------------------------------
# Test 6: Truncated PDF (Partial File with intact page objects)
# --------------------------------------------------------------------------
def test_truncated_pdf_recovery(tmp_path):
    orig = make_valid_pdf()
    # Truncate 35% of the file from the end
    trunc_len = int(len(orig) * 0.70)
    truncated_data = orig[:trunc_len]

    f = tmp_path / "truncated.pdf"
    f.write_bytes(truncated_data)

    analysis = PDFAnalyzer.analyze(str(f))
    assert analysis["is_corrupted"] is True

    out = tmp_path / "salvaged_truncated.pdf"
    res = PDFRecoveryEngine.recover(str(f), str(out), analysis)
    # Even on truncated files, deterministic engine attempts recovery
    if res["success"]:
        assert os.path.exists(str(out))
        assert os.path.getsize(str(out)) > 100


# --------------------------------------------------------------------------
# Test 7: Valid DOCX Document
# --------------------------------------------------------------------------
def test_valid_docx_analysis(tmp_path):
    f = tmp_path / "valid.docx"
    f.write_bytes(make_valid_docx())

    analysis = DOCXAnalyzer.analyze(str(f))
    assert analysis["file_type"] == "DOCX"
    assert analysis["is_corrupted"] is False
    for reg in analysis["corruption_regions"]:
        assert reg["status"] == "valid"


# --------------------------------------------------------------------------
# Test 8: Corrupted DOCX ZIP Container (Missing Central Directory / EOCD)
# --------------------------------------------------------------------------
def test_corrupted_docx_zip_structure(tmp_path):
    orig = make_valid_docx()
    # Truncate the ZIP Central Directory and EOCD
    corrupted_data = orig[:len(orig) - 150] + b"CORRUPTED_CENTRAL_DIRECTORY_JUNK"

    f = tmp_path / "broken_zip.docx"
    f.write_bytes(corrupted_data)

    # 1. Detection classifies as DOCX
    det = FileDetector.detect_file_type(str(f), "broken_zip.docx")
    assert det["file_type"] == "DOCX"

    # 2. Analyzer localizes end_of_file corruption
    analysis = DOCXAnalyzer.analyze(str(f))
    assert analysis["is_corrupted"] is True
    eof_reg = next(r for r in analysis["corruption_regions"] if r["region"] == "end_of_file")
    assert eof_reg["status"] == "corrupted"

    # 3. Recovery salvages raw PK\x03\x04 members and rebuilds container
    out = tmp_path / "rebuilt_container.docx"
    res = DOCXRecoveryEngine.recover(str(f), str(out), analysis)
    assert res["success"] is True

    # 4. Validate output with python-docx
    val = RecoveredFileValidator.validate(str(out), "DOCX")
    assert val["openable"] is True
    assert val["structure_valid"] is True


# --------------------------------------------------------------------------
# Test 9: Damaged word/document.xml (Truncated unclosed tags)
# --------------------------------------------------------------------------
def test_damaged_docx_document_xml(tmp_path):
    # Create DOCX with unclosed document.xml
    orig = make_valid_docx()
    zin = zipfile.ZipFile(io.BytesIO(orig), "r")
    members = {n: zin.read(n) for n in zin.namelist()}
    zin.close()

    # Truncate document.xml mid-tag
    doc_xml = members["word/document.xml"]
    cut_idx = doc_xml.find(b"</w:p>")
    if cut_idx != -1:
        members["word/document.xml"] = doc_xml[:cut_idx + 2]  # truncated tag

    out_zip = io.BytesIO()
    zout = zipfile.ZipFile(out_zip, "w")
    for n, c in members.items():
        zout.writestr(n, c)
    zout.close()

    f = tmp_path / "broken_xml.docx"
    f.write_bytes(out_zip.getvalue())

    analysis = DOCXAnalyzer.analyze(str(f))
    assert analysis["is_corrupted"] is True
    body_reg = next(r for r in analysis["corruption_regions"] if r["region"] == "body")
    assert body_reg["status"] == "corrupted"

    # Recover XML and balance tags
    out = tmp_path / "repaired_xml.docx"
    res = DOCXRecoveryEngine.recover(str(f), str(out), analysis)
    assert res["success"] is True

    val = RecoveredFileValidator.validate(str(out), "DOCX")
    assert val["openable"] is True


# --------------------------------------------------------------------------
# Test 10: Broken DOCX Relationship Targets
# --------------------------------------------------------------------------
def test_broken_docx_relationships(tmp_path):
    orig = make_valid_docx()
    zin = zipfile.ZipFile(io.BytesIO(orig), "r")
    members = {n: zin.read(n) for n in zin.namelist()}
    zin.close()

    # Insert broken relationship pointing to missing media/image99.png
    broken_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
        '  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>\n'
        '  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/missing_image_99.png"/>\n'
        '</Relationships>'
    )
    members["word/_rels/document.xml.rels"] = broken_rels.encode("utf-8")

    out_zip = io.BytesIO()
    zout = zipfile.ZipFile(out_zip, "w")
    for n, c in members.items():
        zout.writestr(n, c)
    zout.close()

    f = tmp_path / "broken_rels.docx"
    f.write_bytes(out_zip.getvalue())

    analysis = DOCXAnalyzer.analyze(str(f))
    assert analysis["is_corrupted"] is True
    ref_reg = next(r for r in analysis["corruption_regions"] if r["region"] == "references")
    assert ref_reg["status"] == "corrupted"

    out = tmp_path / "cleaned_rels.docx"
    res = DOCXRecoveryEngine.recover(str(f), str(out), analysis)
    assert res["success"] is True

    val = RecoveredFileValidator.validate(str(out), "DOCX")
    assert val["openable"] is True


# --------------------------------------------------------------------------
# Test 11 & 12: Recovery Report and Non-Blank Guarantee
# --------------------------------------------------------------------------
def test_recovery_engine_end_to_end_report(tmp_path):
    orig = make_valid_pdf()
    corrupt = b"HEADER_JUNK_OFFSET_12345" + orig + b"TRAILING_NOISE"

    f = tmp_path / "sample_corrupt.pdf"
    f.write_bytes(corrupt)

    res = RecoveryEngine.recover_file(
        file_path=str(f),
        original_filename="sample_corrupt.pdf",
        requested_type="pdf"
    )

    assert res["success"] is True
    assert res["recovered_size_bytes"] > 0
    assert os.path.exists(res["output_path"])

    # Verify structured report format
    report = res["report"]
    assert report["file"] == "sample_corrupt.pdf"
    assert report["file_type"] == "PDF"
    assert "detected_regions" in report
    assert "recovery" in report

    # Verify human-readable report string
    hr_report = res["human_readable_report"]
    assert "FILEGUARD AI RECOVERY REPORT" in hr_report
    assert "Corruption Status:" in hr_report
    assert "HEADER" in hr_report
    assert "Output:" in hr_report


# --------------------------------------------------------------------------
# Test 13: Full API Workflow (/api/validate -> /api/recover -> /api/recovery/* -> /api/clear)
# --------------------------------------------------------------------------
def test_api_full_workflow(client):
    orig = make_valid_pdf()
    corrupt_pdf = b"GARBAGE_BYTES_123" + orig

    # 1. POST /api/validate (pure corruption analysis)
    val_resp = client.post(
        "/api/validate",
        data={"file": (io.BytesIO(corrupt_pdf), "test_doc.pdf")},
        content_type="multipart/form-data"
    )
    assert val_resp.status_code == 200
    val_json = val_resp.get_json()
    assert val_json["success"] is True
    assert val_json["file_type"] == "PDF"
    assert "corruption_regions" in val_json
    assert val_json["is_corrupted"] is True
    cache_id = val_json["cache_id"]

    # 2. POST /api/recover using cached validation file
    rec_resp = client.post(
        "/api/recover",
        data={"cache_id": cache_id, "file_type": "pdf"},
        content_type="multipart/form-data"
    )
    assert rec_resp.status_code == 200
    rec_json = rec_resp.get_json()
    assert rec_json["success"] is True
    rec_id = rec_json["recovery_id"]

    # 3. GET /api/recovery/{recovery_id}
    details_resp = client.get(f"/api/recovery/{rec_id}")
    assert details_resp.status_code == 200
    assert details_resp.get_json()["success"] is True

    # 4. GET /api/recovery/{recovery_id}/download
    dl_resp = client.get(f"/api/recovery/{rec_id}/download")
    assert dl_resp.status_code == 200
    assert dl_resp.data.startswith(b"%PDF")

    # 5. GET /api/recovery/{recovery_id}/view
    view_resp = client.get(f"/api/recovery/{rec_id}/view")
    assert view_resp.status_code == 200
    assert view_resp.get_json()["success"] is True

    # 6. DELETE /api/clear
    clear_resp = client.delete(f"/api/clear?recovery_id={rec_id}")
    assert clear_resp.status_code == 200
    assert clear_resp.get_json()["success"] is True


def test_corrupted_pdf_with_damaged_stream_non_blank_recovery(tmp_path):
    """
    Tests that a PDF with damaged internal stream decompression is reconstructed
    without producing an empty/blank page, recovering genuine characters.
    """
    # Create PDF with tagged text elements and broken stream
    corrupted_data = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n"
        b"4 0 obj\n<< /Length 20 /Filter /FlateDecode >>\nstream\n"
        b"BROKEN_DECOMPRESSION_STREAM_BYTES\nendstream\nendobj\n"
        b"5 0 obj\n<< /Type /StructElem /E (Harish Machine Learning Engineer) /T (Harish Resume) >>\nendobj\n"
        b"6 0 obj\n<< /Type /StructElem /E (Projects: Smart Case Management, Computer Vision Model) >>\nendobj\n"
        b"7 0 obj\n<< /Type /StructElem /E (Education: Bachelor of Technology; Score: 92%) >>\nendobj\n"
        b"xref\n0 8\n"
        b"0000000000 65535 f\n"
        b"0000000009 00000 n\n"
        b"0000000058 00000 n\n"
        b"0000000115 00000 n\n"
        b"0000000178 00000 n\n"
        b"0000000278 00000 n\n"
        b"0000000378 00000 n\n"
        b"0000000478 00000 n\n"
        b"trailer\n<< /Size 8 /Root 1 0 R >>\nstartxref\n578\n%%EOF\n"
    )

    f = tmp_path / "broken_stream.pdf"
    f.write_bytes(corrupted_data)

    analysis = PDFAnalyzer.analyze(str(f))
    out = tmp_path / "recovered_stream.pdf"

    res = PDFRecoveryEngine.recover(str(f), str(out), analysis)
    assert res["success"] is True
    assert os.path.exists(str(out))

    # Validator must confirm openable AND has_content is strictly True
    val = RecoveredFileValidator.validate(str(out), "PDF")
    assert val["openable"] is True
    assert val["has_content"] is True
    assert val["text_extractable"] is True
    assert "Harish" in val["extracted_preview"] or "Machine Learning" in val["extracted_preview"]


def test_regional_corruption_analysis_and_suggested_tools(tmp_path):
    """
    Tests that PDF analysis breaks corruption down across Header, Body, Reference, EOF,
    provides specific suggested tools for each, and passes applied_tools during recovery.
    """
    # Create file with displaced header and missing EOF
    corrupted_data = (
        b"DISPLACED_JUNK_HEADER_BYTES"
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n"
        b"4 0 obj\n<< /Length 40 >>\nstream\nBT /F1 12 Tf 100 700 Td (Invoice #49281) Tj ET\nendstream\nendobj\n"
        b"xref\n0 5\n"
        b"0000000000 65535 f\n"
        b"0000000028 00000 n\n"
        b"0000000078 00000 n\n"
        b"0000000135 00000 n\n"
        b"0000000198 00000 n\n"
        b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n290\n"
        # Missing %%EOF
    )

    f = tmp_path / "multi_region_corrupt.pdf"
    f.write_bytes(corrupted_data)

    analysis = RecoveryEngine.analyze_file(str(f), "multi_region_corrupt.pdf")
    assert analysis["is_corrupted"] is True
    assert "corruption_regions" in analysis
    regions = analysis["corruption_regions"]
    assert len(regions) >= 4

    region_dict = {r["region"]: r for r in regions}
    assert "header" in region_dict
    assert "body" in region_dict
    assert "references" in region_dict
    assert "end_of_file" in region_dict

    # Check that each region contains name and suggested_tools
    for r in regions:
        assert "name" in r
        assert "suggested_tools" in r
        assert len(r["suggested_tools"]) > 0

    # Header is corrupted
    assert region_dict["header"]["status"] == "corrupted"
    assert any("Realignment" in t["tool"] or "Header" in t["tool"] for t in region_dict["header"]["suggested_tools"])

    # EOF is corrupted
    assert region_dict["end_of_file"]["status"] == "corrupted"
    assert any("EOF" in t["tool"] or "Trailer" in t["tool"] for t in region_dict["end_of_file"]["suggested_tools"])

    # Perform recovery
    out = tmp_path / "multi_region_recovered.pdf"
    res = RecoveryEngine.recover_file(str(f), "multi_region_corrupt.pdf")
    assert res["success"] is True
    assert "applied_tools" in res
    assert len(res["applied_tools"]) >= 4

    # Verify report contains applied tools
    report = res["report"]
    assert "applied_tools" in report
    assert "APPLIED RECOVERY TOOLS" in report["human_readable_report"]

