import os
import io
import json
import pytest
from pathlib import Path
from pypdf import PdfWriter

from app import app
from services.pdf_analyzer import PDFAnalyzer
from services.pdf_recovery import PDFRecoveryEngine
from services.recovery_engine import RecoveryEngine
from services.recovery_report import RecoveryReportGenerator
from services.validator import RecoveredFileValidator


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def make_sample_pdf(pages: int = 3, text_content: str = "Quarterly Financial Analysis and Audit Log") -> bytes:
    """Creates a valid multi-page PDF with readable streams."""
    writer = PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(width=612, height=792)
    buf = io.BytesIO()
    writer.write(buf)
    data = buf.getvalue()
    # Inject text stream
    return data + f"\n% Text: {text_content}\n".encode("utf-8")


def test_header_corruption_classification(tmp_path):
    orig = make_sample_pdf()
    corrupt_data = b"GARBAGE_BYTES_CORRUPTION_PREFIX_12345" * 4 + orig
    f = tmp_path / "header_corrupt.pdf"
    f.write_bytes(corrupt_data)

    analysis = PDFAnalyzer.analyze(str(f))
    assert analysis["is_corrupted"] is True
    assert "Header corruption" in analysis["classification"]
    assert analysis["structure_matrix"]["header"]["status"] == "CORRUPTED"
    assert any("Displaced" in r.get("reason", "") for r in analysis["corruption_regions"] if r["region"] == "header")
    assert len(analysis["recommended_tools"]) > 0


def test_xref_and_startxref_corruption_classification(tmp_path):
    orig = make_sample_pdf()
    corrupt_data = orig.replace(b"startxref", b"startxref_broken").replace(b"xref", b"xxxx")
    f = tmp_path / "xref_corrupt.pdf"
    f.write_bytes(corrupt_data)

    analysis = PDFAnalyzer.analyze(str(f))
    assert analysis["is_corrupted"] is True
    assert "startxref corruption" in analysis["classification"] or "Cross-reference (xref) corruption" in analysis["classification"]
    assert analysis["structure_matrix"]["xref"]["status"] == "CORRUPTED"
    assert any("qpdf" in t["tool"].lower() for t in analysis["recommended_tools"])


def test_missing_eof_and_truncation_classification(tmp_path):
    orig = make_sample_pdf(pages=4)
    # Physically truncate the file to simulate half-written transfer
    truncated_data = orig[:len(orig) // 2]
    f = tmp_path / "truncated.pdf"
    f.write_bytes(truncated_data)

    analysis = PDFAnalyzer.analyze(str(f))
    assert analysis["is_corrupted"] is True
    assert "EOF corruption" in analysis["classification"] or "Missing/truncated data" in analysis["classification"]
    assert analysis["structure_matrix"]["eof"]["status"] == "CORRUPTED"


def test_intelligent_pipeline_recovery_and_confidence(tmp_path):
    orig = make_sample_pdf(pages=3, text_content="Executive Revenue Summary 2026")
    # Break xref table and displaced header
    damaged_data = b"PREPENDED_CORRUPTION\n" + orig.replace(b"startxref", b"startxref_lost")
    f = tmp_path / "damaged_report.pdf"
    f.write_bytes(damaged_data)

    res = RecoveryEngine.recover_file(str(f), "damaged_report.pdf", requested_type="pdf")
    assert res["success"] is True
    assert os.path.exists(res["output_path"])
    
    rep = res["report"]
    assert rep["confidence_score"] > 0
    assert "%" in rep["confidence"]
    assert len(rep["recovered_items"]) > 0
    assert len(rep["lost_items"]) > 0
    assert "html_report" in rep
    assert "<!DOCTYPE html>" in rep["html_report"]
    assert "PDF Recovery & Diagnostic Audit" in rep["html_report"]


def test_api_report_downloads(client, tmp_path):
    orig = make_sample_pdf(pages=2, text_content="Confidential Audit File")
    damaged = b"JUNK_DATA_OFFSET\n" + orig
    
    # Upload and recover via API
    response = client.post(
        "/api/recover",
        data={
            "file": (io.BytesIO(damaged), "audit_sample.pdf"),
            "file_type": "pdf"
        },
        content_type="multipart/form-data"
    )
    assert response.status_code == 200
    res_data = response.get_json()
    assert res_data["success"] is True
    rec_id = res_data["recovery_id"]

    # Test downloading report.json
    json_resp = client.get(f"/api/recovery/{rec_id}/report.json")
    assert json_resp.status_code == 200
    json_data = json_resp.get_json()
    assert json_data["file"] == "audit_sample.pdf"
    assert json_data["recovery"]["output_filename"] == "audit_sample_recovered.pdf"
    assert "recovery" in json_data
    assert "structure_matrix" in json_data

    # Test downloading report.html
    html_resp = client.get(f"/api/recovery/{rec_id}/report.html")
    assert html_resp.status_code == 200
    assert b"<!DOCTYPE html>" in html_resp.data
    assert b"Confidence Score" in html_resp.data

