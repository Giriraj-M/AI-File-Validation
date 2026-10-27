import io
import os
import pytest
from app import app
from services.corruption_service import FileCorruptor
from services.corruption_history_service import CorruptionHistoryService
from services.corruption_report_service import CorruptionReportService


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def make_test_pdf() -> bytes:
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n"
        b"4 0 obj\n<< /Length 44 >>\nstream\nBT /F1 12 Tf 72 712 Td (Confidential Document) Tj ET\nendstream\nendobj\n"
        b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000210 00000 n \n"
        b"trailer\n<< /Size 5 /Root 1 0 R >>\n"
        b"startxref\n308\n%%EOF\n"
    )


def test_corrupt_header_only(tmp_path):
    orig_path = tmp_path / "orig_header.pdf"
    orig_path.write_bytes(make_test_pdf())
    out_path = tmp_path / "corrupt_header.pdf"

    res = FileCorruptor.corrupt_file(str(orig_path), str(out_path), ["header"])
    assert res["success"] is True
    assert res["structure_matrix"]["header"] == "CORRUPTED"
    assert res["structure_matrix"]["body"] == "INTACT"
    assert res["structure_matrix"]["reference"] == "INTACT"
    assert res["structure_matrix"]["end_of_file"] == "INTACT"
    assert os.path.exists(str(out_path))


def test_corrupt_body_only(tmp_path):
    orig_path = tmp_path / "orig_body.pdf"
    orig_path.write_bytes(make_test_pdf())
    out_path = tmp_path / "corrupt_body.pdf"

    res = FileCorruptor.corrupt_file(str(orig_path), str(out_path), ["body"])
    assert res["success"] is True
    assert res["structure_matrix"]["body"] == "CORRUPTED"
    assert res["structure_matrix"]["header"] == "INTACT"
    assert res["structure_matrix"]["reference"] == "INTACT"
    assert res["structure_matrix"]["end_of_file"] == "INTACT"


def test_corrupt_reference_only(tmp_path):
    orig_path = tmp_path / "orig_ref.pdf"
    orig_path.write_bytes(make_test_pdf())
    out_path = tmp_path / "corrupt_ref.pdf"

    res = FileCorruptor.corrupt_file(str(orig_path), str(out_path), ["reference"])
    assert res["success"] is True
    assert res["structure_matrix"]["reference"] == "CORRUPTED"
    assert res["structure_matrix"]["header"] == "INTACT"
    assert res["structure_matrix"]["body"] == "INTACT"
    assert res["structure_matrix"]["end_of_file"] == "INTACT"


def test_corrupt_eof_only(tmp_path):
    orig_path = tmp_path / "orig_eof.pdf"
    orig_path.write_bytes(make_test_pdf())
    out_path = tmp_path / "corrupt_eof.pdf"

    res = FileCorruptor.corrupt_file(str(orig_path), str(out_path), ["end_of_file"])
    assert res["success"] is True
    assert res["structure_matrix"]["end_of_file"] == "CORRUPTED"
    assert res["structure_matrix"]["header"] == "INTACT"
    assert res["structure_matrix"]["body"] == "INTACT"
    assert res["structure_matrix"]["reference"] == "INTACT"


def test_corrupt_all_sections(tmp_path):
    orig_path = tmp_path / "orig_all.pdf"
    orig_path.write_bytes(make_test_pdf())
    out_path = tmp_path / "corrupt_all.pdf"

    res = FileCorruptor.corrupt_file(str(orig_path), str(out_path), ["all"])
    assert res["success"] is True
    assert res["is_all"] is True
    assert res["structure_matrix"]["header"] == "CORRUPTED"
    assert res["structure_matrix"]["body"] == "CORRUPTED"
    assert res["structure_matrix"]["reference"] == "CORRUPTED"
    assert res["structure_matrix"]["end_of_file"] == "CORRUPTED"
    assert res["structure_matrix"]["images"] == "CORRUPTED"


def test_api_upload_download_and_report(client):
    pdf_bytes = make_test_pdf()
    data = {
        "file": (io.BytesIO(pdf_bytes), "sample_doc.pdf"),
        "targets[]": ["header", "body"]
    }
    resp = client.post("/api/corrupt/upload", data=data, content_type="multipart/form-data")
    assert resp.status_code == 200
    res = resp.get_json()["data"]
    corr_id = res["id"]
    assert res["original_filename"] == "sample_doc.pdf"
    assert res["corrupted_filename"] == "corrupted_sample_doc.pdf"

    # Download corrupted file
    dl_resp = client.get(f"/api/corrupt/download/{corr_id}")
    assert dl_resp.status_code == 200
    assert len(dl_resp.data) > 0
    assert "corrupted_sample_doc.pdf" in dl_resp.headers.get("Content-Disposition", "")

    # HTML report view (verify no print or download button in the report)
    rep_resp = client.get(f"/api/corrupt/report/{corr_id}")
    assert rep_resp.status_code == 200
    assert b"Forensic Corruption Audit Report" in rep_resp.data
    assert b"Print / Save PDF" not in rep_resp.data
    assert b"Download Corrupted File" not in rep_resp.data

    # JSON report
    json_resp = client.get(f"/api/corrupt/report/{corr_id}/json")
    assert json_resp.status_code == 200
    assert json_resp.get_json()["record"]["id"] == corr_id

    # Individual delete
    del_resp = client.post(f"/api/corrupt/delete/{corr_id}")
    assert del_resp.status_code == 200

    # Clear all
    clear_resp = client.post("/api/corrupt/clear-all")
    assert clear_resp.status_code == 200
