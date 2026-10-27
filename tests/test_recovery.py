import os
import io
import pytest
from app import app
from config import Config
from services.recovery_service import RecoveryService
from services.recovery_history_service import RecoveryHistoryService

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_recovery_pdf_not_blank(tmp_path):
    """Verifies that recovering a corrupted PDF results in a valid non-blank PDF document."""
    # Create an intentionally broken PDF (truncated stream, broken xref)
    corrupted_pdf = tmp_path / "broken.pdf"
    corrupted_pdf.write_bytes(b"%PDF-1.4\n1 0 obj\n<< /Title (Confidential Agreement) >>\nstream\nBT /F1 12 Tf (This is a restored contract clause) Tj ET\nendstream\ncorrupted_data_junk_###")

    result = RecoveryService.recover_file(
        corrupted_path=str(corrupted_pdf),
        original_filename="broken.pdf",
        requested_type="pdf"
    )

    assert result["success"] is True
    assert result["recovered_type"] == "PDF"
    assert result["recovered_size_bytes"] > 0
    assert os.path.exists(result["recovered_path"])

    # Verify that the generated PDF is non-blank (size > 1000 bytes with readable streams)
    with open(result["recovered_path"], "rb") as f:
        pdf_bytes = f.read()
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 500

def test_recovery_docx_not_blank(tmp_path):
    """Verifies that recovering a damaged DOCX produces a valid Word document."""
    corrupted_docx = tmp_path / "broken.docx"
    corrupted_docx.write_bytes(b"PK\x03\x04corrupted_zip_header<w:t>Quarterly Financial Results</w:t><w:t>Revenue: $5,000,000</w:t>trailer_junk")

    result = RecoveryService.recover_file(
        corrupted_path=str(corrupted_docx),
        original_filename="broken.docx",
        requested_type="word"
    )

    assert result["success"] is True
    assert result["recovered_type"] == "WORD"
    assert result["recovered_size_bytes"] > 0
    assert os.path.exists(result["recovered_path"])

def test_recovery_xlsx_not_blank(tmp_path):
    """Verifies that recovering damaged Excel data builds a valid workbook."""
    corrupted_xlsx = tmp_path / "broken.xlsx"
    corrupted_xlsx.write_bytes(b"PK\x03\x04corrupted_stream|Item 1|Value 100|\n|Item 2|Value 200|")

    result = RecoveryService.recover_file(
        corrupted_path=str(corrupted_xlsx),
        original_filename="broken.xlsx",
        requested_type="excel"
    )

    assert result["success"] is True
    assert result["recovered_type"] == "EXCEL"
    assert result["recovered_size_bytes"] > 0

def test_recovery_csv_text_not_blank(tmp_path):
    """Verifies that recovering damaged CSV/TXT removes nulls and formats clean UTF-8."""
    corrupted_csv = tmp_path / "broken.csv"
    corrupted_csv.write_bytes(b"name,amount,status\x00\x00\nJohn Doe,1250,Paid\nJane Smith,3400,Pending\x00\xff")

    result = RecoveryService.recover_file(
        corrupted_path=str(corrupted_csv),
        original_filename="broken.csv",
        requested_type="csv"
    )

    assert result["success"] is True
    assert os.path.exists(result["recovered_path"])
    with open(result["recovered_path"], "r", encoding="utf-8") as f:
        content = f.read()
    assert "\x00" not in content
    assert "John Doe" in content

def test_recovery_history_lifecycle():
    """Tests recording, viewing, deleting, and clearing recovery logs."""
    rec_id = RecoveryHistoryService.record_recovery({
        "filename": "test_doc_recovered.pdf",
        "original_type": "PDF",
        "recovered_type": "PDF",
        "original_size_human": "1.2 MB",
        "recovered_size_human": "1.4 MB",
        "original_size_bytes": 1200000,
        "recovered_size_bytes": 1400000,
        "status": "recovered",
        "integrity_before": "Corrupted",
        "integrity_after": "Intact",
        "recovery_method": "AI Reconstruction",
        "storage_filename": "test_storage.pdf",
        "preview_snippet": "Test snippet content.",
        "summary": "Document recovered."
    })

    assert rec_id.startswith("rec_")
    record = RecoveryHistoryService.get_recovery_by_id(rec_id)
    assert record is not None
    assert record["filename"] == "test_doc_recovered.pdf"

    # Delete single item
    deleted = RecoveryHistoryService.delete_recovery(rec_id)
    assert deleted is True
    assert RecoveryHistoryService.get_recovery_by_id(rec_id) is None

def test_api_recover_flow(client):
    """Tests the full HTTP API flow for the /recover page and /api/recover endpoints."""
    # 1. GET /recover page
    res_page = client.get("/recover")
    assert res_page.status_code == 200
    assert b"AI Document Recovery Engine" in res_page.data

    # 2. POST /api/recover with a file
    broken_content = b"%PDF-1.4 damaged file with contract text: Party A agrees to terms."
    data = {
        "file": (io.BytesIO(broken_content), "damaged_contract.pdf"),
        "file_type": "pdf"
    }
    res_rec = client.post("/api/recover", data=data, content_type="multipart/form-data")
    assert res_rec.status_code == 200
    rec_json = res_rec.get_json()
    assert rec_json["success"] is True
    rec_id = rec_json["recovery_id"]

    # 3. GET /api/recover/view/<id>
    res_view = client.get(f"/api/recover/view/{rec_id}")
    assert res_view.status_code == 200
    view_json = res_view.get_json()
    assert view_json["success"] is True
    assert "content" in view_json

    # 4. GET /api/recover/download/<id>
    res_down = client.get(f"/api/recover/download/{rec_id}")
    assert res_down.status_code == 200
    assert len(res_down.data) > 0

    # 5. POST /api/recover/validate/<id>
    res_val = client.post(f"/api/recover/validate/{rec_id}", data={"prompt": "Validate PDF"})
    assert res_val.status_code == 200
    val_json = res_val.get_json()
    assert val_json["success"] is True
    assert val_json["validation_status"] == "passed"
    assert val_json["score"] == 100

    # 6. DELETE /api/recover/delete/<id>
    res_del = client.post(f"/api/recover/delete/{rec_id}")
    assert res_del.status_code == 200
    assert res_del.get_json()["success"] is True

    # 7. POST /api/recover/clear-all
    res_clear = client.post("/api/recover/clear-all")
    assert res_clear.status_code == 200
    assert res_clear.get_json()["success"] is True
