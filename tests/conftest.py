import pytest
import shutil
from config import Config
from app import app

@pytest.fixture(autouse=True)
def isolate_test_history(tmp_path, monkeypatch):
    """
    Safeguards the development and production databases during test runs.
    Redirects recovery and validation history storage and file folders to pytest temp dirs.
    """
    test_recovery_hist = tmp_path / "test_recovery_history.json"
    test_val_hist = tmp_path / "test_validation_history.json"
    test_recovered_folder = tmp_path / "recovered_files"
    test_recovered_folder.mkdir(exist_ok=True)
    test_uploads = tmp_path / "uploads"
    test_uploads.mkdir(exist_ok=True)

    monkeypatch.setattr(Config, "RECOVERY_HISTORY_FILE", str(test_recovery_hist))
    monkeypatch.setattr(Config, "HISTORY_FILE", str(test_val_hist))
    monkeypatch.setattr(Config, "RECOVERED_FOLDER", str(test_recovered_folder))
    monkeypatch.setattr(Config, "UPLOAD_FOLDER", str(test_uploads))

    # Also update Flask app config
    app.config["RECOVERY_HISTORY_FILE"] = str(test_recovery_hist)
    app.config["HISTORY_FILE"] = str(test_val_hist)
    app.config["RECOVERED_FOLDER"] = str(test_recovered_folder)
    app.config["UPLOAD_FOLDER"] = str(test_uploads)
    app.config["TESTING"] = True
