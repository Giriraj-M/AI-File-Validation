import os
from unittest.mock import patch
from pathlib import Path
import pytest
from utils.file_utils import ensure_upload_directory

def test_ensure_upload_directory_handles_oserror(caplog):
    """Verifies ensure_upload_directory does not crash on read-only file systems (OSError)."""
    with patch("os.makedirs", side_effect=OSError(30, "Read-only file system", "/var/task/instance/uploads")):
        # Should not raise exception
        ensure_upload_directory("/var/task/instance/uploads")
    
    assert "Could not create storage directory" in caplog.text

def test_vercel_path_resolution(monkeypatch):
    """Verifies that on Vercel (VERCEL=1), storage paths resolve to /tmp/ai-file-validation/."""
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.delenv("UPLOAD_FOLDER", raising=False)
    monkeypatch.delenv("RECOVERED_FOLDER", raising=False)
    monkeypatch.delenv("HISTORY_FILE", raising=False)
    
    import importlib
    import config
    importlib.reload(config)
    
    assert config.IS_VERCEL is True
    assert config.Config.UPLOAD_FOLDER.startswith("/tmp/ai-file-validation") or "/tmp" in config.Config.UPLOAD_FOLDER
    assert config.Config.RECOVERED_FOLDER.startswith("/tmp/ai-file-validation") or "/tmp" in config.Config.RECOVERED_FOLDER
    assert config.Config.HISTORY_FILE.startswith("/tmp/ai-file-validation") or "/tmp" in config.Config.HISTORY_FILE
    
    # Reload again without VERCEL to restore local state
    monkeypatch.delenv("VERCEL", raising=False)
    importlib.reload(config)
