import os
import json
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from config import Config
from utils.file_utils import cleanup_file

# Indian Standard Time (IST = UTC+5:30)
IST = timezone(timedelta(hours=5, minutes=30))

class RecoveryHistoryService:
    """
    Audit log and storage manager for AI file recoveries.
    Tracks metadata and manages physical recovered files in instance/recovered_files/.
    """

    MAX_HISTORY_ITEMS = 100

    @classmethod
    def record_recovery(cls, record: dict) -> str:
        """Saves a recovery run and returns the assigned recovery ID."""
        history = cls._load_history()
        rec_id = f"rec_{uuid.uuid4().hex[:10]}"
        
        entry = {
            "id": rec_id,
            "timestamp": datetime.now(IST).strftime("%Y-%m-%d %I:%M:%S %p IST"),
            "filename": record.get("filename", "unknown"),
            "original_type": record.get("original_type", "Unknown"),
            "recovered_type": record.get("recovered_type", "Unknown"),
            "original_size_human": record.get("original_size_human", "0 B"),
            "recovered_size_human": record.get("recovered_size_human", "0 B"),
            "original_size_bytes": record.get("original_size_bytes", 0),
            "recovered_size_bytes": record.get("recovered_size_bytes", 0),
            "status": record.get("status", "recovered"),
            "confidence": record.get("confidence", "high"),
            "confidence_score": record.get("confidence_score", 90),
            "integrity_before": record.get("integrity_before", "Corrupted"),
            "integrity_after": record.get("integrity_after", "Intact"),
            "corruption_area": record.get("corruption_area", "Reference"),
            "recovery_method": record.get("recovery_method", "AI Reconstruction"),
            "storage_filename": record.get("storage_filename", ""),
            "preview_snippet": record.get("preview_snippet", ""),
            "summary": record.get("summary", ""),
            "report": record.get("report", {})
        }
        
        history.insert(0, entry)
        if len(history) > cls.MAX_HISTORY_ITEMS:
            # Clean up old file if pruned
            pruned = history[cls.MAX_HISTORY_ITEMS:]
            for old_item in pruned:
                cls._delete_storage_file(old_item.get("storage_filename"))
            history = history[:cls.MAX_HISTORY_ITEMS]
            
        cls._save_history(history)
        return rec_id

    @classmethod
    def get_recent_recoveries(cls, limit: int = 50) -> list[dict]:
        """Returns recent recovery records."""
        history = cls._load_history()
        return history[:limit]

    @classmethod
    def get_stats(cls) -> dict:
        """Calculates aggregated metrics and type distribution for recovery audit history."""
        history = cls._load_history()
        total = len(history)
        if total == 0:
            return {
                "total_recovered": 0,
                "successful_count": 0,
                "partial_count": 0,
                "failed_count": 0,
                "success_rate": 0,
                "avg_score": 0,
                "type_breakdown": {}
            }

        successful = sum(1 for r in history if r.get("status") in ["FULLY_RECOVERED", "SUCCESS", "recovered", "passed"])
        partial = sum(1 for r in history if r.get("status") in ["PARTIALLY_RECOVERED", "PARTIAL", "partial"])
        failed = total - (successful + partial)
        avg_score = round(sum(r.get("confidence_score", 90) for r in history) / total, 1)
        success_rate = round((successful / total) * 100, 1)

        type_counts = {}
        for r in history:
            t = r.get("recovered_type") or r.get("original_type") or "Other"
            t = t.upper()
            type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "total_recovered": total,
            "successful_count": successful,
            "partial_count": partial,
            "failed_count": failed,
            "success_rate": success_rate,
            "avg_score": avg_score,
            "type_breakdown": type_counts
        }

    @classmethod
    def get_recovery_by_id(cls, rec_id: str) -> dict | None:
        """Finds a single recovery by ID."""
        history = cls._load_history()
        for item in history:
            if item.get("id") == rec_id:
                return item
        return None

    @classmethod
    def delete_recovery(cls, rec_id: str) -> bool:
        """Deletes a single recovery entry and its physical file."""
        history = cls._load_history()
        target_idx = None
        target_item = None
        for i, item in enumerate(history):
            if item.get("id") == rec_id:
                target_idx = i
                target_item = item
                break

        if target_idx is not None and target_item:
            cls._delete_storage_file(target_item.get("storage_filename"))
            history.pop(target_idx)
            cls._save_history(history)
            return True
        return False

    @classmethod
    def clear_all(cls) -> int:
        """Clears all recovery audit logs and cleans up all recovered files."""
        history = cls._load_history()
        count = len(history)
        for item in history:
            cls._delete_storage_file(item.get("storage_filename"))
        cls._save_history([])
        return count

    @classmethod
    def _delete_storage_file(cls, storage_filename: str) -> None:
        if not storage_filename:
            return
        file_path = os.path.join(Config.RECOVERED_FOLDER, storage_filename)
        cleanup_file(file_path)

    @classmethod
    def _load_history(cls) -> list[dict]:
        file_path = Config.RECOVERY_HISTORY_FILE
        if not os.path.exists(file_path):
            return []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    @classmethod
    def _save_history(cls, history: list[dict]) -> None:
        file_path = Config.RECOVERY_HISTORY_FILE
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2)
        except Exception:
            pass
