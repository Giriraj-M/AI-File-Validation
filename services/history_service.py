import os
import json
import uuid
from datetime import datetime, timezone, timedelta
from config import Config

# Indian Standard Time (IST = UTC+5:30)
IST = timezone(timedelta(hours=5, minutes=30))

class HistoryService:
    """
    Lightweight, privacy-preserving audit log and stats tracking for validations.
    Persists non-sensitive metadata (timestamp, filename, status, score, violations).
    """

    MAX_HISTORY_ITEMS = 100

    @classmethod
    def record_validation(cls, record: dict) -> str:
        """Saves a validation run and returns the assigned validation ID."""
        history = cls._load_history()
        val_id = f"val_{uuid.uuid4().hex[:10]}"
        
        entry = {
            "id": val_id,
            "timestamp": datetime.now(IST).strftime("%Y-%m-%d %I:%M:%S %p IST"),
            "filename": record.get("filename", "unknown"),
            "detected_type": record.get("detected_type", "Unknown"),
            "file_size_human": record.get("file_size_human", "0 B"),
            "status": record.get("status", "failed"),
            "score": record.get("score", 0),
            "prompt": record.get("prompt", ""),
            "violations": record.get("violations", []),
            "ai_analysis": record.get("ai_analysis", "")
        }
        
        # Prepend to history (newest first)
        history.insert(0, entry)
        if len(history) > cls.MAX_HISTORY_ITEMS:
            history = history[:cls.MAX_HISTORY_ITEMS]
            
        cls._save_history(history)
        return val_id

    @classmethod
    def get_recent_validations(cls, limit: int = 20) -> list[dict]:
        history = cls._load_history()
        return history[:limit]

    @classmethod
    def get_stats(cls) -> dict:
        history = cls._load_history()
        total = len(history)
        if total == 0:
            return {
                "total_validated": 0,
                "passed_count": 0,
                "failed_count": 0,
                "success_rate": 0,
                "avg_score": 0,
                "type_breakdown": {}
            }

        passed = sum(1 for r in history if r["status"] == "passed")
        failed = total - passed
        avg_score = round(sum(r.get("score", 0) for r in history) / total, 1)
        success_rate = round((passed / total) * 100, 1)

        type_counts = {}
        for r in history:
            t = r.get("detected_type", "Other")
            type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "total_validated": total,
            "passed_count": passed,
            "failed_count": failed,
            "success_rate": success_rate,
            "avg_score": avg_score,
            "type_breakdown": type_counts
        }

    @classmethod
    def clear_history(cls) -> None:
        cls._save_history([])

    @classmethod
    def delete_record(cls, record_id: str) -> bool:
        """Deletes a single validation record by its ID or timestamp."""
        history = cls._load_history()
        initial_len = len(history)
        history = [r for r in history if str(r.get("id")) != str(record_id) and str(r.get("timestamp")) != str(record_id)]
        if len(history) < initial_len:
            cls._save_history(history)
            return True
        return False

    @classmethod
    def _load_history(cls) -> list[dict]:
        file_path = Config.HISTORY_FILE
        if not os.path.exists(file_path):
            return []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                modified = False
                for idx, r in enumerate(data):
                    if not r.get("id"):
                        r["id"] = f"val_{uuid.uuid4().hex[:10]}"
                        modified = True
                if modified:
                    cls._save_history(data)
                return data
        except Exception:
            return []

    @classmethod
    def _save_history(cls, history: list[dict]) -> None:
        file_path = Config.HISTORY_FILE
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2)
        except Exception:
            pass
