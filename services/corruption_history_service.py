import os
import json
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from config import Config
from utils.file_utils import cleanup_file

# Indian Standard Time (IST = UTC+5:30)
IST = timezone(timedelta(hours=5, minutes=30))


class CorruptionHistoryService:
    """
    Audit log and storage manager for intentional file corruptions.
    Tracks metadata and manages physical corrupted files in instance/corrupted_files/.
    """

    MAX_HISTORY_ITEMS = 100

    @classmethod
    def record_corruption(cls, record: dict) -> str:
        """Saves a corruption run and returns the assigned corruption ID."""
        history = cls._load_history()
        corr_id = f"cor_{uuid.uuid4().hex[:10]}"

        entry = {
            "id": corr_id,
            "timestamp": datetime.now(IST).strftime("%Y-%m-%d %I:%M:%S %p IST"),
            "original_filename": record.get("original_filename", "unknown"),
            "corrupted_filename": record.get("corrupted_filename", "unknown"),
            "file_type": record.get("file_type", "Unknown"),
            "original_size_human": record.get("original_size_human", "0 B"),
            "corrupted_size_human": record.get("corrupted_size_human", "0 B"),
            "original_size_bytes": record.get("original_size_bytes", 0),
            "corrupted_size_bytes": record.get("corrupted_size_bytes", 0),
            "is_all": record.get("is_all", False),
            "targets_selected": record.get("targets_selected", []),
            "effective_targets": record.get("effective_targets", []),
            "summary": record.get("summary", ""),
            "storage_filename": record.get("storage_filename", ""),
            "corrupted_regions": record.get("corrupted_regions", []),
            "hex_diffs": record.get("hex_diffs", []),
            "structure_matrix": record.get("structure_matrix", {})
        }

        history.insert(0, entry)
        if len(history) > cls.MAX_HISTORY_ITEMS:
            pruned = history[cls.MAX_HISTORY_ITEMS:]
            for old_item in pruned:
                cls._delete_storage_file(old_item.get("storage_filename"))
            history = history[:cls.MAX_HISTORY_ITEMS]

        cls._save_history(history)
        return corr_id

    @classmethod
    def get_recent_corruptions(cls, limit: int = 50) -> list[dict]:
        """Returns recent corruption records."""
        history = cls._load_history()
        return history[:limit]

    @classmethod
    def get_stats(cls) -> dict:
        """Calculates aggregated metrics and breakdown by corrupted section and file type."""
        history = cls._load_history()
        total = len(history)
        if total == 0:
            return {
                "total_corrupted": 0,
                "header_count": 0,
                "body_count": 0,
                "reference_count": 0,
                "eof_count": 0,
                "images_count": 0,
                "all_count": 0,
                "type_breakdown": {}
            }

        header_cnt = sum(1 for r in history if "header" in r.get("effective_targets", []))
        body_cnt = sum(1 for r in history if "body" in r.get("effective_targets", []))
        ref_cnt = sum(1 for r in history if "reference" in r.get("effective_targets", []))
        eof_cnt = sum(1 for r in history if "end_of_file" in r.get("effective_targets", []))
        img_cnt = sum(1 for r in history if "images" in r.get("effective_targets", []))
        all_cnt = sum(1 for r in history if r.get("is_all"))

        type_counts = {}
        for r in history:
            t = (r.get("file_type") or "OTHER").upper()
            type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "total_corrupted": total,
            "header_count": header_cnt,
            "body_count": body_cnt,
            "reference_count": ref_cnt,
            "eof_count": eof_cnt,
            "images_count": img_cnt,
            "all_count": all_cnt,
            "type_breakdown": type_counts
        }

    @classmethod
    def get_corruption_by_id(cls, corr_id: str) -> dict | None:
        """Finds a single corruption record by ID."""
        history = cls._load_history()
        for item in history:
            if item.get("id") == corr_id:
                return item
        return None

    @classmethod
    def delete_corruption(cls, corr_id: str) -> bool:
        """Deletes a single corruption log entry and its physical file on disk."""
        history = cls._load_history()
        target_idx = None
        target_item = None
        for i, item in enumerate(history):
            if item.get("id") == corr_id:
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
        """Clears all corruption audit logs and cleans up all corrupted files on disk."""
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
        file_path = os.path.join(Config.CORRUPTED_FOLDER, storage_filename)
        cleanup_file(file_path)

    @classmethod
    def _load_history(cls) -> list[dict]:
        file_path = Config.CORRUPTION_HISTORY_FILE
        if not os.path.exists(file_path):
            return []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    @classmethod
    def _save_history(cls, history: list[dict]) -> None:
        file_path = Config.CORRUPTION_HISTORY_FILE
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2)
        except Exception:
            pass
