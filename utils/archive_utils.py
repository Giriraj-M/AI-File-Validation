import os
import zipfile
import logging
from pathlib import Path

logger = logging.getLogger("FileGuard.ArchiveUtils")

def create_batch_zip(file_mappings: list[dict], output_zip_path: str, summary_html_content: str | None = None) -> bool:
    """
    Creates a ZIP archive containing recovered files and an optional recovery summary report.
    file_mappings: list of dicts with {"source_path": str, "archive_name": str}
    """
    try:
        out_path = Path(output_zip_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(output_zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zipf:
            # Add each recovered file
            for item in file_mappings:
                src = item.get("source_path")
                arch_name = item.get("archive_name") or os.path.basename(src or "document")
                if src and os.path.exists(src):
                    zipf.write(src, arcname=f"recovered_files/{arch_name}")
            
            # Add summary report if provided
            if summary_html_content:
                zipf.writestr("recovery_summary.html", summary_html_content)

        return True
    except Exception as e:
        logger.error(f"Failed to create batch ZIP archive: {e}", exc_info=True)
        return False
