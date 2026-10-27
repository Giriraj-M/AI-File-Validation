import os
import logging
from typing import Dict, Any, List, Optional

from services.detector import FileDetector
from services.corruption_classifier import CorruptionClassifier
from services.tool_registry import ToolRegistry
from services.ai_service import AIService

logger = logging.getLogger("FileGuard.ToolRecommender")


class ToolRecommender:
    """
    Intelligent Recovery Tool Recommendation Engine.
    Maps forensic corruption diagnoses to available deterministic recovery tools.
    Integrates AI strategic explanations with deterministic safety constraints.
    """

    @classmethod
    def recommend(cls, file_path: str, corruption_type: str = "auto") -> Dict[str, Any]:
        """
        Recommends primary and fallback recovery tools based on file format,
        corruption category, and tool installation status.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        # 1. Detect format & classify corruption
        det = FileDetector.detect_file_type(file_path)
        fmt = det.get("file_type", "UNKNOWN").upper()

        if corruption_type == "auto":
            classification = CorruptionClassifier.classify(file_path, fmt)
        else:
            classification = {
                "file_type": fmt,
                "corruption_type": corruption_type,
                "category": corruption_type.replace("_", " ").title(),
                "confidence": 0.90,
                "confidence_level": "HIGH",
                "details": f"User-specified corruption profile: {corruption_type}",
                "defects": [],
                "can_recover": True,
                "recommended_tools": [],
                "expected_limitations": "Standard forensic repair pipeline."
            }

        corr_key = classification.get("corruption_type", "UNKNOWN")
        cat_name = classification.get("category", "Unspecified Corruption")
        conf_score = classification.get("confidence", 0.85)
        conf_level = classification.get("confidence_level", "HIGH")
        limitations = classification.get("expected_limitations", "Partial recovery possible if structural damage is deep.")

        # 2. Match tools from ToolRegistry
        all_tools = ToolRegistry.get_all_tools()
        matched = []
        for t in all_tools:
            # Check format match
            fmt_matches = any(f.upper() == fmt or f.upper() in fmt for f in t.get("supported_formats", []))
            if not fmt_matches:
                continue

            # Check corruption match
            corr_matches = any(
                c in corr_key or corr_key in c
                for c in t.get("supported_corruption_types", [])
            )
            score = 10 if corr_matches else 1
            if t.get("is_installed"):
                score += 5
            score -= t.get("priority", 1)

            tool_entry = dict(t)
            tool_entry["match_score"] = score
            matched.append(tool_entry)

        matched.sort(key=lambda x: x["match_score"], reverse=True)

        # 3. Formulate Primary and Alternative Tools
        if matched:
            primary_tool = matched[0]
            alternatives = matched[1:5]
        else:
            primary_tool = {
                "id": "generic_recovery",
                "name": "Generic Forensic Engine",
                "is_installed": True,
                "description": "Fallback stream salvager.",
                "install_guide": ""
            }
            alternatives = []

        # 4. Generate Reasoning
        reason = cls._generate_reasoning(fmt, corr_key, primary_tool)

        return {
            "file_type": fmt,
            "detected_format": det.get("detected_format", fmt.lower()),
            "corruption_category": cat_name,
            "corruption_type": corr_key,
            "confidence": conf_score,
            "confidence_level": conf_level,
            "primary_tool": {
                "id": primary_tool.get("id"),
                "name": primary_tool.get("name"),
                "is_installed": primary_tool.get("is_installed", False),
                "install_guide": primary_tool.get("install_guide", ""),
                "description": primary_tool.get("description", "")
            },
            "alternative_tools": [
                {
                    "id": a.get("id"),
                    "name": a.get("name"),
                    "is_installed": a.get("is_installed", False),
                    "install_guide": a.get("install_guide", ""),
                    "description": a.get("description", "")
                }
                for a in alternatives
            ],
            "reason": reason,
            "expected_limitations": limitations,
            "classification_details": classification
        }

    @classmethod
    def _generate_reasoning(cls, fmt: str, corr_type: str, primary_tool: Dict[str, Any]) -> str:
        t_name = primary_tool.get("name", "Specialized Recovery Engine")
        installed_str = "is installed and ready" if primary_tool.get("is_installed") else "is recommended (install guide provided)"
        if "HEADER" in corr_type:
            return f"The {fmt} document contains recoverable body objects, but its header signature or byte offset is displaced. {t_name} {installed_str} to realign magic bytes without modifying internal page trees."
        elif "XREF" in corr_type:
            return f"The document contains valid PDF objects, but its cross-reference table or startxref pointer is damaged. {t_name} {installed_str} to rebuild the xref table by recalculating byte offsets deterministically."
        elif "EOF" in corr_type:
            return f"The document ends abruptly with a missing %%EOF or damaged trailer dictionary. {t_name} {installed_str} to seal open streams and reconstruct a valid document termination."
        elif "IMAGE" in corr_type:
            return f"The document outer structure is readable, but embedded raster graphics contain corrupted scanlines or damaged SOI/EOI markers. {t_name} {installed_str} to salvage raster streams."
        elif "BODY" in corr_type:
            return f"The document has corrupted content streams. {t_name} {installed_str} to harvest readable text, vector elements, and renderable pages."
        elif "ZIP" in corr_type or "XML" in corr_type:
            return f"The {fmt} OpenXML archive container has central directory or XML stream defects. {t_name} {installed_str} to harvest surviving document parts."
        else:
            return f"{t_name} {installed_str} to execute multi-strategy forensic recovery for {fmt}."


def recommend_recovery_tools(file_path: str, corruption_type: str = "auto") -> Dict[str, Any]:
    """Top-level functional interface conforming to system specification."""
    return ToolRecommender.recommend(file_path, corruption_type)
