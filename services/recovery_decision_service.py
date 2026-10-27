import logging
from typing import Dict, Any, List
from config import Config
from services.ai_service import AIService
from services.tool_manager import ToolManager
from services.recovery_tool_registry import RecoveryToolRegistry

logger = logging.getLogger("FileGuard.RecoveryDecisionService")

class RecoveryDecisionService:
    """
    Decides the optimal recovery execution pipeline.
    Combines AI Strategy Recommendation with Deterministic Safety Constraints.
    """

    @classmethod
    def plan_recovery(cls, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Plans the sequence of tools to attempt for recovering a file.
        Returns:
          {
            "recommended_tool": str,
            "fallback_sequence": list[str],
            "reason": str,
            "ai_metadata": dict,
            "classification": str
          }
        """
        # 1. Ask Gemini 3.5 Flash / AIService for strategy recommendation
        ai_recommendation = AIService.recommend_recovery_strategy(analysis_data)
        
        raw_recommended = ai_recommendation.get("recommended_tool")
        raw_fallbacks = ai_recommendation.get("fallback_tools", [])

        # 2. Get available tools for format
        fmt = analysis_data.get("detected_type", "UNKNOWN")
        candidates = RecoveryToolRegistry.get_candidate_tools_for_analysis(
            fmt,
            analysis_data.get("corruption", {})
        )
        available_candidate_ids = [c["id"] for c in candidates]

        # 3. Deterministic Safety Check: Filter recommended tools by actual availability
        execution_queue = []

        if raw_recommended and raw_recommended in available_candidate_ids:
            execution_queue.append(raw_recommended)

        for fb in raw_fallbacks:
            if fb in available_candidate_ids and fb not in execution_queue:
                execution_queue.append(fb)

        # Fill remaining available candidate tools up to MAX_RECOVERY_ATTEMPTS
        max_attempts = getattr(Config, "MAX_RECOVERY_ATTEMPTS", 7)
        for cand_id in available_candidate_ids:
            if cand_id not in execution_queue and len(execution_queue) < max_attempts:
                execution_queue.append(cand_id)

        # If queue is empty, default to format generic handler
        if not execution_queue:
            execution_queue = ["generic_stream_repair"]

        top_tool = execution_queue[0]
        fallbacks = execution_queue[1:]

        return {
            "recommended_tool": top_tool,
            "fallback_sequence": fallbacks,
            "all_attempts_sequence": execution_queue,
            "reason": ai_recommendation.get("reason", "Deterministic safety prioritized best available engine."),
            "ai_metadata": ai_recommendation,
            "classification": ai_recommendation.get("classification", analysis_data.get("classification", "MODERATE"))
        }
