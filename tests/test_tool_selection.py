import pytest
from services.tool_manager import ToolManager
from services.recovery_tool_registry import RecoveryToolRegistry
from services.recovery_decision_service import RecoveryDecisionService

def test_tool_manager_inspection():
    tools = ToolManager.get_system_tools()
    assert "pymupdf" in tools
    assert "pypdf" in tools
    assert "openpyxl" in tools
    assert "python-docx" in tools
    assert "pillow" in tools

def test_tool_selection_never_picks_unavailable_tool(monkeypatch):
    # Mock ToolManager to report qpdf as unavailable
    def mock_is_avail(name):
        if name == "qpdf":
            return False
        return True

    monkeypatch.setattr(ToolManager, "is_tool_available", mock_is_avail)

    candidate_tools = RecoveryToolRegistry.get_candidate_tools_for_analysis(
        "PDF",
        {"xref": True, "header": True}
    )

    tool_ids = [t["id"] for t in candidate_tools]
    assert "qpdf" not in tool_ids

    # Recovery plan must not have qpdf as top tool
    plan = RecoveryDecisionService.plan_recovery({
        "detected_type": "PDF",
        "corruption": {"xref": True},
        "recommended_tools": candidate_tools
    })

    assert plan["recommended_tool"] != "qpdf"
