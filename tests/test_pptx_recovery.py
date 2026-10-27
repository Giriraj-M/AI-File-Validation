import os
import io
import pytest
from services.pptx_analyzer import PPTXAnalyzer
from services.pptx_recovery import PPTXRecoveryEngine

try:
    from pptx import Presentation
except ImportError:
    Presentation = None

def test_pptx_token_recovery(tmp_path):
    # Construct raw payload containing slide XML text tokens
    raw_corrupt_pptx = (
        b"PK\x03\x04GARBAGE"
        b"<p:sp><a:t>Quarterly Strategy Plan</a:t></p:sp>"
        b"<p:sp><a:t>Accelerate Revenue Growth</a:t></p:sp>"
        b"<p:sp><a:t>Optimize Operational Overhead</a:t></p:sp>"
    )

    corrupt_path = str(tmp_path / "corrupt_pres.pptx")
    out_path = str(tmp_path / "recovered_pres.pptx")

    with open(corrupt_path, "wb") as f:
        f.write(raw_corrupt_pptx)

    analysis = PPTXAnalyzer.analyze(corrupt_path)
    assert analysis["can_recover"] is True

    res = PPTXRecoveryEngine.recover(corrupt_path, out_path)
    if Presentation is not None:
        assert res["success"] is True
        assert os.path.exists(out_path)
        prs = Presentation(out_path)
        assert len(prs.slides) >= 1
