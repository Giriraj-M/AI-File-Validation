import os
import io
import pytest
from PIL import Image
from services.image_analyzer import ImageAnalyzer
from services.image_recovery import ImageRecoveryEngine

def test_jpeg_truncated_recovery(tmp_path):
    # Generate valid JPEG
    im = Image.new("RGB", (100, 100), color=(255, 0, 0))
    buf = io.BytesIO()
    im.save(buf, format="JPEG")
    valid_jpeg = buf.getvalue()

    # Truncate by stripping EOI \xFF\xD9 marker
    truncated_jpeg = valid_jpeg[:-2]

    corrupt_path = str(tmp_path / "truncated.jpg")
    out_path = str(tmp_path / "recovered.jpg")

    with open(corrupt_path, "wb") as f:
        f.write(truncated_jpeg)

    analysis = ImageAnalyzer.analyze(corrupt_path)
    assert analysis["is_corrupted"] is True
    assert any(r["region"] == "end_of_file" and r["status"] == "corrupted" for r in analysis["corruption_regions"])

    res = ImageRecoveryEngine.recover(corrupt_path, out_path)
    assert res["success"] is True
    assert os.path.exists(out_path)

    # Verify loaded image
    with Image.open(out_path) as rec_im:
        rec_im.load()
        assert rec_im.size[0] > 0 and rec_im.size[1] > 0

def test_image_unrecoverable_random_noise(tmp_path):
    noise_path = str(tmp_path / "noise.png")
    out_path = str(tmp_path / "out.png")
    with open(noise_path, "wb") as f:
        f.write(os.urandom(256))

    res = ImageRecoveryEngine.recover(noise_path, out_path)
    # Should not report fake success on unrenderable noise
    assert res["success"] is False or not os.path.exists(out_path)
