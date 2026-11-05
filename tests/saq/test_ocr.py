import numpy as np
import os
import pytest

from saq import ocr


@pytest.mark.unit
def test_invert_image_color(datadir):
    image = ocr.read_image(os.path.join(datadir, "white.png"))
    assert list(np.unique(image.flatten())) == [255]

    inverted = ocr.invert_image_color(np.array([[0, 10, 255]], dtype=np.uint8))
    assert inverted.tolist() == [[255, 245, 0]]


@pytest.mark.unit
def test_is_dark():
    assert ocr.is_dark(np.full((4, 4), 127, dtype=np.uint8)) is False
    assert ocr.is_dark(np.full((4, 4), 126, dtype=np.uint8)) is True


@pytest.mark.unit
def test_is_small(datadir):
    image = ocr.read_image(os.path.join(datadir, "small.png"))
    assert ocr.is_small(image) is True

    # small means both dimensions are under their limits
    assert ocr.is_small(np.zeros((649, 399), dtype=np.uint8)) is True
    assert ocr.is_small(np.zeros((649, 400), dtype=np.uint8)) is False
    assert ocr.is_small(np.zeros((650, 399), dtype=np.uint8)) is False


@pytest.mark.unit
def test_denoise_image():
    image = np.random.default_rng(14).normal(128, 8, (64, 64)).clip(0, 255).astype(np.uint8)
    denoised = ocr.denoise_image(image)
    assert denoised.shape == image.shape
    assert denoised.dtype == image.dtype
    assert denoised.std() < image.std() / 2


@pytest.mark.unit
def test_add_border():
    image = np.full((5, 7), 100, dtype=np.uint8)
    original_h, original_w = image.shape[:2]
    bordered = ocr.add_border(image, border_size=10)
    assert bordered.shape[0] == original_h + 20
    assert bordered.shape[1] == original_w + 20
    # Top-left corner pixel should be white (border)
    assert bordered[0, 0] == 255
    # and the image itself is inside it, unchanged
    assert (bordered[10:-10, 10:-10] == image).all()


@pytest.mark.unit
def test_get_scale_factor():
    assert ocr.get_scale_factor(np.zeros((1, 500), dtype=np.uint8)) == 3.0

    # nothing wider than min_width is scaled
    assert ocr.get_scale_factor(np.zeros((1, 2000), dtype=np.uint8)) == 1.0

    # Very small image should be capped at 4.0
    tiny = np.zeros((10, 10), dtype=np.uint8)
    assert ocr.get_scale_factor(tiny) == 4.0


@pytest.mark.unit
def test_sharpen_image():
    # a step edge: the unsharp mask overshoots on both sides of it
    image = np.full((32, 32), 100, dtype=np.uint8)
    image[:, 16:] = 150
    sharpened = ocr.sharpen_image(image)
    assert sharpened.shape == image.shape
    assert sharpened.dtype == image.dtype
    assert sharpened.min() < 100
    assert sharpened.max() > 150


@pytest.mark.unit
def test_remove_line_wrapping():
    text = """Text Message
Today 8:57 AM
[Blah Blah Bank]: We recently
detected some unusual activities &
your access is temporarily
suspended. Visit https://bit.ly/
3B65FKM to regain online access.

"""

    expected = "Text Message Today 8:57 AM [Blah Blah Bank]: We recently detected some unusual activities &your access is temporarily suspended. Visit https://bit.ly/3B65FKM to regain online access. "

    assert ocr.remove_line_wrapping(text) == expected


@pytest.mark.unit
@pytest.mark.parametrize("input_text,expected", [
    # ] misread as I
    ("example[.Icom", "example[.]com"),
    # Brackets misread as braces
    ("example{.}com", "example[.]com"),
    # [ misread as lowercase l
    ("examplel.]com", "example[.]com"),
    # [ misread as f
    ("examplef.Jcom", "example[.]com"),
    # Space inserted after dot (only with clear bracket opening)
    ("example[. Jcom", "example[.]com"),
    ("example{. ]com", "example[.]com"),
    ("example{. }com", "example[.]com"),
    ("example[. Icom", "example[.]com"),
    # Multiple occurrences in FQDN-like string
    ("hostnamel.Jnal.Jdomainl.Jnet", "hostname[.]na[.]domain[.]net"),
    # Context-aware: l. J preceded by [.] (defanged FQDN context)
    ("hostname[.]nal. Jdomain[.]net", "hostname[.]na[.]domain[.]net"),
    # Context-aware: l. I preceded by @ (email/UPN context)
    ("user@nal. Idomain[.]net", "user@na[.]domain[.]net"),
    # Context-aware: chained — multiple l. J with [.] context propagating
    ("host[.]nal. Jdomainl. Jnet", "host[.]na[.]domain[.]net"),
    # Adjacent pair: first ] dropped, second [.] broken
    ("hostname-03[. nal Jdomain[.]net", "hostname-03[.]na[.]domain[.]net"),
    # Sentence boundary — should NOT be changed (no [.] or @ context)
    ("beautiful. Just like that", "beautiful. Just like that"),
    # @ defanging
    ("user{@}example.com", "user[@]example.com"),
    ("user[@Jexample.com", "user[@]example.com"),
    ("userl@Jexample.com", "user[@]example.com"),
    ("user[@ Jexample.com", "user[@]example.com"),
])
def test_fix_defanged_indicators(input_text, expected):
    assert ocr.fix_defanged_indicators(input_text) == expected


@pytest.mark.unit
def test_scale_image(datadir):
    image = ocr.read_image(os.path.join(datadir, "small.png"))
    scaled = ocr.scale_image(image, x_factor=3, y_factor=2)
    assert scaled.shape[0] == image.shape[0] * 2
    assert scaled.shape[1] == image.shape[1] * 3
