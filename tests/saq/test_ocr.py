import numpy as np
import os
import pytest

from saq import ocr


@pytest.mark.unit
def test_invert_image_color(datadir):
    image = ocr.read_image(os.path.join(datadir, "white.png"))
    assert list(np.unique(image.flatten())) == [255]

    inverted = ocr.invert_image_color(image)
    assert list(np.unique(inverted.flatten())) == [0]


@pytest.mark.unit
def test_is_dark(datadir):
    image = ocr.read_image(os.path.join(datadir, "white.png"))
    assert ocr.is_dark(image) is False

    inverted = ocr.invert_image_color(image)
    assert ocr.is_dark(inverted) is True


@pytest.mark.unit
def test_is_small(datadir):
    image = ocr.read_image(os.path.join(datadir, "small.png"))
    assert ocr.is_small(image) is True


@pytest.mark.unit
def test_denoise_image(datadir):
    image = ocr.read_image(os.path.join(datadir, "white.png"))
    denoised = ocr.denoise_image(image)
    assert denoised.shape == image.shape
    assert denoised.dtype == image.dtype


@pytest.mark.unit
def test_add_border(datadir):
    image = ocr.read_image(os.path.join(datadir, "small.png"))
    original_h, original_w = image.shape[:2]
    bordered = ocr.add_border(image, border_size=10)
    assert bordered.shape[0] == original_h + 20
    assert bordered.shape[1] == original_w + 20
    # Top-left corner pixel should be white (border)
    assert bordered[0, 0] == 255


@pytest.mark.unit
def test_get_scale_factor(datadir):
    small_image = ocr.read_image(os.path.join(datadir, "small.png"))
    factor = ocr.get_scale_factor(small_image)
    assert factor > 1.0
    assert factor <= 4.0

    # A large image should return 1.0
    large_image = ocr.scale_image(small_image, x_factor=30, y_factor=30)
    assert ocr.get_scale_factor(large_image) == 1.0

    # Very small image should be capped at 4.0
    tiny = np.zeros((10, 10), dtype=np.uint8)
    assert ocr.get_scale_factor(tiny) == 4.0


@pytest.mark.unit
def test_sharpen_image(datadir):
    image = ocr.read_image(os.path.join(datadir, "small.png"))
    sharpened = ocr.sharpen_image(image)
    assert sharpened.shape == image.shape
    assert sharpened.dtype == image.dtype


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
    # ] misread as J or I
    ("example[.Jcom", "example[.]com"),
    ("example[.Icom", "example[.]com"),
    # Brackets misread as braces
    ("example{.}com", "example[.]com"),
    # Mixed bracket/brace
    ("example{.]com", "example[.]com"),
    ("example[.}com", "example[.]com"),
    # [ misread as lowercase l
    ("examplel.Jcom", "example[.]com"),
    ("examplel.Icom", "example[.]com"),
    ("examplel.]com", "example[.]com"),
    # [ misread as f
    ("examplef.Jcom", "example[.]com"),
    # Space inserted after dot (only with clear bracket opening)
    ("example[. Jcom", "example[.]com"),
    ("example{. ]com", "example[.]com"),
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
    # Already correct — should not change
    ("example[.]com", "example[.]com"),
    # Normal text without defanged indicators — should not change
    ("Hello world", "Hello world"),
])
def test_fix_defanged_indicators(input_text, expected):
    assert ocr.fix_defanged_indicators(input_text) == expected


@pytest.mark.unit
def test_scale_image(datadir):
    image = ocr.read_image(os.path.join(datadir, "small.png"))
    scaled = ocr.scale_image(image, x_factor=2, y_factor=2)
    assert scaled.shape[0] == image.shape[0] * 2
    assert scaled.shape[1] == image.shape[1] * 2
