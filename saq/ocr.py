import cv2
import enchant
import logging
import numpy as np
import pytesseract
import re

from PIL import Image, ImageOps


def add_border(image: np.ndarray, border_size: int = 10) -> np.ndarray:
    """Adds a white border around the image. Text touching image edges is a known Tesseract failure mode."""

    return cv2.copyMakeBorder(image, border_size, border_size, border_size, border_size,
                              cv2.BORDER_CONSTANT, value=255)


def fix_defanged_indicators(text: str) -> str:
    """Fixes common OCR misreadings of defanged security indicators.

    In security contexts, indicators like domains and IPs are often "defanged" by replacing dots with [.]
    to prevent accidental clicks/linking. Tesseract frequently misreads the bracket characters in these
    patterns — e.g., [ as l/f/{, ] as J/I/}, and sometimes inserts spaces between them.
    """

    # Pass 1: Fix unambiguous bracket misreadings

    # [.] without spaces — broad character set since l.J, f.I, etc. don't appear in normal text
    text = re.sub(r"[\[{lf]\.[\]}JI]", "[.]", text)

    # [.] with space after dot — only [ and { as opening to avoid false positives at sentence
    # boundaries (e.g., "beautiful. Just" has the pattern l. J but is not a defanged indicator)
    text = re.sub(r"[\[{]\.\s[\]}JI]", "[.]", text)

    # Adjacent [.] pair where first ] was dropped and second [.] is broken
    # e.g., "[. nal J" → "[.]na[.]" (the [. is intact but ] became a space)
    text = re.sub(r"\[\.\s(\w+)[lf]\s?[JI]", r"[.]\1[.]", text)

    # [@] same patterns
    text = re.sub(r"[\[{lf]@[\]}JI]", "[@]", text)
    text = re.sub(r"[\[{]@\s?[\]}JI]", "[@]", text)

    # Pass 2: Context-aware fix for ambiguous patterns (l/f as opening bracket with space)
    # After pass 1, a preceding [.] or @ confirms we're in a defanged FQDN, not a sentence boundary.
    prev = None
    while prev != text:
        prev = text
        text = re.sub(r"(\[\.\]\w*)[lf]\.\s?[JI]", r"\1[.]", text)
        text = re.sub(r"(@\w*)[lf]\.\s?[JI]", r"\1[.]", text)

    return text


def denoise_image(image: np.ndarray) -> np.ndarray:
    """Applies non-local means denoising to reduce noise while preserving text detail."""

    return cv2.fastNlMeansDenoising(image, None, h=10, templateWindowSize=7, searchWindowSize=21)


# Tesseract 5's LSTM engine outputs Unicode characters (smart quotes, dashes, etc.) that have no
# benefit over their ASCII equivalents for our use case. This table normalizes them to ASCII.
# Note: str.translate handles single-char → single-char mappings; multi-char replacements use _UNICODE_MULTI.
_UNICODE_CHARMAP = str.maketrans({
    "\u2014": "-",   # em-dash → hyphen
    "\u2013": "-",   # en-dash → hyphen
    "\u2018": "'",   # left single quote → apostrophe
    "\u2019": "'",   # right single quote → apostrophe
    "\u201A": ",",   # single low-9 quote → comma
    "\u201C": '"',   # left double quote → double quote
    "\u201D": '"',   # right double quote → double quote
    "\u201E": '"',   # double low-9 quote → double quote
    "\u2032": "'",   # prime → apostrophe
    "\u2033": '"',   # double prime → double quote
    "\u2010": "-",   # hyphen (Unicode)
    "\u2011": "-",   # non-breaking hyphen
    "\u2012": "-",   # figure dash
    "\u2015": "-",   # horizontal bar
    "\u00AB": '"',   # left guillemet → double quote
    "\u00BB": '"',   # right guillemet → double quote
    "\u2039": "'",   # left single guillemet → apostrophe
    "\u203A": "'",   # right single guillemet → apostrophe
    "\u00B7": ".",   # middle dot → period
    "\u2022": "*",   # bullet → asterisk
    "\u00D7": "x",   # multiplication sign → x
    "\u00F7": "/",   # division sign → slash
})

_UNICODE_MULTI = {
    "\u2026": "...",   # ellipsis → three dots
    "\u00A9": "(c)",   # copyright
    "\u00AE": "(R)",   # registered trademark
    "\u2122": "(TM)",  # trademark
    "\u2120": "(SM)",  # service mark
}


def get_image_text(image: np.ndarray, psm: int = 3) -> str:
    """Returns the text within the image by using OCR.

    Uses OEM 1 (LSTM-only) for highest accuracy with Tesseract 5.
    PSM 3 (fully automatic page segmentation) adapts to mixed layouts.
    """

    text = str(pytesseract.image_to_string(image, config=f"--oem 1 --psm {psm}"))

    # In testing, Tesseract sometimes had issues identifying http:// or https://. In particular, it would mix up the
    # double "t" and sometimes make one of them an "i" instead. Sometimes the "p" or ":" would be mixed up as well.
    if text:
        text = re.sub(r"h(t|i)(t|i)(p|o)s(:|.)\/\/", "https://", text)
        text = re.sub(r"h(t|i)(t|i)(p|o)(:|.)\/\/", "http://", text)

        # Normalize Unicode characters to ASCII equivalents
        text = text.translate(_UNICODE_CHARMAP)
        for unicode_char, ascii_replacement in _UNICODE_MULTI.items():
            text = text.replace(unicode_char, ascii_replacement)

        # Fix common misreadings of defanged security indicators like [.] and [@]
        text = fix_defanged_indicators(text)

    return text


def get_scale_factor(image: np.ndarray, min_width: int = 1500) -> float:
    """Returns the scale factor needed to bring the image width up to min_width, capped at 4x."""

    width = image.shape[1]
    if width >= min_width:
        return 1.0
    return min(min_width / width, 4.0)


def invert_image_color(image: np.ndarray) -> np.ndarray:
    """Returns an image where the colors are inverted."""

    return cv2.bitwise_not(image)


def is_dark(image: np.ndarray) -> bool:
    """Returns True/False if the image appears to be in dark-mode. Must be used on a grayscale image."""

    # In grayscale mode, each pixel has a value from 0-255 (0=black, 255=white). If the mean value is closer to
    # 0 than 255, then we assume that the original image is dark overall.
    return cv2.mean(image)[0] < 127


def is_small(image: np.ndarray) -> bool:
    """Returns True/False if the resolution of the image is what we consider to be small."""

    width = image.shape[1]
    height = image.shape[0]

    return width < 400 and height < 650


def read_image(image_path: str, use_grayscale: bool = True) -> np.ndarray:
    """Reads the image at the given path. By default it will return the image in grayscale mode."""

    image = Image.open(image_path)

    if use_grayscale:
        image = ImageOps.grayscale(image)

    return np.array(image)


def remove_line_wrapping(text: str) -> str:
    """Attempts to interpret the text to remove line wraps. This is particularly helpful when performing OCR on
    a screenshot of a text message where things like domains or URLs a broken up over multiple lines.
    
    It loops over each line in the text, and if the last "word" in the line (when broken up by spaces) is a valid
    word according to the dictionary it will join that line to the resulting text with a space at the end. If it
    is not a valid word, then it joins the line without a space at the end, which implies that the word continues on
    the next line."""

    dictionary = enchant.Dict("en_US")

    unwrapped_text = ""
    for line in text.splitlines():
        try:
            last_word = line.split()[-1]
        except IndexError:
            continue

        is_a_word = False
        try:
            is_a_word = dictionary.check(last_word)
        except Exception:
            logging.exception(f"Unable to determine if \"{last_word}\" is a word.")

        if is_a_word:
            unwrapped_text += f"{line} "
        else:
            unwrapped_text += line

    return unwrapped_text


def scale_image(image: np.ndarray, x_factor: int, y_factor: int) -> np.ndarray:
    """Returns a scaled version of the image."""

    return cv2.resize(image, None, fx=x_factor, fy=y_factor, interpolation=cv2.INTER_CUBIC)


def sharpen_image(image: np.ndarray, amount: float = 1.0) -> np.ndarray:
    """Applies an unsharp mask to restore edge crispness after upscaling.

    Subtracts a Gaussian-blurred copy from the original to amplify high-frequency detail.
    """

    blurred = cv2.GaussianBlur(image, (0, 0), sigmaX=3)
    return cv2.addWeighted(image, 1.0 + amount, blurred, -amount, 0)
