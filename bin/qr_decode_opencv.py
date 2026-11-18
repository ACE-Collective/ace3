#!/usr/bin/env python3
"""Prints, as JSON, the text of each QR code OpenCV finds in an image and in its inverse:
{"normal": [...], "inverted": [...]}.

QRCodeAnalyzer runs this in the tool sandbox when zbarimg finds no URL, because an icon over the
center of a code can stop zbarimg from finding it at all. The image comes from an attacker, so this
never runs in an engine worker. It reads the inverse in the same run because most of a run is
starting Python and loading cv2. An image OpenCV cannot load has no codes: zbarimg has already
scanned it, and is what reads the formats OpenCV does not."""

import json
import sys

try:
    import cv2
except ImportError as e:
    # this node cannot run OpenCV, whatever the image: QRCodeAnalyzer matches this prefix as a startup error
    sys.exit(f"qr_decode_opencv: cannot load OpenCV: {e}")


def main(image_path: str):
    # one image on an engine worker does not get every core of the node
    cv2.setNumThreads(1)
    # a code's text comes from the attacker and need not be valid UTF-8
    sys.stdout.reconfigure(errors="replace")

    image = cv2.imread(image_path)
    codes = {"normal": [], "inverted": []}
    if image is not None:
        codes = {"normal": _decode(image), "inverted": _decode(cv2.bitwise_not(image))}
    json.dump(codes, sys.stdout, ensure_ascii=False)


def _decode(image) -> list[str]:
    detector = cv2.QRCodeDetector()
    # each call reads codes the other misses: Multi finds them all, but returned an empty string for
    # a code with finder-like squares in its icon that the single decoder reads
    decoded = [detector.detectAndDecode(image)[0], *detector.detectAndDecodeMulti(image)[1]]
    return list(dict.fromkeys(filter(None, decoded)))


if __name__ == "__main__":
    main(sys.argv[1])
