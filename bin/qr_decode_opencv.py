#!/usr/bin/env python3
"""Prints the text of each QR code OpenCV finds in an image, one per line.

QRCodeAnalyzer runs this in the tool sandbox when zbarimg finds nothing, because an icon over the
center of a code can stop zbarimg from finding it at all. The image comes from an attacker, so this
never runs in an engine worker. An image OpenCV cannot load prints nothing: zbarimg has already
scanned it, and is what reads the formats OpenCV does not."""

import sys

import cv2


def main(image_path: str):
    # one image on an engine worker does not get every core of the node
    cv2.setNumThreads(1)
    # a code's text comes from the attacker and need not be valid UTF-8
    sys.stdout.reconfigure(errors="replace")

    image = cv2.imread(image_path)
    if image is None:
        return

    detector = cv2.QRCodeDetector()
    # each call reads codes the other misses: Multi finds them all, but returned an empty string for
    # a code with finder-like squares in its icon that the single decoder reads
    decoded = [detector.detectAndDecode(image)[0], *detector.detectAndDecodeMulti(image)[1]]
    for text in dict.fromkeys(filter(None, decoded)):
        print(text)


if __name__ == "__main__":
    main(sys.argv[1])
