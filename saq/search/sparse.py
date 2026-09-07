"""Lexical (sparse) encoding of text for the `sparse` named vector.

Text is turned into a bag of terms where every identifier an analyst might search for (an email
address, a url, an ip, a hash, a domain, a file path) is kept whole AND split into its parts, so
that "bob@example.com" matches the exact address while "example.com" still matches the domain.
Term ids are a stable 32-bit hash so no vocabulary has to be shared between processes or nodes,
and term weights are saturated term frequencies; inverse document frequency is applied by qdrant
itself (SparseVectorParams(modifier=IDF)), so this module needs no corpus statistics at all.

The same function encodes documents and queries.
"""

import hashlib
import re
from collections import Counter

from qdrant_client import models

# longest-first so a url wins over the domain and email inside it
IDENTIFIER_RE = re.compile(
    r"(?P<url>[a-z][a-z0-9+.-]*://[^\s<>\"']+)"
    r"|(?P<email>[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})"
    r"|(?P<hash>\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b)"
    r"|(?P<ipv4>\b(?:\d{1,3}\.){3}\d{1,3}\b)"
    r"|(?P<winpath>\b[a-z]:\\(?:[^\\\s<>\"|?*]+\\)*[^\\\s<>\"|?*]*)"
    r"|(?P<fqdn>\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b)"
    r"|(?P<posixpath>(?:/[^/\s<>\"'|?*]+){2,}/?)",
    re.IGNORECASE,
)

WORD_RE = re.compile(r"[a-z0-9]+", re.IGNORECASE)
SUBTOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+", re.IGNORECASE)

MIN_TOKEN_LENGTH = 2

# plain words that carry no signal on their own; identifiers are never filtered
STOPWORDS = frozenset("""
a an and are as at be been but by for from has have he her his i if in into is it its of on or our
she so than that the their them then there these they this to too was we were what when where which
who will with would you your yes no not do does did done can could should may might must shall
am us me my mine yours ours them him hers am s t re ve ll d m
http https www com net org html htm php
""".split())
# BM25-style saturation constant: the weight of a term grows with its frequency but never
# beyond 1.0, so a term repeated a hundred times does not dominate a document
TF_SATURATION_K = 1.2


def identifiers(text: str) -> list[str]:
    """Returns every identifier-shaped substring of text, lowercased, in order of appearance."""
    return [match.group(0).lower().rstrip(".,;:)") for match in IDENTIFIER_RE.finditer(text)]


def lexical_tokens(text: str) -> list[str]:
    """Returns the bag of terms for text: identifiers whole, their sub-tokens, and plain words."""
    tokens: list[str] = []
    for identifier in identifiers(text):
        tokens.append(identifier)
        tokens.extend(part.lower() for part in SUBTOKEN_SPLIT_RE.split(identifier) if len(part) >= MIN_TOKEN_LENGTH)

    tokens.extend(word for word in (w.lower() for w in WORD_RE.findall(text)) if len(word) >= MIN_TOKEN_LENGTH and word not in STOPWORDS)
    return tokens


def token_index(token: str) -> int:
    """Maps a term to a stable unsigned 32-bit id (blake2b, not hash(), which is per-process)."""
    digest = hashlib.blake2b(token.encode("utf-8"), digest_size=4).digest()
    return int.from_bytes(digest, "big")


def term_weights(text: str) -> dict[int, float]:
    """Returns {term id: saturated tf} for text. Empty text yields an empty dict."""
    counts = Counter(lexical_tokens(text))
    weights: dict[int, float] = {}
    for token, count in counts.items():
        index = token_index(token)
        # a hash collision just merges two rare terms; accumulating rather than overwriting
        # keeps the vector deterministic regardless of token order
        weights[index] = weights.get(index, 0.0) + count
    return {index: tf / (tf + TF_SATURATION_K) for index, tf in weights.items()}


def sparse_vector(text: str) -> models.SparseVector:
    """Returns the qdrant sparse vector for text with indices sorted ascending."""
    weights = term_weights(text)
    indices = sorted(weights)
    return models.SparseVector(indices=indices, values=[weights[index] for index in indices])
