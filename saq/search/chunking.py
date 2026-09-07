"""Splits a document into overlapping chunks sized in model tokens.

The embedding model silently truncates anything past its maximum sequence length, so every
document is split BEFORE encoding using the model's own tokenizer. Chunks are slices of the
original text (via token offsets), never de-tokenized text, so the stored snippet is exactly
what the analyst wrote.
"""

import logging
from dataclasses import dataclass
from typing import Optional, Protocol


class OffsetTokenizer(Protocol):
    """The subset of a HuggingFace fast tokenizer the chunker uses."""

    def __call__(self, text: str, *, add_special_tokens: bool, return_offsets_mapping: bool, truncation: bool) -> dict: ...


@dataclass(frozen=True)
class Chunk:
    index: int
    text: str
    token_count: int


def token_offsets(tokenizer: OffsetTokenizer, text: str) -> list[tuple[int, int]]:
    """Returns the (start, end) character span of every token in text."""
    encoding = tokenizer(text, add_special_tokens=False, return_offsets_mapping=True, truncation=False)
    # tokens with an empty span (some tokenizers emit them for whitespace) carry no text
    return [(start, end) for start, end in encoding["offset_mapping"] if end > start]


def chunk_text(
    text: str,
    tokenizer: OffsetTokenizer,
    *,
    chunk_tokens: int,
    overlap: int,
    max_chunks: int,
    title: Optional[str] = None,
    log_key: Optional[str] = None,
) -> list[Chunk]:
    """Splits text into at most max_chunks chunks of chunk_tokens tokens overlapping by overlap.

    The title, when given, is prepended to the first chunk only (so it is embedded with the
    opening of the document without being repeated in every chunk).
    """
    if chunk_tokens < 1:
        raise ValueError("chunk_tokens must be positive")
    if overlap >= chunk_tokens:
        raise ValueError("overlap must be smaller than chunk_tokens")

    text = text.strip()
    if not text:
        return []

    offsets = token_offsets(tokenizer, text)
    if not offsets:
        return []

    stride = chunk_tokens - overlap
    chunks: list[Chunk] = []
    start = 0
    while start < len(offsets):
        end = min(start + chunk_tokens, len(offsets))
        chunk_body = text[offsets[start][0]:offsets[end - 1][1]]
        if title and not chunks:
            chunk_body = f"{title}\n{chunk_body}"

        chunks.append(Chunk(index=len(chunks), text=chunk_body, token_count=end - start))

        if end >= len(offsets):
            break

        if len(chunks) >= max_chunks:
            logging.debug(f"document {log_key or '(unknown)'} truncated to {max_chunks} chunks ({len(offsets)} tokens)")
            break

        start += stride

    return chunks
