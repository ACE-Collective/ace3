import pytest

from saq.search.chunking import chunk_text
from saq.search.sparse import identifiers, lexical_tokens, sparse_vector, term_weights, token_index

pytestmark = pytest.mark.unit


class TestSparse:
    def test_identifiers_are_kept_whole(self):
        text = "Bob <bob@example.com> hit https://evil.example/a/b?x=1 from 10.20.30.40 and c:\\windows\\cmd.exe"
        found = identifiers(text)
        assert "bob@example.com" in found
        assert "https://evil.example/a/b?x=1" in found
        assert "10.20.30.40" in found
        assert "c:\\windows\\cmd.exe" in found

    def test_identifiers_are_also_split_into_parts(self):
        tokens = lexical_tokens("bob@example.com")
        assert "bob@example.com" in tokens
        assert "bob" in tokens
        assert "example" in tokens
        assert "com" in tokens

    def test_ipv4_octets_are_not_emitted_as_words(self):
        # single digits are below the minimum token length; the whole address is the term
        assert "1" not in lexical_tokens("1.2.3.4")
        assert "1.2.3.4" in lexical_tokens("1.2.3.4")

    def test_hashes_are_identifiers(self):
        digest = "a" * 64
        assert digest in identifiers(f"sha256 {digest} seen")

    def test_token_index_is_deterministic_u32(self):
        index = token_index("example")
        assert index == token_index("example")
        assert 0 <= index < 2**32
        assert index != token_index("Example".lower() + "x")

    def test_weights_saturate(self):
        once = term_weights("alpha")[token_index("alpha")]
        many = term_weights("alpha " * 100)[token_index("alpha")]
        assert once < many < 1.0

    def test_sparse_vector_is_sorted_and_unique(self):
        vector = sparse_vector("beta alpha beta gamma")
        assert vector.indices == sorted(vector.indices)
        assert len(vector.indices) == len(set(vector.indices)) == len(vector.values)

    def test_empty_text(self):
        vector = sparse_vector("")
        assert vector.indices == [] and vector.values == []

    def test_stopwords_are_dropped_but_identifiers_never_are(self):
        assert lexical_tokens("what is the weather today") == ["weather", "today"]
        assert sparse_vector("the and of").indices == []
        # "the" inside an identifier is part of the identifier, and the identifier survives
        assert "the.example.com" in lexical_tokens("the.example.com")
        assert "qr" in lexical_tokens("qr code") and "c2" in lexical_tokens("c2 beacon")


class TestChunking:
    def test_short_text_is_one_chunk(self, tokenizer):
        chunks = chunk_text("one two three", tokenizer, chunk_tokens=8, overlap=2, max_chunks=4)
        assert len(chunks) == 1
        assert chunks[0].text == "one two three"
        assert chunks[0].token_count == 3

    def test_windows_overlap_and_slice_original_text(self, tokenizer):
        words = [f"w{i}" for i in range(20)]
        text = "  ".join(words)  # double spaces: the slice must come from the original text
        chunks = chunk_text(text, tokenizer, chunk_tokens=8, overlap=2, max_chunks=10)
        assert [c.index for c in chunks] == [0, 1, 2]
        assert chunks[0].text.split() == words[0:8]
        assert chunks[1].text.split() == words[6:14]
        assert chunks[2].text.split() == words[12:20]
        assert "  " in chunks[0].text

    def test_max_chunks_truncates(self, tokenizer):
        text = " ".join(str(i) for i in range(100))
        chunks = chunk_text(text, tokenizer, chunk_tokens=8, overlap=0, max_chunks=3)
        assert len(chunks) == 3

    def test_title_on_first_chunk_only(self, tokenizer):
        text = " ".join(str(i) for i in range(20))
        chunks = chunk_text(text, tokenizer, chunk_tokens=8, overlap=0, max_chunks=5, title="Invoice")
        assert chunks[0].text.startswith("Invoice\n")
        assert not chunks[1].text.startswith("Invoice")

    def test_empty_and_whitespace(self, tokenizer):
        assert chunk_text("", tokenizer, chunk_tokens=8, overlap=0, max_chunks=1) == []
        assert chunk_text("   \n ", tokenizer, chunk_tokens=8, overlap=0, max_chunks=1) == []

    def test_invalid_overlap(self, tokenizer):
        with pytest.raises(ValueError):
            chunk_text("a b", tokenizer, chunk_tokens=4, overlap=4, max_chunks=1)
