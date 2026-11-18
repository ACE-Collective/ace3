package tidy

import (
	"strings"
	"testing"

	"github.com/x0r19x91/libautoit/lexer"
)

type fakeLexer struct{ toks []*lexer.Token }

func (f *fakeLexer) NextToken() *lexer.Token {
	if len(f.toks) == 0 {
		return &lexer.Token{TokType: lexer.EOF}
	}
	tok := f.toks[0]
	f.toks = f.toks[1:]
	return tok
}

func (f *fakeLexer) NumberOfLines() int { return 1 }

func TestStrLit(t *testing.T) {
	cases := []struct {
		lit  string // StrLit token value as produced by a lexer
		size int    // max string literal size
		want string
	}{
		// AutoIt has no escape sequences, so backslashes and tabs are verbatim
		{`"HKCU\Software\Microsoft\"`, 160, `"HKCU\Software\Microsoft\"`},
		{`"(?<=\d)(?=(\d{3})+\z)"`, 160, `"(?<=\d)(?=(\d{3})+\z)"`},
		{"\"\t<tr>\"", 160, "\"\t<tr>\""},
		{`"a\""b"`, 160, `"a\""b"`},
		// the delimiter is doubled
		{`"say ""hi"""`, 160, `"say ""hi"""`},
		{`'it''s'`, 160, `'it''s'`},
		// CR/LF cannot appear inside a literal
		{"\"a\r\nb\rc\nd\"", 160, `"a" & @CRLF & "b" & @CR & "c" & @LF & "d"`},
		{`""`, 160, `''`},
		// long literals are split on character boundaries
		{`"abcdef"`, 4, "\"abcd\" & _\n    \"ef\""},
		{`"ab""cd"`, 3, "\"ab\"\"\" & _\n    \"cd\""},
		{`"äöüß"`, 2, "\"äö\" & _\n    \"üß\""},
		{`"abcdef"`, 0, `"abcdef"`},
	}
	for _, c := range cases {
		tidy := NewTidyInfo(&fakeLexer{toks: []*lexer.Token{
			{TokType: lexer.StrLit, Value: c.lit},
			{TokType: lexer.EOL},
		}})
		tidy.SetMaxStringLiteralSize(c.size)
		if got := strings.TrimSuffix(tidy.Tidy(), "\n"); got != c.want {
			t.Errorf("Tidy(%q, size %d) = %q, want %q", c.lit, c.size, got, c.want)
		}
	}
}
