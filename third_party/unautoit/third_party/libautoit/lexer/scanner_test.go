package lexer

import (
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

// strLitBytecode encodes s as a compiled script holding one string token.
func strLitBytecode(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 9, 9+2*len(u))
	binary.LittleEndian.PutUint32(b, 1)
	b[4] = 0x36
	binary.LittleEndian.PutUint32(b[5:], uint32(len(u)))
	for _, c := range u {
		b = append(b, byte(c)^byte(len(u)), byte(c>>8)^byte(len(u)>>8))
	}
	return b
}

func TestStrLitValue(t *testing.T) {
	cases := map[string]string{
		`HKCU\Software\Microsoft\`: `"HKCU\Software\Microsoft\"`,
		`]*\Z`:                     `"]*\Z"`,
		"\t<tr>":                   "\"\t<tr>\"",
		`say "hi"`:                 `"say ""hi"""`,
		"äöü €":                    `"äöü €"`,
		"":                         `""`,
	}
	for in, want := range cases {
		tok := NewLexer(strLitBytecode(in)).NextToken()
		if tok.TokType != StrLit || tok.Value != want {
			t.Errorf("NextToken(%q) = %v %q, want StrLit %q", in, tok.TokType, tok.Value, want)
		}
	}
}

// TestCleanWord checks the indexes against a case-insensitive linear scan.
func TestCleanWord(t *testing.T) {
	lists := map[string][]string{
		"keywords": Au3Keywords, "macros": Au3Macros,
		"std functions": Au3StdFunctions, "user functions": Au3UserFunctions,
	}
	indexes := map[string]wordIndex{
		"keywords": keywordIndex, "macros": macroIndex,
		"std functions": stdFunctionIndex, "user functions": userFunctionIndex,
	}
	for name, list := range lists {
		for _, w := range list {
			want := w
			for _, cand := range list {
				if strings.EqualFold(cand, w) {
					want = cand
					break
				}
			}
			if got := cleanWord(indexes[name], strings.ToUpper(w)); got != want {
				t.Errorf("%s: cleanWord(%q) = %q, want %q", name, strings.ToUpper(w), got, want)
			}
		}
		if got := cleanWord(indexes[name], "NotAnAutoItWord"); got != "NotAnAutoItWord" {
			t.Errorf("%s: unknown word changed to %q", name, got)
		}
	}
}
