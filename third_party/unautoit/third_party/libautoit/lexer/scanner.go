package lexer

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"unicode/utf16"
)

type TokenType int

type ITokenizer interface {
	NextToken() *Token
	NumberOfLines() int
}

const (
	// the following tokens need GetString()
	Keyword TokenType = iota
	StdFunction
	Macro
	Identifier
	UserFunction
	StructField
	StrLit
	Directive
	EndOfGetString // marker
	// end of GetString() based tokens
	LParen
	RParen
	LBracket
	RBracket
	Comma
	LegacyKeyword
	LegacyStdFunction
	Int32
	Int64
	Float64
	EOL

	// operators
	OpAssign
	OpStructRef
	OpAdd
	OpSub
	OpMul
	OpDiv
	OpNot
	OpAnd
	OpOr
	OpGt
	OpGe
	OpLt
	OpLe
	OpNe
	OpEq
	OpStrEq
	OpExp
	OpAddEq
	OpSubEq
	OpDivEq
	OpMulEq
	OpConcatAssign
	OpTernaryQuestion
	OpTernaryColon
	OpConcat
	OpEnd // marker to denote end of operator list

	EOF
	// Invalid Token
	InvalidToken
)

func (tt TokenType) IsBinaryOp() bool {
	return tt == OpExp || tt == OpMul || tt == OpDiv ||
		tt == OpAdd || tt == OpSub || tt == OpConcat ||
		tt == OpGt || tt == OpGe || tt == OpLe || tt == OpLt ||
		tt == OpStrEq || tt == OpNe || tt == OpAssign ||
		tt == OpAnd || tt == OpOr
}

func (tt TokenType) IsNumber() bool {
	return tt == Float64 || tt == Int32 || tt == Int64
}

func (tt TokenType) IsUnaryOp() bool {
	return tt == OpAdd || tt == OpSub || tt == OpNot
}

func (tt TokenType) GetUnaryPrec() int {
	if tt == OpAdd || tt == OpSub {
		return 9
	} else if tt == OpNot {
		return 10
	}
	return 0
}

func (tt TokenType) GetBinaryPrec() int {
	if tt == OpStructRef {
		return 8
	} else if tt == OpExp {
		return 7
	} else if tt == OpMul || tt == OpDiv {
		return 6
	} else if tt == OpAdd || tt == OpSub {
		return 5
	} else if tt == OpConcat {
		return 3
	} else if tt == OpGt || tt == OpGe || tt == OpLe || tt == OpLt ||
		tt == OpStrEq || tt == OpNe || tt == OpAssign {
		return 2
	} else if tt == OpAnd || tt == OpOr {
		return 1
	}
	return 0
}

type Token struct {
	TokType TokenType
	Value   string
	IdList  []int
	Id      int
}

type Lexer struct {
	src        []byte
	readOffset int // next byte to read
	offset     int // src[offset] == ch
	ch         int // current char
	nLines     int
	mark       int // trackback
	state      int
	fieldName  string
}

func (lex *Lexer) NumberOfLines() int {
	return lex.nLines
}

func NewLexer(inStream []byte) ITokenizer {
	n := int(binary.LittleEndian.Uint32(inStream[:4]))
	return &Lexer{
		src:    inStream[4:],
		nLines: n,
	}
}

func (tt TokenType) String() string {
	return Au3TokenTypes[tt]
}

func (t *Token) IsBlockStartKeyword() bool {
	tt := t.Value
	return tt == "If" || tt == "Func" || tt == "Switch" || tt == "Select" ||
		tt == "With" || tt == "For" || tt == "While" || tt == "Do" ||
		tt == "ElseIf" || tt == "Else" || tt == "Case" ||
		strings.HasPrefix(tt, "#Region")
}

func (t *Token) IsBlockEndKeyword() bool {
	tt := t.Value
	return strings.HasPrefix(tt, "End") || tt == "WEnd" ||
		tt == "Next" || tt == "Until" || tt == "Else" ||
		tt == "ElseIf" || tt == "Case" ||
		strings.HasPrefix(tt, "#EndRegion")
}

func (tt TokenType) IsAssignOp() bool {
	return tt == OpAssign || tt == OpAddEq || tt == OpSubEq ||
		tt == OpMulEq || tt == OpDivEq || tt == OpConcatAssign
}

func (tt TokenType) IsLiteral() bool {
	return tt == Int32 || tt == Int64 || tt == Float64 || tt == StrLit
}

func (tt TokenType) IsOpenBracket() bool {
	return tt == LBracket || tt == LParen
}

func (tt TokenType) IsCloseBracket() bool {
	return tt == RBracket || tt == RParen
}

func (t *Token) NeedsExtraNewline() bool {
	if t.TokType != Keyword {
		return false
	}
	tv := t.Value
	return tv == "EndFunc" || strings.HasPrefix(tv, "#Region")
}

func (t *Token) String() string {
	return fmt.Sprintf("Token [type=%s, id=%#02x, value=%q]", t.TokType, t.Id, t.Value)
}

func (t *Token) IsOperator() bool {
	v := int(t.TokType)
	return int(OpAssign) <= v && v < int(OpEnd)
}

func GetTokenByType(tt TokenType) *Token {
	for _, t := range StdTokens {
		if t.TokType == tt {
			return &t
		}
	}
	return &TokenInvalid
}

func GetTokenByValue(val string) *Token {
	for _, t := range StdTokens {
		if t.Value == val {
			return &t
		}
	}
	return nil
}

func GetTokenByByteValue(e byte) *Token {
	ev := string([]byte{e})
	for _, t := range StdTokens {
		if t.Value == ev {
			return &t
		}
	}
	return nil
}

func IsOperator(ch byte) bool {
	tt := GetTokenByByteValue(ch)
	return tt != nil && tt.IsOperator()
}

func GetTokenFromID(tokID int) Token {
	for _, tok := range StdTokens {
		for _, r := range tok.IdList {
			if r == tokID {
				return tok
			}
		}
	}
	return TokenInvalid
}

func (lex *Lexer) nextByte() byte {
	if lex.readOffset >= len(lex.src) {
		lex.ch = -1
	} else {
		lex.ch = int(lex.src[lex.readOffset])
	}
	lex.offset = lex.readOffset
	lex.readOffset++
	return byte(lex.ch)
}

func (lex *Lexer) u32() uint32 {
	b := []byte{0, 0, 0, 0}
	b[0] = lex.nextByte()
	b[1] = lex.nextByte()
	b[2] = lex.nextByte()
	b[3] = lex.nextByte()
	return binary.LittleEndian.Uint32(b)
}

func (lex *Lexer) u64() uint64 {
	b := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	b[0] = lex.nextByte()
	b[1] = lex.nextByte()
	b[2] = lex.nextByte()
	b[3] = lex.nextByte()
	b[4] = lex.nextByte()
	b[5] = lex.nextByte()
	b[6] = lex.nextByte()
	b[7] = lex.nextByte()
	return binary.LittleEndian.Uint64(b)
}

func (lex *Lexer) f64() float64 {
	return math.Float64frombits(lex.u64())
}

func (lex *Lexer) GetString() string {
	lex.mark = lex.offset
	size := int(lex.u32())
	ans := make([]uint16, size)
	for i := 0; i < size; i++ {
		lo := uint16(lex.nextByte() ^ byte(size))
		hi := uint16(lex.nextByte() ^ byte(size>>8))
		ans[i] = (hi << 8) | lo
	}
	return string(utf16.Decode(ans))
}

func (lex *Lexer) NextToken() *Token {
	var tok Token
	if lex.state == 1 {
		tok = Token{
			TokType: StructField,
			Value:   lex.fieldName,
			IdList:  nil,
			Id:      0,
		}
		lex.state = 0
		return &tok
	}
	tokType := int(lex.nextByte())
	id := lex.ch
	if id == -1 {
		return &TokenEOF
	}
	tok = GetTokenFromID(tokType)
	tok.Id = id
	if tok.TokType == InvalidToken {
		return &TokenInvalid
	}
	// xor str for - 30h,31h,32h,33h,34h,35h,36h,37h,
	if tok.TokType >= Keyword && tok.TokType < EndOfGetString {
		tmpStr := lex.GetString()
		tok.Value = tmpStr
	}
	if id == 0 {
		// keyword and function name
		keywordIndex := lex.u32()
		tok.TokType = Keyword
		tok.Value = Au3Keywords[keywordIndex]
	} else if id == 1 {
		fnIndex := lex.u32()
		tok.TokType = StdFunction
		tok.Value = Au3StdFunctions[fnIndex]
	} else if id > 2 && id < 16 {
		// int32
		tok.TokType = Int32
		tok.Value = fmtInt32(lex.u32())
	} else if id >= 16 && id < 32 {
		tok.TokType = Int64
		tok.Value = fmtInt64(lex.u64())
	} else if id >= 32 && id < 48 {
		tok.TokType = Float64
		tok.Value = fmt.Sprintf("%g", lex.f64())
	}
	if tok.TokType == Keyword {
		tok.Value = cleanWord(keywordIndex, tok.Value)
		if tok.Value == "Not" {
			tok.TokType = OpNot
		} else if tok.Value == "And" {
			tok.TokType = OpAnd
		} else if tok.Value == "Or" {
			tok.TokType = OpOr
		}
	} else if tok.TokType == StdFunction {
		tok.Value = cleanWord(stdFunctionIndex, tok.Value)
	}
	if tok.TokType == StrLit {
		// AutoIt strings have no escape sequences, only doubled quotes
		tok.Value = "\"" + strings.ReplaceAll(tok.Value, "\"", "\"\"") + "\""
	}
	if tok.TokType == StructField {
		if lex.state == 0 {
			lex.fieldName = tok.Value
			// return operator
			tok = Token{
				TokType: OpStructRef,
				Value:   ".",
				IdList:  nil,
				Id:      0,
			}
			lex.state = 1
		}
	}
	if tok.TokType == Identifier {
		tok.Value = "$" + tok.Value
	} else if tok.TokType == Macro {
		tok.Value = cleanWord(macroIndex, "@"+tok.Value)
	}
	if tok.TokType == UserFunction {
		tok.Value = cleanWord(userFunctionIndex, tok.Value)
	}
	return &tok
}

// wordIndex maps lowercased words to their canonical spelling
type wordIndex map[string]string

func newWordIndex(list []string) wordIndex {
	idx := make(wordIndex, len(list))
	// walk backwards so the first occurrence of a word wins
	for i := len(list) - 1; i >= 0; i-- {
		idx[strings.ToLower(list[i])] = list[i]
	}
	return idx
}

var (
	keywordIndex      = newWordIndex(Au3Keywords)
	macroIndex        = newWordIndex(Au3Macros)
	stdFunctionIndex  = newWordIndex(Au3StdFunctions)
	userFunctionIndex = newWordIndex(Au3UserFunctions)
)

func cleanWord(idx wordIndex, needle string) string {
	if word, ok := idx[strings.ToLower(needle)]; ok {
		return word
	}
	return needle
}
