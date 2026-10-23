// Modified for ACE, October 2026: isPresent looks words up in a map
// (see third_party/unautoit/third_party/README.md).

package lexer

import (
    "bytes"
    "math/bits"
    "strconv"
    "strings"
    "unicode"
)

const (
    InvalidInt TokenType = iota
)

type tokenizer struct {
    input []byte
    pos   int

    iStateCmt       int
    iStateStructRef int
    structRefName   string
}

func (tt *tokenizer) NumberOfLines() int {
    return bytes.Count(tt.input, []byte{10})
}

func NewTokenizer(inp []byte) ITokenizer {
    inp = bytes.ReplaceAll(inp, []byte{13, 10}, []byte{10})
    return &tokenizer{
        input: append(inp, 10), pos: 0,
    }
}

func (tt *tokenizer) db() byte {
    tt.pos++
    return tt.input[tt.pos-1]
}

func (tt *tokenizer) peek() byte {
    return tt.input[tt.pos]
}

func (tt *tokenizer) getStrLit(start byte) string {
    ans := new(bytes.Buffer)
    ans.WriteByte(start)
    for {
        c := tt.db()
        if c == start {
            ans.WriteByte(start)
            break
        }
        ans.WriteByte(c)
    }
    return ans.String()
}

func (tt *tokenizer) getIdent() string {
    ans := new(bytes.Buffer)
    for {
        c := rune(tt.peek())
        if !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != '_' {
            break
        }
        tt.pos++
        ans.WriteRune(c)
    }
    return ans.String()
}

func (tt *tokenizer) skipSpaces() {
    for {
        c := tt.peek()
        if c != ' ' {
            break
        }
        tt.pos++
    }
}

func (tt *tokenizer) NextToken() *Token {
    var curr byte
    for {
        if tt.pos >= len(tt.input) {
            return &Token{TokType: EOF, Value: ""}
        }
        if tt.iStateStructRef == 1 {
            tt.iStateStructRef = 0
            return &Token{TokType: StructField, Value: tt.structRefName}
        }
        tt.skipSpaces()
        curr = tt.peek()
        if curr == '\r' {
            tt.iStateCmt = 0
            tt.pos += 2
            return &Token{TokType: EOL, Value: "\n"}
        }
        if curr == '\n' {
            tt.iStateCmt = 0
            tt.pos++
            return &Token{TokType: EOL, Value: "\n"}
        }
        if tt.iStateCmt == 1 {
            // skip all bytes until NewLine
            continue
        }
        oldPos := tt.pos
        if 0x30 <= curr && curr <= 0x39 || curr == '.' {
            // number
            if tt.input[1+tt.pos] == 'X' || tt.input[1+tt.pos] == 'x' {
                tt.pos += 2
                var u uint64
                for {
                    x := unicode.ToLower(rune(tt.db()))
                    pos := strings.IndexRune("0123456789abcdef", x)
                    if pos == -1 {
                        break
                    }
                    u = u*16 + uint64(pos)
                }
                rv := fmtInt64(u)
                if bits.Len64(u) <= 32 {
                    return &Token{
                        Value:   rv,
                        TokType: Int32,
                    }
                } else {
                    return &Token{
                        Value:   rv,
                        TokType: Int64,
                    }
                }
            } else {
                buf := ""
                for {
                    x := unicode.ToLower(rune(tt.peek()))
                    pos := strings.IndexRune("0123456789.e+-", x)
                    if pos == -1 {
                        break
                    }
                    tt.pos++
                    buf += string(x)
                }
                if _, err := strconv.ParseInt(buf, 10, 64); err == nil {
                    if _, err := strconv.ParseInt(buf, 10, 32); err == nil {
                        return &Token{
                            Value:   buf,
                            TokType: Int32,
                        }
                    } else {
                        return &Token{
                            Value:   buf,
                            TokType: Int64,
                        }
                    }
                }
                _, err := strconv.ParseFloat(buf, 64)
                if err == nil {
                    return &Token{
                        Value:   buf,
                        TokType: Float64,
                    }
                } else {
                    tt.pos = oldPos
                }
            }
        }
        ident := tt.getIdent()
        if len(ident) > 0 {
            if isPresent(keywordIndex, ident) {
                return &Token{
                    Value:   cleanWord(keywordIndex, ident),
                    TokType: Keyword,
                }
            } else if isPresent(stdFunctionIndex, ident) {
                return &Token{
                    Value:   cleanWord(stdFunctionIndex, ident),
                    TokType: StdFunction,
                }
            } else {
                return &Token{
                    Value:   cleanWord(userFunctionIndex, ident),
                    TokType: UserFunction,
                }
            }
        }
        switch curr {
        case ';':
            for tt.peek() != '\n' {
                tt.pos++
            }
            return &Token{TokType: EOL, Value: ""}
        case '#':
            tt.pos++
            ident := "#" + tt.getIdent()
            if ident == "#Region" || ident == "#EndRegion" {
                for {
                    x := tt.peek()
                    if x == '\n' {
                        break
                    }
                    tt.pos++
                    ident += string(x)
                }
            }
            return &Token{TokType: Directive, Value: ident}
        case '(':
            tt.pos++
            return &Token{TokType: LParen, Value: "("}
        case ')':
            tt.pos++
            return &Token{TokType: RParen, Value: ")"}
        case '[':
            tt.pos++
            return &Token{TokType: LParen, Value: "["}
        case ']':
            tt.pos++
            return &Token{TokType: RParen, Value: "]"}
        case '$':
            // variable
            tt.pos++
            return &Token{Value: "$" + tt.getIdent(), TokType: Identifier}
        case '@':
            tt.pos++
            return &Token{
                Value:   "@" + cleanWord(macroIndex, tt.getIdent()),
                TokType: Macro,
            }
        case '"', '\'':
            tt.pos++
            return &Token{Value: tt.getStrLit(curr), TokType: StrLit}
        case ',':
            tt.pos++
            return &Token{Value: ",", TokType: Comma}
        }
        opStr := string(curr) + string(tt.input[tt.pos+1])
        switch opStr {
        case "+=":
            tt.pos += 2 // peek
            return &Token{TokType: OpAddEq, Value: "+="}
        case "-=":
            tt.pos += 2 // peek
            return &Token{TokType: OpSubEq, Value: "-="}
        case "*=":
            tt.pos += 2 // peek
            return &Token{TokType: OpMulEq, Value: "*="}
        case "/=":
            tt.pos += 2 // peek
            return &Token{TokType: OpDivEq, Value: "/="}
        case "&=":
            tt.pos += 2 // peek
            return &Token{TokType: OpConcatAssign, Value: "&="}
        case ">=":
            tt.pos += 2 // peek
            return &Token{TokType: OpGe, Value: ">="}
        case "<=":
            tt.pos += 2 // peek
            return &Token{TokType: OpLe, Value: "<="}
        case "==":
            tt.pos += 2 // peek
            return &Token{TokType: OpStrEq, Value: "=="}
        case "<>":
            tt.pos += 2 // peek
            return &Token{TokType: OpNe, Value: "<>"}
        }
        opStr = string(curr)
        switch opStr {
        case "^":
            tt.pos++
            return &Token{TokType: OpExp, Value: "^"}
        case "*":
            tt.pos++
            return &Token{TokType: OpMul, Value: "*"}
        case "/":
            tt.pos++
            return &Token{TokType: OpDiv, Value: "/"}
        case "+":
            tt.pos++
            return &Token{TokType: OpAdd, Value: "+"}
        case "-":
            tt.pos++
            return &Token{TokType: OpSub, Value: "-"}
        case "&":
            tt.pos++
            return &Token{TokType: OpConcat, Value: "&"}
        case ">":
            tt.pos++
            return &Token{TokType: OpGt, Value: ">"}
        case "<":
            tt.pos++
            return &Token{TokType: OpLt, Value: "<"}
        case "=":
            tt.pos++
            return &Token{TokType: OpAssign, Value: "="}
        case ".":
            tt.pos++
            if tt.iStateStructRef == 0 {
                tt.iStateStructRef = 1
                tt.structRefName = tt.getIdent()
            }
            return &Token{Value: ".", TokType: OpStructRef}
        }

        return &TokenInvalid
    }
}

func isPresent(idx wordIndex, entry string) bool {
    _, ok := idx[strings.ToLower(entry)]
    return ok
}

func isNumber(str string) TokenType {
    n := uint64(0)
    isValidInt := true
    for _, r := range str {
        if r < 0x30 || r > 0x39 {
            isValidInt = false
            break
        }
        n = n*10 + uint64(r) - 0x30
    }
    if isValidInt {
        nBits := bits.Len64(n)
        if nBits <= 32 {
            return Int32
        } else {
            return Int64
        }
    }
    _, err := strconv.ParseFloat(str, 64)
    if err == nil {
        return Float64
    }
    return InvalidInt
}
