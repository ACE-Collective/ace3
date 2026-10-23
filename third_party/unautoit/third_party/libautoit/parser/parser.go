package parser

import (
	"bytes"
	"errors"
	lexer2 "github.com/x0r19x91/libautoit/lexer"
	"strings"
)

const DefaultIndent = 4

var (
	ErrAssignExpr     = errors.New("expected '='")
	ErrMissingBracket = errors.New("expected '['")
)

type Parser struct {
	lexer     *lexer2.Lexer
	currToken *lexer2.Token
	peekToken *lexer2.Token
}

func NewParser(l *lexer2.Lexer) *Parser {
	p := &Parser{lexer: l}
	p.nextToken()
	p.nextToken()
	return p
}

func (p *Parser) nextToken() *lexer2.Token {
	p.currToken = p.peekToken
	p.peekToken = p.lexer.NextToken()
	return p.currToken
}

func (p *Parser) Parse() (string, error) {
	return p.ParseStmtList(0, "EOF")
}

func padWith(indent int) string {
	return strings.Repeat(" ", indent)
}

func (p *Parser) ParseStmt(indent int) (string, error) {
	tok := p.currToken
	var err error
	var ans string
	if tok.TokType == lexer2.Directive {
		tt := tok.Value
		p.nextToken()
		return padWith(indent) + tt, nil
	} else if tok.TokType == lexer2.Identifier {
		ans, err = p.ParseAssign()
		if err != nil {
			return "", err
		}
		ans = padWith(indent) + ans
	} else if tok.TokType == lexer2.UserFunction || tok.TokType == lexer2.StdFunction {
		a, err := p.ParseCallExpr()
		return padWith(indent) + a, err
	} else if tok.TokType == lexer2.Keyword {
		tv := tok.Value
		if tv == "Global" || tv == "Local" || tv == "Static" ||
			tv == "Dim" || tv == "Const" {
			if p.peekToken.Value == "Enum" {
				return p.ParseEnum(indent)
			}
			ans = tv
			p.nextToken()
			tv = p.currToken.Value
			if tv == "Global" || tv == "Local" || tv == "Static" ||
				tv == "Dim" || tv == "Const" {
				ans += " " + tv
				p.nextToken()
			}
			ret, err := p.ParseDeclList()
			if err != nil {
				return "", nil
			}
			return padWith(indent) + ans + " " + ret, nil
		} else if tv == "Func" {
			return p.ParseFuncDecl(indent)
		} else if tv == "Return" {
			p.nextToken()
			ret, err := p.ParseExprPrec(0)
			if err != nil {
				return "", err
			}
			return padWith(indent) + "Return " + ret, nil
		} else if tv == "ContinueCase" {
			p.nextToken()
			return padWith(indent) + tv, nil
		} else if tv == "ContinueLoop" {
			p.nextToken()
			exp, err := p.ParseExprPrec(0)
			return padWith(indent) + "ContinueLoop " + exp, err
		} else if tv == "For" {
			return p.ParseForLoop(indent)
		} else if tv == "ReDim" {
			return p.ParseRedimStmt(indent)
		} else if tv == "Do" {
			return p.ParseDoUntilLoop(indent)
		} else if tv == "Exit" {
			return p.ParseExitStmt(indent)
		} else if tv == "While" {
			return p.ParseWhileStmt(indent)
		} else {
			return "unimpl " + tv, nil
		}
	}
	return ans, err
}

func (p *Parser) ParseLValue() (string, error) {
	ans := new(bytes.Buffer)
	tt := p.currToken
	if tt.TokType == lexer2.Identifier {
		ans.WriteString("$" + tt.Value)
		p.nextToken()
	} else if tt.TokType == lexer2.Macro {
		ans.WriteString("@" + tt.Value)
		p.nextToken()
	} else if tt.TokType == lexer2.StdFunction || tt.TokType == lexer2.UserFunction {
		fnCall, err := p.ParseCallExpr()
		if err != nil {
			return "", err
		}
		ans.WriteString(fnCall)
	}

	for {
		if p.currToken.TokType == lexer2.OpStructRef {
			p.nextToken()
			tt := p.currToken.Value
			p.nextToken()
			ans.WriteString("." + tt)
		} else if p.currToken.TokType == lexer2.LBracket {
			// array index, consume it
			p.nextToken()
			ans.WriteRune('[')
			expr, err := p.ParseExprPrec(0)
			if err != nil {
				return "", err
			}
			ans.WriteString(expr)
			if p.currToken.TokType != lexer2.RBracket {
				return "", ErrMissingBracket
			}
			p.nextToken()
			ans.WriteRune(']')
		} else {
			break
		}
	}
	return ans.String(), nil
}

func (p *Parser) ParseExprPrec(prec int) (string, error) {
	unaryPrec := p.currToken.TokType.GetUnaryPrec()
	ans := new(bytes.Buffer)
	if unaryPrec != 0 && unaryPrec >= prec {
		op := p.currToken
		p.nextToken()
		ret, err := p.ParseExprPrec(unaryPrec)
		if err != nil {
			return "", err
		}
		ans.WriteString(op.Value)
		if op.TokType == lexer2.OpNot {
			ans.WriteString(" ")
		}
		ans.WriteString(ret)
	} else {
		ret, err := p.ParsePrimaryExpr()
		if err != nil {
			return "", err
		}
		ans.WriteString(ret)
	}
	for {
		binPrec := p.currToken.TokType.GetBinaryPrec()
		if binPrec == 0 || binPrec <= prec {
			break
		}
		op := p.currToken.Value
		p.nextToken()
		right, err := p.ParseExprPrec(binPrec)
		if err != nil {
			return "", err
		}
		if op != "." {
			ans.WriteRune(' ')
		}
		ans.WriteString(op)
		if op != "." {
			ans.WriteRune(' ')
		}
		ans.WriteString(right)
	}
	return ans.String(), nil
}

func (p *Parser) ParseAssign() (string, error) {
	lhs, err := p.ParseLValue()
	if err != nil {
		return "", err
	}
	if p.currToken.TokType == lexer2.Comma {
		p.nextToken()
		return lhs, nil
	}
	assOp := p.currToken.Value
	if !p.currToken.TokType.IsAssignOp() {
		// return "", errors.New("expected '='")
		return lhs, nil
	}
	p.nextToken()
	rhs, err := p.ParseExprPrec(0)
	if err != nil {
		return "", errors.New("expected expr")
	}
	return lhs + " " + assOp + " " + rhs, nil
}

func (p *Parser) ParseDeclList() (string, error) {
	var ans string
	for {
		ret, err := p.ParseAssign()
		if err != nil {
			return "", err
		}
		ans += ret
		if p.currToken.TokType == lexer2.EOL {
			break
		}
		if p.currToken.TokType == lexer2.Comma {
			p.nextToken()
			ans += ", "
		} else {
			return "", errors.New("expected assignment")
		}
	}
	return ans, nil
}

func (p *Parser) ParseDecl() (string, error) {
	peek := p.currToken.Value
	var ans string
	if peek == "Global" || peek == "Local" || peek == "Dim" || peek == "Static" {
		ans = peek
		p.nextToken()
	}
	if p.currToken.Value == "Const" {
		ans += " Const"
		p.nextToken()
	}
	ret, err := p.ParseDeclList()
	if err != nil {
		return "", err
	}
	return ans + " " + ret, nil
}

func (p *Parser) ParseArrayExpr() (string, error) {
	ans := new(bytes.Buffer)
	for {
		if p.currToken.TokType == lexer2.RBracket {
			break
		}
		pp, err := p.ParseExprPrec(0)
		if err != nil {
			return "", err
		}
		ans.WriteString(pp)
		if p.currToken.TokType == lexer2.RBracket {
			break
		}
		if p.currToken.TokType != lexer2.Comma {
			return "", errors.New("expected ','")
		}
		p.nextToken()
		ans.WriteString(", ")
	}
	return ans.String(), nil
}

func (p *Parser) ParsePrimaryExpr() (string, error) {
	tt := p.currToken
	if tt.TokType == lexer2.LBracket {
		p.nextToken()
		ret, err := p.ParseArrayExpr()
		if err != nil {
			return "", err
		}
		if p.currToken.TokType != lexer2.RBracket {
			return "", errors.New("expected ']'")
		}
		p.nextToken()
		if ret[0] != '[' && ret[len(ret)-1] != ']' {
			ret = " " + ret + " "
		}
		return "[" + ret + "]", nil
	}
	if tt.TokType == lexer2.LParen {
		p.nextToken()
		ret, err := p.ParseExprPrec(0)
		if err != nil || p.currToken.TokType != lexer2.RParen {
			return "", err
		}
		p.nextToken()
		return "(" + ret + ")", nil
	} else if tt.TokType.IsLiteral() || tt.TokType == lexer2.StructField {
		p.nextToken()
		return tt.Value, nil
	} else if tt.TokType == lexer2.Macro {
		p.nextToken()
		return "@" + tt.Value, nil
	} else if tt.TokType == lexer2.Identifier {
		return p.ParseLValue()
	} else if tt.TokType == lexer2.UserFunction || tt.TokType == lexer2.StdFunction {
		return p.ParseCallExpr()
	} else if tt.TokType == lexer2.Keyword {
		if tt.Value == "Default" || tt.Value == "False" ||
			tt.Value == "Null" || tt.Value == "True" {
			p.nextToken()
			return tt.Value, nil
		}
	}
	return "", errors.New("expected primary expr")
}

func (p *Parser) ParseFuncDecl(indent int) (string, error) {
	ans := new(bytes.Buffer)
	ans.WriteString(padWith(indent))
	ans.WriteString("Func ")
	p.nextToken()
	if p.currToken.TokType != lexer2.UserFunction {
		return "", errors.New("expected func name")
	}
	ans.WriteString(p.currToken.Value)
	p.nextToken()
	if p.currToken.TokType != lexer2.LParen {
		return "", errors.New("expected '('")
	}
	ans.WriteRune('(')
	p.nextToken()
	ret, err := p.ParseFuncSignature()
	if err != nil {
		return "", err
	}
	ans.WriteString(ret)
	if p.currToken.TokType != lexer2.RParen {
		return "", errors.New("expected ')'")
	}
	p.nextToken()
	ans.WriteRune(')')
	p.nextToken()
	ans.WriteRune('\n')
	stmtList, err := p.ParseStmtList(indent+DefaultIndent, "EndFunc")
	if err != nil {
		return "", err
	}
	ans.WriteString(stmtList)
	if p.currToken.Value != "EndFunc" {
		return "", errors.New("expected EndFunc")
	}
	ans.WriteString(padWith(indent))
	ans.WriteString("EndFunc")
	p.nextToken()
	return ans.String(), nil
}

func (p *Parser) ParseFuncParam() (string, error) {
	// [ByRef] [Const] $argName [ = Expr ]
	ans := new(bytes.Buffer)
	if p.currToken.TokType == lexer2.Keyword {
		if p.currToken.Value != "ByRef" && p.currToken.Value != "Const" {
			return "", errors.New("expected Byref/const")
		}
		ans.WriteString(p.currToken.Value)
		p.nextToken()
	}
	if p.currToken.TokType == lexer2.Keyword {
		if p.currToken.Value != "ByRef" && p.currToken.Value != "Const" {
			return "", errors.New("expected Byref/const")
		}
		ans.WriteString(" " + p.currToken.Value)
		p.nextToken()
	}
	if p.currToken.TokType != lexer2.Identifier {
		return "", errors.New("expected identifier")
	}
	if ans.Len() > 0 {
		ans.WriteRune(' ')
	}
	ans.WriteString("$" + p.currToken.Value)
	p.nextToken()
	if p.currToken.TokType == lexer2.OpAssign {
		// optional value
		p.nextToken()
		def, err := p.ParseExprPrec(0)
		if err != nil {
			return "", err
		}
		ans.WriteString(" = ")
		ans.WriteString(def)
	}
	return ans.String(), nil
}

func (p *Parser) ParseFuncSignature() (string, error) {
	ans := new(bytes.Buffer)
	for {
		if p.currToken.TokType == lexer2.RParen {
			break
		}
		ret, err := p.ParseFuncParam()
		if err != nil {
			return "", err
		}
		ans.WriteString(ret)
		if p.currToken.TokType == lexer2.Comma {
			ans.WriteString(", ")
			p.nextToken()
		} else {
			break
		}
	}
	return ans.String(), nil
}

func (p *Parser) ParseStmtList(indent int, term string) (string, error) {
	ans := new(bytes.Buffer)
	for {
		stmt, err := p.ParseStmt(indent)
		if err != nil {
			return "", err
		}
		ans.WriteString(stmt)
		if p.currToken.TokType == lexer2.EOL {
			p.nextToken()
			ans.WriteRune('\n')
		}
		if p.currToken.Value == term {
			break
		}
	}
	return ans.String(), nil
}

func (p *Parser) ParseCallExpr() (string, error) {
	ans := new(bytes.Buffer)
	ans.WriteString(p.currToken.Value)
	p.nextToken()
	if p.currToken.TokType != lexer2.LParen {
		return "", errors.New("expected '('")
	}
	ans.WriteRune('(')
	p.nextToken()
	ret, err := p.ParseCallParamList()
	if err != nil {
		return "", err
	}
	ans.WriteString(ret)
	if p.currToken.TokType != lexer2.RParen {
		return "", errors.New("expected ')'")
	}
	ans.WriteRune(')')
	p.nextToken()
	return ans.String(), nil
}

func (p *Parser) ParseCallParamList() (string, error) {
	ans := new(bytes.Buffer)
	// [lvalue || rvalue] *
	for {
		if p.currToken.TokType == lexer2.RParen {
			break
		}
		ret, err := p.ParseExprPrec(0)
		if err != nil {
			return "", err
		}
		ans.WriteString(ret)
		if p.currToken.TokType == lexer2.RParen {
			break
		}
		if p.currToken.TokType != lexer2.Comma {
			return "", errors.New("expected ','")
		}
		ans.WriteString(", ")
		p.nextToken()
	}
	return ans.String(), nil
}

func (p *Parser) ParseForLoop(indent int) (string, error) {
	ans := new(bytes.Buffer)
	if p.currToken.TokType != lexer2.Keyword || p.currToken.Value != "For" {
		return "", errors.New("expected For")
	}
	ans.WriteString(padWith(indent) + "For ")
	p.nextToken()
	if p.currToken.TokType != lexer2.Identifier {
		return "", errors.New("expected identifier")
	}
	ans.WriteString("$" + p.currToken.Value)
	p.nextToken()
	if p.currToken.Value == "In" {
		// for each loop
		p.nextToken()
		rhs, err := p.ParseExprPrec(0)
		if err != nil {
			return "", err
		}
		ans.WriteString(" In ")
		ans.WriteString(rhs)
	} else if p.currToken.TokType == lexer2.OpAssign {
		ans.WriteString(" = ")
		p.nextToken()
		start, err := p.ParseExprPrec(0)
		if err != nil {
			return "", err
		}
		ans.WriteString(start)
		if p.currToken.TokType != lexer2.Keyword || p.currToken.Value != "To" {
			return "", errors.New("expected 'To'")
		}
		p.nextToken()
		ans.WriteString(" To ")
		end, err := p.ParseExprPrec(0)
		if err != nil {
			return "", err
		}
		ans.WriteString(end)
		if p.currToken.TokType == lexer2.Keyword && p.currToken.Value == "Step" {
			p.nextToken()
			step, err := p.ParseExprPrec(0)
			if err != nil {
				return "", err
			}
			ans.WriteString(" Step ")
			ans.WriteString(step)
		}
	} else {
		return "", errors.New("expected '='")
	}
	if p.currToken.TokType != lexer2.EOL {
		return "", errors.New("expected End of Statement")
	}
	p.nextToken()
	ans.WriteRune('\n')
	stmts, err := p.ParseStmtList(DefaultIndent+indent, "Next")
	if err != nil {
		return "", err
	}
	ans.WriteString(stmts)
	if p.currToken.TokType != lexer2.Keyword || p.currToken.Value != "Next" {
		return "", errors.New("expected Next")
	}
	p.nextToken()
	ans.WriteString(padWith(indent) + "Next")
	return ans.String(), nil
}

func (p *Parser) ParseDoUntilLoop(indent int) (string, error) {
	if p.currToken.TokType != lexer2.Keyword {
		return "", errors.New("expected Do")
	}
	ans := new(bytes.Buffer)
	ans.WriteString(padWith(indent) + "Do")
	ans.WriteRune('\n')
	p.nextToken()
	if p.currToken.TokType != lexer2.EOL {
		return "", errors.New("expected end of line")
	}
	p.nextToken()
	stmts, err := p.ParseStmtList(indent+DefaultIndent, "Until")
	if err != nil {
		return "", err
	}
	ans.WriteString(stmts)
	if p.currToken.Value != "Until" {
		return "", errors.New("expected until")
	}
	p.nextToken()
	ans.WriteString(padWith(indent) + "Until ")
	exp, err := p.ParseExprPrec(0)
	if err != nil {
		return "", err
	}
	ans.WriteString(exp)
	return ans.String(), nil
}

func (p *Parser) ParseExitStmt(indent int) (string, error) {
	if p.currToken.Value != "Exit" {
		return "", errors.New("expected Exit")
	}
	p.nextToken()
	rv := "Exit"
	if p.currToken.TokType != lexer2.EOL {
		exp, err := p.ParseExprPrec(0)
		if err != nil {
			return "", err
		}
		rv += " " + exp
	}
	return padWith(indent) + rv, nil
}

func (p *Parser) ParseRedimStmt(indent int) (string, error) {
	p.nextToken()
	ans := new(bytes.Buffer)
	ans.WriteString(padWith(indent) + "Redim ")
	if p.currToken.TokType != lexer2.Identifier {
		return "", errors.New("expected variable")
	}
	ans.WriteString("$" + p.currToken.Value)
	p.nextToken()
	for {
		if p.currToken.TokType != lexer2.LBracket {
			break
		}
		p.nextToken()
		sub, err := p.ParseExprPrec(0)
		if err != nil {
			return "", err
		}
		if p.currToken.TokType != lexer2.RBracket {
			return "", errors.New("expected ]")
		}
		p.nextToken()
		ans.WriteRune('[')
		ans.WriteString(sub)
		ans.WriteRune(']')
	}
	return ans.String(), nil
}

func (p *Parser) ParseEnum(indent int) (string, error) {
	ans := new(bytes.Buffer)
	ans.WriteString(padWith(indent) + p.currToken.Value)
	p.nextToken()
	ans.WriteString(" " + p.currToken.Value)
	p.nextToken()
	if p.currToken.Value == "Step" {
		ans.WriteString(" Step ")
		if p.peekToken.Value == "*" || p.peekToken.Value == "+" ||
			p.peekToken.Value == "-" {
			p.nextToken()
			ans.WriteString(p.currToken.Value)
			p.nextToken()
		}
		ans.WriteString(p.currToken.Value)
		p.nextToken()
	}
	for {
		ans.WriteString(" ")
		ident := p.currToken
		if ident.TokType != lexer2.Identifier {
			return "", errors.New("expected ident")
		}
		ans.WriteString("$" + ident.Value)
		p.nextToken()
		if p.currToken.TokType == lexer2.OpAssign {
			p.nextToken()
			exp, err := p.ParseExprPrec(0)
			if err != nil {
				return "", err
			}
			ans.WriteString(" = ")
			ans.WriteString(exp)
		}
		if p.currToken.TokType != lexer2.Comma {
			break
		}
		p.nextToken()
		ans.WriteString(",")
	}
	return ans.String(), nil
}

func (p *Parser) ParseWhileStmt(indent int) (string, error) {
	ans := new(bytes.Buffer)
	ans.WriteString(padWith(indent) + "While ")
	p.nextToken()
	expr, err := p.ParseExprPrec(0)
	if err != nil {
		return "", err
	}
	ans.WriteString(expr)
	if p.currToken.TokType != lexer2.EOL {
		return "", errors.New("end of stmt expected")
	}
	ans.WriteRune('\n')
	p.nextToken()
	stmts, err := p.ParseStmtList(indent+DefaultIndent, "WEnd")
	if err != nil {
		return "", err
	}
	ans.WriteString(stmts)
	if p.currToken.Value != "WEnd" {
		return "", errors.New("expected WEnd")
	}
	p.nextToken()
	ans.WriteString(padWith(indent) + "WEnd")
	return ans.String(), nil
}
