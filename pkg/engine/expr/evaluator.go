// Package expr implements a lightweight boolean expression evaluator for pipeline conditionals.
package expr

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// LookupFunc resolves variable references encountered in expressions.
type LookupFunc func(path string) (any, bool)

var (
	// ErrSyntax indicates the expression could not be parsed.
	ErrSyntax = errors.New("condition syntax error")
	// ErrUnknownIdentifier indicates a referenced variable is not available in scope.
	ErrUnknownIdentifier = errors.New("unknown identifier")
	// ErrTypeMismatch indicates the expression attempted an unsupported type coercion.
	ErrTypeMismatch = errors.New("type mismatch")
)

// Options control evaluator behaviour.
type Options struct {
	Timeout time.Duration
}

// Evaluator evaluates boolean expressions against a lookup scope.
type Evaluator struct {
	timeout time.Duration
}

// NewEvaluator constructs an Evaluator applying sane defaults.
func NewEvaluator(opts Options) *Evaluator {
	timeout := opts.Timeout
	if timeout <= 0 {
		// Default to 10ms - tight enough to prevent abuse while allowing
		// reasonable expression evaluation. Original 1ms was too aggressive
		// for complex conditionals with multiple variable lookups.
		timeout = 10 * time.Millisecond
	}
	return &Evaluator{timeout: timeout}
}

// Evaluate determines whether the supplied expression evaluates to true using the provided lookup.
func (e *Evaluator) Evaluate(ctx context.Context, expression string, lookup LookupFunc) (bool, error) {
	if lookup == nil {
		return false, fmt.Errorf("%w: lookup function is required", ErrSyntax)
	}

	expression = strings.TrimSpace(expression)
	if expression == "" {
		return false, fmt.Errorf("%w: empty expression", ErrSyntax)
	}

	if ctx == nil {
		ctx = context.Background()
	}

	var cancel context.CancelFunc
	if e.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, e.timeout)
		defer cancel()
	}

	l := newLexer(expression)
	p := newParser(ctx, l)
	node, err := p.parseExpression()
	if err != nil {
		return false, err
	}

	if err := p.expect(tokenEOF); err != nil {
		return false, err
	}

	value, err := node.Eval(ctx, lookup)
	if err != nil {
		return false, err
	}

	boolValue, ok := value.(bool)
	if !ok {
		return false, fmt.Errorf("%w: expression does not evaluate to boolean", ErrTypeMismatch)
	}

	return boolValue, nil
}

// --- Lexer ---

type tokenType int

type token struct {
	typ     tokenType
	literal string
}

const (
	tokenIllegal tokenType = iota
	tokenEOF
	tokenIdentifier
	tokenNumber
	tokenString
	tokenBool
	tokenAnd
	tokenOr
	tokenNot
	tokenEq
	tokenNeq
	tokenGt
	tokenGte
	tokenLt
	tokenLte
	tokenLParen
	tokenRParen
	tokenMinus
	tokenPlus
)

func (t tokenType) String() string {
	switch t {
	case tokenIllegal:
		return "illegal"
	case tokenEOF:
		return "eof"
	case tokenIdentifier:
		return "identifier"
	case tokenNumber:
		return "number"
	case tokenString:
		return "string"
	case tokenBool:
		return "bool"
	case tokenAnd:
		return "&&"
	case tokenOr:
		return "||"
	case tokenNot:
		return "!"
	case tokenEq:
		return "=="
	case tokenNeq:
		return "!="
	case tokenGt:
		return ">"
	case tokenGte:
		return ">="
	case tokenLt:
		return "<"
	case tokenLte:
		return "<="
	case tokenLParen:
		return "("
	case tokenRParen:
		return ")"
	case tokenMinus:
		return "-"
	case tokenPlus:
		return "+"
	default:
		return "unknown"
	}
}

type lexer struct {
	input  string
	length int
	pos    int
}

func newLexer(input string) *lexer {
	return &lexer{input: input, length: len(input)}
}

func (l *lexer) nextToken() token {
	l.skipWhitespace()
	if l.pos >= l.length {
		return token{typ: tokenEOF}
	}

	ch := l.input[l.pos]

	switch ch {
	case '(':
		l.pos++
		return token{typ: tokenLParen, literal: "("}
	case ')':
		l.pos++
		return token{typ: tokenRParen, literal: ")"}
	case '!':
		if l.peek() == '=' {
			l.pos += 2
			return token{typ: tokenNeq, literal: "!="}
		}
		l.pos++
		return token{typ: tokenNot, literal: "!"}
	case '=':
		if l.peek() == '=' {
			l.pos += 2
			return token{typ: tokenEq, literal: "=="}
		}
	case '>':
		if l.peek() == '=' {
			l.pos += 2
			return token{typ: tokenGte, literal: ">="}
		}
		l.pos++
		return token{typ: tokenGt, literal: ">"}
	case '<':
		if l.peek() == '=' {
			l.pos += 2
			return token{typ: tokenLte, literal: "<="}
		}
		l.pos++
		return token{typ: tokenLt, literal: "<"}
	case '&':
		if l.peek() == '&' {
			l.pos += 2
			return token{typ: tokenAnd, literal: "&&"}
		}
	case '|':
		if l.peek() == '|' {
			l.pos += 2
			return token{typ: tokenOr, literal: "||"}
		}
	case '-':
		l.pos++
		return token{typ: tokenMinus, literal: "-"}
	case '+':
		l.pos++
		return token{typ: tokenPlus, literal: "+"}
	case '\'', '"':
		return l.scanString()
	}

	if isDigit(ch) {
		return l.scanNumber()
	}

	if isIdentifierStart(ch) {
		return l.scanIdentifier()
	}

	return token{typ: tokenIllegal, literal: string(ch)}
}

func (l *lexer) skipWhitespace() {
	for l.pos < l.length {
		switch l.input[l.pos] {
		case ' ', '\t', '\n', '\r':
			l.pos++
		default:
			return
		}
	}
}

func (l *lexer) peek() byte {
	if l.pos+1 >= l.length {
		return 0
	}
	return l.input[l.pos+1]
}

func (l *lexer) advance() byte {
	if l.pos >= l.length {
		return 0
	}
	ch := l.input[l.pos]
	l.pos++
	return ch
}

func (l *lexer) scanNumber() token {
	start := l.pos
	hasDot := false

	for l.pos < l.length {
		ch := l.input[l.pos]
		if ch == '.' {
			if hasDot {
				break
			}
			hasDot = true
			l.pos++
			continue
		}
		if !isDigit(ch) {
			break
		}
		l.pos++
	}

	return token{typ: tokenNumber, literal: l.input[start:l.pos]}
}

func (l *lexer) scanIdentifier() token {
	start := l.pos
	for l.pos < l.length {
		ch := l.input[l.pos]
		if isIdentifierPart(ch) {
			l.pos++
			continue
		}
		break
	}
	literal := l.input[start:l.pos]
	switch strings.ToLower(literal) {
	case "true", "false":
		return token{typ: tokenBool, literal: literal}
	}
	return token{typ: tokenIdentifier, literal: literal}
}

func (l *lexer) scanString() token {
	quote := l.advance()
	var builder strings.Builder
	escaped := false

	for l.pos < l.length {
		ch := l.advance()
		if escaped {
			switch ch {
			case 'n':
				builder.WriteByte('\n')
			case 't':
				builder.WriteByte('\t')
			case 'r':
				builder.WriteByte('\r')
			case '\\', '\'', '"':
				builder.WriteByte(ch)
			default:
				builder.WriteByte(ch)
			}
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == quote {
			return token{typ: tokenString, literal: builder.String()}
		}
		builder.WriteByte(ch)
	}

	return token{typ: tokenIllegal, literal: "unterminated string"}
}

func isDigit(ch byte) bool {
	return ch >= '0' && ch <= '9'
}

func isIdentifierStart(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_' || ch == '$'
}

func isIdentifierPart(ch byte) bool {
	switch {
	case isIdentifierStart(ch):
		return true
	case ch >= '0' && ch <= '9':
		return true
	case ch == '.', ch == '-', ch == ':':
		return true
	}
	return false
}

// --- Parser ---

type parser struct {
	ctx  context.Context
	lex  *lexer
	cur  token
	peek token
}

func newParser(ctx context.Context, lex *lexer) *parser {
	p := &parser{ctx: ctx, lex: lex}
	p.nextToken()
	p.nextToken()
	return p
}

func (p *parser) nextToken() {
	p.cur = p.peek
	p.peek = p.lex.nextToken()
}

func (p *parser) parseExpression() (node, error) {
	return p.parseOr()
}

func (p *parser) parseOr() (node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}

	for p.cur.typ == tokenOr {
		op := p.cur.typ
		p.nextToken()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &binaryExpr{op: op, left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (node, error) {
	left, err := p.parseComparison()
	if err != nil {
		return nil, err
	}

	for p.cur.typ == tokenAnd {
		op := p.cur.typ
		p.nextToken()
		right, err := p.parseComparison()
		if err != nil {
			return nil, err
		}
		left = &binaryExpr{op: op, left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseComparison() (node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}

	for {
		switch p.cur.typ {
		case tokenEq, tokenNeq, tokenGt, tokenGte, tokenLt, tokenLte:
			op := p.cur.typ
			p.nextToken()
			right, err := p.parseUnary()
			if err != nil {
				return nil, err
			}
			left = &binaryExpr{op: op, left: left, right: right}
		default:
			return left, nil
		}
	}
}

func (p *parser) parseUnary() (node, error) {
	switch p.cur.typ {
	case tokenNot, tokenMinus, tokenPlus:
		op := p.cur.typ
		p.nextToken()
		operand, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &unaryExpr{op: op, operand: operand}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (node, error) {
	if err := checkContext(p.ctx); err != nil {
		return nil, err
	}

	tok := p.cur
	switch tok.typ {
	case tokenIdentifier:
		p.nextToken()
		return &identifierExpr{name: tok.literal}, nil
	case tokenNumber:
		p.nextToken()
		value, err := strconv.ParseFloat(tok.literal, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid number %q", ErrSyntax, tok.literal)
		}
		return &literalExpr{value: value}, nil
	case tokenString:
		p.nextToken()
		return &literalExpr{value: tok.literal}, nil
	case tokenBool:
		p.nextToken()
		boolVal := strings.EqualFold(tok.literal, "true")
		return &literalExpr{value: boolVal}, nil
	case tokenLParen:
		p.nextToken()
		exprNode, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		if err := p.expect(tokenRParen); err != nil {
			return nil, err
		}
		p.nextToken()
		return exprNode, nil
	default:
		return nil, fmt.Errorf("%w: unexpected token %q", ErrSyntax, tok.literal)
	}
}

func (p *parser) expect(expected tokenType) error {
	if p.cur.typ == tokenIllegal {
		return fmt.Errorf("%w: %s", ErrSyntax, p.cur.literal)
	}
	if p.cur.typ != expected {
		return fmt.Errorf("%w: expected %s, got %s", ErrSyntax, expected.String(), p.cur.typ.String())
	}
	return nil
}

// --- AST Nodes ---

type node interface {
	Eval(ctx context.Context, lookup LookupFunc) (any, error)
}

type binaryExpr struct {
	op    tokenType
	left  node
	right node
}

type unaryExpr struct {
	op      tokenType
	operand node
}

type identifierExpr struct {
	name string
}

type literalExpr struct {
	value any
}

func (n *binaryExpr) Eval(ctx context.Context, lookup LookupFunc) (any, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	leftVal, err := n.left.Eval(ctx, lookup)
	if err != nil {
		return nil, err
	}

	switch n.op {
	case tokenAnd:
		leftBool, err := toBool(leftVal)
		if err != nil {
			return nil, err
		}
		if !leftBool {
			return false, nil
		}
		rightVal, err := n.right.Eval(ctx, lookup)
		if err != nil {
			return nil, err
		}
		rightBool, err := toBool(rightVal)
		if err != nil {
			return nil, err
		}
		return leftBool && rightBool, nil
	case tokenOr:
		leftBool, err := toBool(leftVal)
		if err != nil {
			return nil, err
		}
		if leftBool {
			return true, nil
		}
		rightVal, err := n.right.Eval(ctx, lookup)
		if err != nil {
			return nil, err
		}
		rightBool, err := toBool(rightVal)
		if err != nil {
			return nil, err
		}
		return rightBool, nil
	}

	rightVal, err := n.right.Eval(ctx, lookup)
	if err != nil {
		return nil, err
	}

	switch n.op {
	case tokenEq:
		return equals(leftVal, rightVal)
	case tokenNeq:
		eq, err := equals(leftVal, rightVal)
		if err != nil {
			return nil, err
		}
		return !eq, nil
	case tokenGt, tokenGte, tokenLt, tokenLte:
		return compare(leftVal, rightVal, n.op)
	default:
		return nil, fmt.Errorf("%w: unsupported binary operator", ErrSyntax)
	}
}

func (n *unaryExpr) Eval(ctx context.Context, lookup LookupFunc) (any, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	value, err := n.operand.Eval(ctx, lookup)
	if err != nil {
		return nil, err
	}
	switch n.op {
	case tokenNot:
		boolVal, err := toBool(value)
		if err != nil {
			return nil, err
		}
		return !boolVal, nil
	case tokenMinus:
		number, ok := toFloat(value)
		if !ok {
			return nil, fmt.Errorf("%w: unary - expects numeric operand", ErrTypeMismatch)
		}
		return -number, nil
	case tokenPlus:
		number, ok := toFloat(value)
		if !ok {
			return nil, fmt.Errorf("%w: unary + expects numeric operand", ErrTypeMismatch)
		}
		return number, nil
	default:
		return nil, fmt.Errorf("%w: unsupported unary operator", ErrSyntax)
	}
}

func (n *identifierExpr) Eval(ctx context.Context, lookup LookupFunc) (any, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if value, ok := lookup(n.name); ok {
		if err := checkContext(ctx); err != nil {
			return nil, err
		}
		return value, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrUnknownIdentifier, n.name)
}

func (n *literalExpr) Eval(ctx context.Context, _ LookupFunc) (any, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	return n.value, nil
}

// --- Helpers ---

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func toBool(value any) (bool, error) {
	switch v := value.(type) {
	case bool:
		return v, nil
	default:
		return false, fmt.Errorf("%w: expected boolean, got %T", ErrTypeMismatch, value)
	}
}

func toFloat(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int8:
		return float64(v), true
	case int16:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint8:
		return float64(v), true
	case uint16:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case string:
		if parsed, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			return parsed, true
		}
	default:
		// no-op
	}
	return 0, false
}

func equals(left, right any) (bool, error) {
	if left == nil || right == nil {
		return left == right, nil
	}

	if lf, ok := toFloat(left); ok {
		if rf, ok := toFloat(right); ok {
			return lf == rf, nil
		}
	}

	switch l := left.(type) {
	case string:
		if r, ok := right.(string); ok {
			return l == r, nil
		}
	case bool:
		if r, ok := right.(bool); ok {
			return l == r, nil
		}
	}

	return false, fmt.Errorf("%w: cannot compare %T and %T", ErrTypeMismatch, left, right)
}

func compare(left, right any, op tokenType) (bool, error) {
	if lf, ok := toFloat(left); ok {
		if rf, ok := toFloat(right); ok {
			switch op {
			case tokenGt:
				return lf > rf, nil
			case tokenGte:
				return lf >= rf, nil
			case tokenLt:
				return lf < rf, nil
			case tokenLte:
				return lf <= rf, nil
			}
		}
	}

	ls, leftIsString := left.(string)
	rs, rightIsString := right.(string)
	if leftIsString && rightIsString {
		switch op {
		case tokenGt:
			return ls > rs, nil
		case tokenGte:
			return ls >= rs, nil
		case tokenLt:
			return ls < rs, nil
		case tokenLte:
			return ls <= rs, nil
		}
	}

	return false, fmt.Errorf("%w: cannot apply comparator to %T and %T", ErrTypeMismatch, left, right)
}
