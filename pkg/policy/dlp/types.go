package dlp

import (
	"bytes"
	"errors"
	"regexp"

	"github.com/polisai/polis-oss/pkg/storage"
)

// Action describes the directive associated with a DLP rule.
type Action string

const (
	// ActionAllow indicates the finding should not alter enforcement.
	ActionAllow Action = "allow"
	// ActionRedact indicates the finding should be masked before forwarding.
	ActionRedact Action = "redact"
	// ActionBlock indicates the finding should cause the request/response to be rejected.
	ActionBlock Action = "block"
	// ActionTokenize indicates the finding should be replaced with a secure token.
	ActionTokenize Action = "tokenize"
)

// Rule declares a DLP detection rule.
type Rule struct {
	Name        string
	Pattern     string
	Action      Action
	Replacement string
}

// Config bundles all rule definitions for a Scanner.
type Config struct {
	Rules        []Rule
	ChunkSize    int
	Overlap      int
	MaxReadBytes int64
	MaxFindings  int
	Mode         string
	Scope        string
	Posture      string
	Vault        storage.TokenVault
}

// Finding captures a single DLP match.
type Finding struct {
	Rule   string
	Match  string
	Start  int
	End    int
	Action Action
}

// Report summarises the outcome of a scan operation.
type Report struct {
	Findings          []Finding
	Redacted          string
	RedactionsApplied bool
	Blocked           bool
}

// Scanner applies DLP rules to textual content.
type Scanner struct {
	rules []compiledRule
	vault storage.TokenVault
}

// StreamRedactor incrementally scans and redacts byte streams.
type StreamRedactor struct {
	scanner           *Scanner
	chunkSize         int
	overlap           int
	maxRead           int64
	maxFindings       int
	totalRead         int64
	bufferRaw         []byte
	findings          []Finding
	blocked           bool
	redactionsApplied bool
	deferEmission     bool
	pending           bytes.Buffer
}

const (
	defaultChunkSize   = 16 * 1024
	defaultOverlap     = 256
	defaultMaxFindings = 128
)

var (
	// ErrBlocked indicates that a block rule matched during streaming inspection.
	ErrBlocked             = errors.New("dlp: content blocked by policy")
	errMaxReadExceeded     = errors.New("dlp: maximum inspected bytes exceeded")
	errMaxFindingsExceeded = errors.New("dlp: maximum findings exceeded")
	errVaultMissing        = errors.New("dlp: tokenization requested but no vault configured")
)

// compiledRule is an internal representation of a Rule with a compiled regex.
type compiledRule struct {
	name        string
	expr        *regexp.Regexp
	action      Action
	replacement string
}

// isValidAction checks if the given action is a known DLP action.
func isValidAction(action Action) bool {
	switch action {
	case ActionAllow, ActionRedact, ActionBlock, ActionTokenize:
		return true
	default:
		return false
	}
}
