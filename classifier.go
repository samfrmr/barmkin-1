// System One classifier client.
//
// A System One endpoint answers typed questions about a piece of state
// instead of generating text: barmkin sends the command (and cwd) plus
// a fixed set of yes/no questions, and the endpoint returns one
// probability-of-yes per question. Jev is one such model; any endpoint
// that serves the same wire format works:
//
//	POST {base_url}/v1/systemone
//	{"model":"...","state":{"command":"...","cwd":"..."},
//	 "questions":{"<id>":{"type":"noul","instructions":"..."}}}
//
//	200 {"model":"...","id":"...","answers":{"<id>":{"type":"noul","noul":0.97}}}
//
// base_url, model and timeout are all configuration. Barmkin bundles
// no endpoint, proxy or credential, and never sends one: authentication
// is entirely the endpoint's business, typically a localhost proxy the
// deployer runs that adds whatever its upstream needs.
//
// This file only fetches and strictly validates the answers; turning
// them into a verdict happens in code (shadow.go), never in the model.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// maxResponseBytes caps the response body read, so a misbehaving
// endpoint can't exhaust memory.
const maxResponseBytes = 256 * 1024

// errRedirect refuses every redirect: the command must never follow a
// 30x to an unexpected host.
var errRedirect = errors.New("classifier: redirects are disabled")

// wireQuestion is one question on the wire. The endpoint requires both
// keys on every question, so neither is omitempty.
type wireQuestion struct {
	Type         string `json:"type"`
	Instructions string `json:"instructions"`
}

type systemOneRequest struct {
	Model     string                  `json:"model"`
	State     map[string]string       `json:"state"`
	Questions map[string]wireQuestion `json:"questions"`
}

type systemOneAnswer struct {
	Type string   `json:"type"`
	Noul *float64 `json:"noul,omitempty"`
}

type systemOneResponse struct {
	Model   string                     `json:"model"`
	ID      string                     `json:"id"`
	Answers map[string]systemOneAnswer `json:"answers"`
}

// classifierError says why there is no answer. Every kind is logged
// and the call proceeds on the regex decision alone.
type classifierError struct {
	kind string // timeout | network | redirect | http_<code> | malformed_response | refused_send
	err  error
}

func (e *classifierError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("classifier: %s: %v", e.kind, e.err)
	}
	return "classifier: " + e.kind
}

func errKind(err error) string {
	var ce *classifierError
	if errors.As(err, &ce) {
		return ce.kind
	}
	return "unknown"
}

// classifierClient is a System One HTTP client for one evaluation.
type classifierClient struct {
	url           string
	model         string
	responseModel *regexp.Regexp // nil: the response must echo model exactly
	http          *http.Client
}

func newClassifierClient(c *Classifier) *classifierClient {
	return &classifierClient{
		url:           strings.TrimSuffix(c.BaseURL, "/") + "/v1/systemone",
		model:         c.Model,
		responseModel: c.responseModel,
		http: &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect },
		},
	}
}

// answer is a validated response.
type answer struct {
	probs     map[string]float64
	model     string
	requestID string
}

// ask sends one request carrying every question against the same state
// and strictly validates the response: a 200 is not yet an answer. A
// wrong model, a missing or extra answer, a non-noul answer, or a
// probability outside [0,1] is malformed_response, never a partial
// result.
func (cl *classifierClient) ask(ctx context.Context, state map[string]string, questions map[string]wireQuestion) (*answer, error) {
	body, err := json.Marshal(systemOneRequest{Model: cl.model, State: state, Questions: questions})
	if err != nil {
		return nil, &classifierError{kind: "network", err: err}
	}
	// Last line of defence after redaction: never send anything that
	// looks like a private key.
	if bytes.Contains(body, []byte("PRIVATE KEY")) {
		return nil, &classifierError{kind: "refused_send", err: errors.New("request body contains a private-key marker")}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cl.url, bytes.NewReader(body))
	if err != nil {
		return nil, &classifierError{kind: "network", err: err}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := cl.http.Do(req)
	if err != nil {
		switch {
		case errors.Is(err, errRedirect):
			return nil, &classifierError{kind: "redirect", err: err}
		case errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err):
			return nil, &classifierError{kind: "timeout", err: err}
		}
		return nil, &classifierError{kind: "network", err: err}
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, &classifierError{kind: "network", err: err}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &classifierError{kind: fmt.Sprintf("http_%d", resp.StatusCode)}
	}

	malformed := func(format string, args ...any) error {
		return &classifierError{kind: "malformed_response", err: fmt.Errorf(format, args...)}
	}
	var sr systemOneResponse
	if err := json.Unmarshal(data, &sr); err != nil {
		return nil, malformed("%v", err)
	}
	if cl.responseModel != nil && !cl.responseModel.MatchString(sr.Model) || cl.responseModel == nil && sr.Model != cl.model {
		return nil, malformed("unexpected model %q", sr.Model)
	}
	if len(sr.Answers) != len(questions) {
		return nil, malformed("got %d answers, want %d", len(sr.Answers), len(questions))
	}
	probs := make(map[string]float64, len(questions))
	for id := range questions {
		a, ok := sr.Answers[id]
		if !ok {
			return nil, malformed("missing answer %q", id)
		}
		if a.Type != "noul" || a.Noul == nil {
			return nil, malformed("answer %q is not a noul", id)
		}
		p := *a.Noul
		if math.IsNaN(p) || math.IsInf(p, 0) || p < 0 || p > 1 {
			return nil, malformed("answer %q: noul %v out of range", id, p)
		}
		probs[id] = p
	}
	return &answer{probs: probs, model: sr.Model, requestID: sr.ID}, nil
}

// secretPatterns are masked in the command before it leaves the
// machine (unless redact: false). Only the command and cwd are ever
// sent, never file contents. A pattern's "keep" and "rest" groups stay
// in place around the marker, so the classifier still sees that a
// secret was there and where it was going.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`), // JWT
	regexp.MustCompile(`\b(sk|rk)-[A-Za-z0-9_-]{10,}\b`),                        // sk-/rk- style API keys
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`),                        // GitHub tokens
	regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`),                           // AWS access key ids
	regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+`),
	// Authorization headers, whatever the scheme.
	regexp.MustCompile(`(?i)(?P<keep>\bAuthorization["']?\s*:\s*["']?)[^'"\n]+`),
	// NAME=value and NAME: value, including JSON and YAML.
	regexp.MustCompile(`(?i)(?P<keep>\b[A-Z0-9_-]*(KEY|TOKEN|SECRET|PASSWORD|PASSWD)["']?\s*[:=]\s*["']?)[^\s'"]+`),
	// NAME value, only for snake_case, kebab-case and flag names
	// (aws_secret_access_key, _authToken, --password), so prose such as
	// "rotate the api key" is left alone.
	regexp.MustCompile(`(?i)(?P<keep>(--?|\b[A-Z0-9]*[_-])[A-Z0-9_-]*?(KEY|TOKEN|SECRET|PASSWORD|PASSWD)\s+)[^\s'"-][^\s'"]*`),
	// curl-style -u user:pass and --user user:pass.
	regexp.MustCompile(`(?P<keep>(^|\s)(-u\s+|--(proxy-)?user(\s+|=))["']?)[^\s'":]*:[^\s'"]+`),
	// user:pass@ in a URL.
	regexp.MustCompile(`(?i)(?P<keep>\b[a-z][a-z0-9+.-]*://)[^/\s'"@:]+:[^/\s'"@]+(?P<rest>@)`),
	// Unprefixed tokens: exactly 32 hex digits, or a UUID. Git SHAs (40)
	// and container ids (64) are longer runs and don't match.
	regexp.MustCompile(`(?i)\b[0-9a-f]{32}\b`),
	regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`),
}

// redact replaces every secret-pattern match with a fixed marker.
func redact(s string) string {
	for _, re := range secretPatterns {
		s = re.ReplaceAllString(s, "${keep}[REDACTED]${rest}")
	}
	return s
}
