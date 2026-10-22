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
// base_url, model, timeout and the credential source are all
// configuration. Barmkin bundles no endpoint, proxy or credential.
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
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// maxResponseBytes caps the response body read, so a misbehaving
// endpoint can't exhaust memory.
const maxResponseBytes = 256 * 1024

// errRedirect refuses every redirect: the bearer token must never
// follow a 30x to an unexpected host.
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
	kind string // no_credential | timeout | network | http_<code> | malformed_response | refused_send
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
	token         string
	http          *http.Client
}

// newClassifierClient resolves the credential within ctx's deadline and
// builds a client. A missing or unusable credential is a
// "no_credential" error like any other unavailability.
func newClassifierClient(ctx context.Context, c *Classifier) (*classifierClient, error) {
	token, err := resolveCredential(ctx, c.Credential)
	if err != nil {
		return nil, err
	}
	return &classifierClient{
		url:           strings.TrimSuffix(c.BaseURL, "/") + "/v1/systemone",
		model:         c.Model,
		responseModel: c.responseModel,
		token:         token,
		http: &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect },
		},
	}, nil
}

// resolveCredential returns the bearer token, or "" when no credential
// is configured. A token file must be mode 0600: anything looser is
// refused rather than trusting a token other local users could read.
func resolveCredential(ctx context.Context, cr Credential) (string, error) {
	noCred := func(err error) error { return &classifierError{kind: "no_credential", err: err} }
	var token string
	switch {
	case cr.File != "":
		info, err := os.Stat(cr.File)
		if err != nil {
			return "", noCred(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			return "", noCred(fmt.Errorf("%s must be mode 0600, has %#o", cr.File, perm))
		}
		b, err := os.ReadFile(cr.File)
		if err != nil {
			return "", noCred(err)
		}
		token = string(b)
	case cr.Env != "":
		token = os.Getenv(cr.Env)
	case len(cr.Command) > 0:
		cmd := exec.CommandContext(ctx, cr.Command[0], cr.Command[1:]...)
		cmd.WaitDelay = 100 * time.Millisecond
		out, err := cmd.Output()
		if err != nil {
			return "", noCred(fmt.Errorf("credential command: %w", err))
		}
		token = string(out)
	default:
		return "", nil
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", noCred(errors.New("credential is empty"))
	}
	return token, nil
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
	// Last line of defence after redaction: never send the bearer
	// token itself or anything that looks like a private key.
	if (cl.token != "" && bytes.Contains(body, []byte(cl.token))) || bytes.Contains(body, []byte("PRIVATE KEY")) {
		return nil, &classifierError{kind: "refused_send", err: errors.New("request body contains a credential marker")}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cl.url, bytes.NewReader(body))
	if err != nil {
		return nil, &classifierError{kind: "network", err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	if cl.token != "" {
		req.Header.Set("Authorization", "Bearer "+cl.token)
	}

	resp, err := cl.http.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
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
// sent, never file contents.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`), // JWT
	regexp.MustCompile(`\b(sk|rk)-[A-Za-z0-9_-]{10,}\b`),                        // sk-/rk- style API keys
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`),                        // GitHub tokens
	regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`),                           // AWS access key ids
	regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+`),
	regexp.MustCompile(`(?i)\b[A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD)\s*=\s*\S+`),
}

// redact replaces every secret-pattern match with a fixed marker.
func redact(s string) string {
	for _, re := range secretPatterns {
		s = re.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}
