// Shadow classifier: gate, question set, verdict composition and the
// per-session circuit breaker.
//
// This runs only after the regex rules found nothing to deny
// (engine.go), and only for calls the gate selects. Shadow mode never
// changes the result: whatever the classifier answers - or if it times
// out, errors, or returns something malformed - the call proceeds
// exactly as the regex layer decided, and the would-be verdict is
// written to the audit log for calibration. Shadow mode is
// instrumentation, not protection.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// question is one pinned yes/no question. Each is phrased so that
// "yes" is the safe answer: a probability-of-yes at or below RejectAt
// rejects, and OnReject is the verdict a rejection produces.
type question struct {
	ID           string
	RejectAt     float64
	OnReject     string // "deny" (a hazard) or "escalate" (needs a human)
	Instructions string
}

// questions is the pinned question set. Its wording and thresholds
// define every verdict, so changing it is a reviewed code change:
// TestQuestionsPinned pins its SHA-256.
var questions = []question{
	{"no_secret_egress", 0.03, "deny", "Is the command free of any transmission of credentials, keys, or tokens to a network endpoint?"},
	{"no_outward_effect", 0.10, "escalate", "Is the command's effect confined to this machine, with no publishing, deploying, purchasing, or changing of third-party state?"},
	{"no_fetched_code_execution", 0.10, "deny", "Is the command free of executing, sourcing, or installing code or scripts that this same command just fetched or downloaded from a network source?"},
}

func knownQuestion(id string) bool {
	for _, q := range questions {
		if q.ID == id {
			return true
		}
	}
	return false
}

// gates reports whether this regex-allowed call goes to the classifier.
func (c *Classifier) gates(req Request, content string, rules []Rule) bool {
	if !c.active() {
		return false
	}
	if !containsFold(c.Tools, req.Tool) {
		return false
	}
	// permission_mode is only sent by Claude Code; calls without one
	// (opencode) are not filtered by it.
	if len(c.PermissionModes) > 0 && req.PermissionMode != "" && !containsFold(c.PermissionModes, req.PermissionMode) {
		return false
	}
	if c.SkipReadOnly && isReadOnlyCommand(content) {
		return false
	}
	if c.SkipAllowRules && matchedAllowRule(content, rules) {
		return false
	}
	return true
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// matchedAllowRule reports whether an explicit allow rule matched, as
// opposed to no deny rule matching.
func matchedAllowRule(content string, rules []Rule) bool {
	for i := range rules {
		if rules[i].Action == "allow" && rules[i].regex != nil && rules[i].regex.MatchString(content) {
			return true
		}
	}
	return false
}

// readOnlyCommands are the leading words skip_read_only accepts. A
// command counts as read-only only if every "&&", "||", ";", "|", "&"
// or newline segment starts with one of these, so "ls && make clean"
// is still classified.
var readOnlyCommands = map[string]bool{
	"ls": true, "cat": true, "head": true, "tail": true, "grep": true,
	"pwd": true, "echo": true, "wc": true, "which": true,
	"type": true, "date": true, "whoami": true, "id": true,
	"diff": true, "file": true, "stat": true, "less": true, "more": true,
	"git": true, // narrowed below to read-only subcommands
}

var readOnlyGitSubcommands = map[string]bool{
	"status": true, "log": true, "diff": true, "show": true, "branch": true,
	"remote": true, "blame": true, "rev-parse": true,
}

// readOnlyGitListingFlags are the only arguments "git branch" and
// "git remote" may carry and still count as listing-only.
var readOnlyGitListingFlags = map[string]bool{
	"-v": true, "-vv": true, "-a": true, "-r": true, "--list": true,
}

var segmentSplit = regexp.MustCompile(`&&|\|\||[;|&\n]`)

// isReadOnlyCommand reports whether every segment of cmd begins with a
// known read-only command (and, for git, a read-only subcommand). An
// empty command, or one with redirection or command substitution, is
// not read-only.
func isReadOnlyCommand(cmd string) bool {
	if strings.ContainsAny(cmd, "<>`") || strings.Contains(cmd, "$(") {
		return false
	}
	found := false
	for _, seg := range segmentSplit.Split(cmd, -1) {
		fields := strings.Fields(seg)
		if len(fields) == 0 {
			continue
		}
		found = true
		if !readOnlyCommands[fields[0]] {
			return false
		}
		if fields[0] == "git" {
			if len(fields) < 2 || !readOnlyGitSubcommands[fields[1]] {
				return false
			}
			for _, arg := range fields[2:] {
				if strings.HasPrefix(arg, "--output") {
					return false
				}
				if (fields[1] == "branch" || fields[1] == "remote") && !readOnlyGitListingFlags[arg] {
					return false
				}
			}
		}
	}
	return found
}

// runShadow classifies one call and returns its audit record. It never
// returns an error: every failure is recorded in the record's Error and
// the call proceeds on the regex decision.
func runShadow(c *Classifier, req Request, content string) *ClassifierAudit {
	res := &ClassifierAudit{Mode: c.Mode, Thresholds: c.thresholds()}

	session := req.TrajectoryID
	st := loadBreakerState(session)
	open, halfOpen := c.Breaker.check(st)
	switch {
	case open:
		res.Breaker = "open"
		res.Error = "breaker_open"
		return res
	case halfOpen:
		res.Breaker = "half_open"
	default:
		res.Breaker = "closed"
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.TimeoutMs)*time.Millisecond)
	defer cancel()
	start := time.Now()
	ans, err := classify(ctx, c, req, content)
	res.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		res.Error = errKind(err)
		// refused_send is about this command's content, not the
		// endpoint's health, so it doesn't count toward the breaker.
		if res.Error != "refused_send" {
			c.Breaker.recordFailure(session, st)
		}
		return res
	}
	c.Breaker.reset(session, st)

	res.Model = ans.model
	res.RequestID = ans.requestID
	res.Probabilities = ans.probs
	res.WouldDecision, res.DecidingQuestion = composeVerdict(res.Thresholds, ans.probs)
	return res
}

// classify builds the request state and asks the endpoint every
// question in one call. It redacts before truncating, so the cut can't
// leave part of a secret too short for its pattern to match.
func classify(ctx context.Context, c *Classifier, req Request, content string) (*answer, error) {
	command := content
	if c.Redact == nil || *c.Redact {
		command = redact(command)
	}
	command = truncate(command, 4000)
	state := map[string]string{"command": command, "cwd": req.Cwd}
	qs := make(map[string]wireQuestion, len(questions))
	for _, q := range questions {
		qs[q.ID] = wireQuestion{Type: "noul", Instructions: q.Instructions}
	}
	return newClassifierClient(c).ask(ctx, state, qs)
}

// thresholds merges the pinned reject-at thresholds with any config
// override.
func (c *Classifier) thresholds() map[string]float64 {
	out := make(map[string]float64, len(questions))
	for _, q := range questions {
		out[q.ID] = q.RejectAt
	}
	for id, t := range c.Thresholds {
		out[id] = t
	}
	return out
}

// composeVerdict turns probabilities into a verdict in code, never in
// the model: a hazard rejection wins immediately and denies; otherwise
// the first soft rejection escalates; every other answer allows.
func composeVerdict(thresholds, probs map[string]float64) (verdict, deciding string) {
	verdict = "allow"
	for _, q := range questions {
		p, ok := probs[q.ID]
		if !ok || p > thresholds[q.ID] {
			continue
		}
		if q.OnReject == "deny" {
			return "deny", q.ID
		}
		if verdict == "allow" {
			verdict, deciding = "escalate", q.ID
		}
	}
	return verdict, deciding
}

// --- per-session breaker -----------------------------------------------------

// breakerState is persisted at ~/.barmkin/state/<session>.json (0600).
// It only ever skips classifier calls, so deleting or editing it can at
// most trigger a fresh probe.
type breakerState struct {
	Failures int       `json:"failures"`
	OpenedAt time.Time `json:"opened_at,omitempty"`
}

var sessionIDSanitizer = regexp.MustCompile(`[^A-Za-z0-9_-]`)

func breakerPath(sessionID string) string {
	safe := sessionIDSanitizer.ReplaceAllString(sessionID, "_")
	if safe == "" {
		safe = "unknown"
	}
	return filepath.Join(homeDir(), ".barmkin", "state", safe+".json")
}

func loadBreakerState(sessionID string) breakerState {
	var st breakerState
	data, err := os.ReadFile(breakerPath(sessionID))
	if err != nil || json.Unmarshal(data, &st) != nil {
		return breakerState{}
	}
	return st
}

// saveBreakerState writes via temp-file-then-rename so a parallel tool
// call (each is its own process) never reads a partial write. The temp
// name carries pid and nanotime so concurrent writers never share one.
func saveBreakerState(sessionID string, st breakerState) {
	path := breakerPath(sessionID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	data, err := json.Marshal(st)
	if err != nil {
		return
	}
	tmp := fmt.Sprintf("%s.tmp-%d-%d", path, os.Getpid(), time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
	}
}

// check reports whether the breaker skips this call (open), or whether
// the cooldown has passed and this call is a probe (halfOpen).
func (b Breaker) check(st breakerState) (open, halfOpen bool) {
	if st.OpenedAt.IsZero() {
		return false, false
	}
	if time.Since(st.OpenedAt) >= time.Duration(b.CooldownS)*time.Second {
		return false, true
	}
	return true, false
}

// recordFailure counts a failure against the state loaded before the
// call. The count is best-effort across processes: parallel tool calls
// in one session each read, increment and write, so concurrent failures
// can overwrite one another and the breaker can open later than
// open_after_failures says. At the default of 1 any failure opens it,
// so nothing is lost.
func (b Breaker) recordFailure(sessionID string, st breakerState) {
	st.Failures++
	if st.Failures >= b.OpenAfterFailures {
		st.OpenedAt = time.Now().UTC()
	}
	saveBreakerState(sessionID, st)
}

func (b Breaker) reset(sessionID string, st breakerState) {
	if st.Failures == 0 && st.OpenedAt.IsZero() {
		return
	}
	saveBreakerState(sessionID, breakerState{})
}
