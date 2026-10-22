// Audit log - appends each evaluation decision as a JSON line.
//
// Format is aligned with sondera's AuditEntry so logs from both
// guardrails can be aggregated and queried together.
//
// Each line:
//
//	{"ts":"2026-06-30T01:00:00Z","trajectory_id":"sess-123","tool":"bash",
//	 "action":"ShellCommand","decision":"deny","reason":"Recursive force-delete",
//	 "duration_ms":0.064,"rule":"rm-rf-force","content":"rm -rf /tmp",
//	 "agent":"claude-code"}
//
// When the opt-in classifier runs (shadow.go), the line also carries a
// "classifier" object with its would-be verdict.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// DecisionLogger appends AuditEntry records as JSON lines to a file.
// Nil when logging is disabled (empty path).
type DecisionLogger struct {
	mu   sync.Mutex
	file *os.File
}

// AuditEntry is the on-wire audit record. Field names match sondera's
// format, with barmkin-specific additions (rule, content, agent).
type AuditEntry struct {
	TS           string  `json:"ts"`                     // RFC3339 UTC timestamp (set by Write)
	TrajectoryID string  `json:"trajectory_id"`           // session ID
	Tool         string  `json:"tool"`                    // e.g. "bash", "read", "edit"
	Action       string  `json:"action"`                  // e.g. "ShellCommand", "FileRead"
	Decision     string  `json:"decision"`                // "allow" or "deny"
	Reason       string  `json:"reason,omitempty"`         // rule reason, shown to LLM
	DurationMs   float64 `json:"duration_ms"`             // evaluation time
	Rule    string `json:"rule,omitempty"`    // barmkin: matched rule name
	Content string `json:"content,omitempty"` // barmkin: truncated command content
	Agent   string `json:"agent,omitempty"`   // barmkin: agent identifier

	// barmkin: present only when the opt-in classifier ran, so lines
	// without it are unchanged
	Classifier *ClassifierAudit `json:"classifier,omitempty"`
}

// ClassifierAudit is what the shadow classifier said about one call.
// It never affects Decision: in shadow mode the outcome is the regex
// layer's alone, so this block is calibration data.
type ClassifierAudit struct {
	Mode             string             `json:"mode"`                        // "shadow"
	WouldDecision    string             `json:"would_decision,omitempty"`    // allow | escalate | deny; empty when there was no answer
	DecidingQuestion string             `json:"deciding_question,omitempty"` // the question that produced would_decision
	Probabilities    map[string]float64 `json:"probabilities,omitempty"`     // probability-of-yes per question
	Thresholds       map[string]float64 `json:"thresholds,omitempty"`        // reject-at threshold per question
	Error            string             `json:"error,omitempty"`             // timeout | network | http_<code> | malformed_response | refused_send | breaker_open
	Model            string             `json:"model,omitempty"`             // model the endpoint reported
	RequestID        string             `json:"request_id,omitempty"`
	LatencyMs        float64            `json:"latency_ms,omitempty"`
	Breaker          string             `json:"breaker,omitempty"` // closed | open | half_open
}

// newDecisionLogger opens (or creates) the log file for appending.
// Returns nil if path is empty - callers must check for nil or use
// the nil-safe Write method.
func newDecisionLogger(path string) *DecisionLogger {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[barmkin] log %s: %v (disabled)\n", path, err)
		return nil
	}
	return &DecisionLogger{file: f}
}

// Write appends one AuditEntry as a JSON line. No-op if logger is nil.
// Sets the timestamp automatically.
func (l *DecisionLogger) Write(entry AuditEntry) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	entry.TS = time.Now().UTC().Format(time.RFC3339)
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	l.file.Write(line)
	l.file.Write([]byte("\n"))
}

// Close closes the underlying file. No-op if logger is nil.
func (l *DecisionLogger) Close() {
	if l != nil && l.file != nil {
		l.file.Close()
	}
}
