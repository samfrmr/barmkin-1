// Request/response types and matching logic.
//
// Barmkin accepts two input formats:
//
//  1. AdapterRequest - sent by the opencode TS plugin (barmkin.ts).
//     Normalized with trajectory_id, agent_id, tool, action, args.
//
//  2. Claude Code - sent by Claude Code's PreToolUse hook.
//     Uses tool_name, tool_input, and session_id.
//
// normalize() maps Claude Code fields into AdapterRequest fields so
// the audit log is consistent regardless of input source.

package main

import (
	"encoding/json"
	"strings"
)

// Request is the unified input structure. Fields from both formats
// are populated by JSON unmarshaling; normalize() reconciles them.
type Request struct {
	// AdapterRequest fields (from opencode TS plugin)
	TrajectoryID string         `json:"trajectory_id"`
	AgentID      string         `json:"agent_id"`
	Tool         string         `json:"tool"`
	Action       string         `json:"action"`
	Args         map[string]any `json:"args"`
	Cwd          string         `json:"cwd,omitempty"`
	EventType    string         `json:"event_type,omitempty"`

	// Claude Code fields (from PreToolUse hook)
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
	Command   string          `json:"command"`
	SessionID string          `json:"session_id"`

	// Claude Code permission mode (e.g. "auto"); only the classifier gate reads it
	PermissionMode string `json:"permission_mode"`
}

// HookOutput is the evaluation result returned by the engine.
type HookOutput struct {
	Decision string `json:"decision"`         // "allow" or "deny"
	Reason   string `json:"reason,omitempty"`  // human-readable, shown to LLM on deny
	Rule     string `json:"rule,omitempty"`    // rule name that matched
}

// toolActions maps Claude Code tool names to semantic action names
// used in the audit log (consistent with sondera's AdapterRequest format).
var toolActions = map[string]string{
	"bash": "ShellCommand", "write": "FileWrite", "edit": "FileEdit",
	"multiedit": "FileEdit", "notebookedit": "FileEdit",
	"read": "FileRead", "glob": "FileSearch", "grep": "ContentSearch",
}

// normalize maps Claude Code fields into AdapterRequest fields so the
// audit log has consistent tool/action/trajectory_id regardless of source.
func (r *Request) normalize() {
	if r.Tool == "" && r.ToolName != "" {
		r.Tool = strings.ToLower(r.ToolName)
	}
	if r.Action == "" && r.Tool != "" {
		r.Action = toolActions[r.Tool]
	}
	if r.TrajectoryID == "" && r.SessionID != "" {
		r.TrajectoryID = r.SessionID
	}
	if r.AgentID == "" {
		// Infer agent from wire format: Claude Code uses tool_name/session_id;
		// opencode uses trajectory_id/args. Default to opencode when neither
		// Claude Code field is present.
		if r.ToolName != "" || r.SessionID != "" {
			r.AgentID = "claude-code"
		} else {
			r.AgentID = "opencode"
		}
	}
}

// extractContent pulls the scannable text from the request.
// Tries AdapterRequest args first (normalized), then falls back to
// Claude Code's raw tool_input format.
func (r *Request) extractContent() string {
	// AdapterRequest: check args for known field names
	if s := firstNonEmpty(r.Args, "command", "path", "url", "content", "query", "pattern", "patch_text"); s != "" {
		return s
	}
	// Claude Code: top-level command field
	if r.Command != "" {
		return r.Command
	}
	// Claude Code: tool_input JSON object
	if s := firstString(r.ToolInput, "command", "path", "filePath", "url", "content"); s != "" {
		return s
	}
	// Fallback: serialize remaining args
	if len(r.Args) > 0 {
		b, _ := json.Marshal(r.Args)
		return string(b)
	}
	return strings.TrimSpace(string(r.ToolInput))
}

// firstNonEmpty returns the first non-empty string value for any of
// the given keys in the map.
func firstNonEmpty(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// firstString unmarshals a JSON RawMessage into a map and returns the
// first non-empty string value for any of the given keys.
func firstString(raw json.RawMessage, keys ...string) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	return firstNonEmpty(m, keys...)
}

// match checks rules in order. An allow rule that matches overrides
// all deny rules and returns nil (allow). Otherwise the first deny
// match wins and that rule is returned.
//
// This allows narrow allow rules to exempt specific patterns from
// broad deny rules, e.g.:
//
//	- name: "allow-tmp-rm"
//	  pattern: 'rm\s+-rf\s+/tmp/'
//	  action: "allow"
//
//	- name: "rm-rf-force"
//	  pattern: 'rm\s+-rf\b'
//	  action: "deny"
func match(content string, rules []Rule) *Rule {
	var firstDeny *Rule
	for i := range rules {
		if rules[i].regex == nil || !rules[i].regex.MatchString(content) {
			continue
		}
		if rules[i].Action == "allow" {
			return nil
		}
		if firstDeny == nil {
			firstDeny = &rules[i]
		}
	}
	return firstDeny
}

// truncate shortens a string to n characters, appending "..." if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
