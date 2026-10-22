// Config types and YAML loading for barmkin.
//
// The config file (rules.yaml) defines:
//   - rules:   list of regex rules with name, pattern, action, reason, example
//   - otel:    optional OpenTelemetry OTLP endpoint
//   - log:     optional JSON-lines audit log path
//   - classifier: optional System One classifier, shadow mode only (off unless enabled)
//
// Config lookup order (first existing file wins):
//   1. $BARMKIN_CONFIG
//   2. /etc/barmkin/rules.yaml  (system-wide, authoritative)
//   3. ~/.barmkin/rules.yaml    (user fallback)

package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level YAML structure.
type Config struct {
	Rules      []Rule     `yaml:"rules"`
	OTel       OTel       `yaml:"otel"`
	Log        Log        `yaml:"log"`
	Classifier Classifier `yaml:"classifier"` // optional; absent or disabled == regex only
}

// Rule defines a single guardrail pattern.
type Rule struct {
	Name    string `yaml:"name"`    // human-readable identifier (must be unique)
	Pattern string `yaml:"pattern"` // Go regex (re2) matched against command content
	Action  string `yaml:"action"`  // "deny" (default) or "allow" (overrides all denies)
	Reason  string `yaml:"reason"`  // shown to the LLM when denied
	Example string `yaml:"example"` // test string - verified by `go test` and `barmkin validate`
	regex   *regexp.Regexp
}

// OTel configures the optional OTLP trace exporter.
type OTel struct {
	Endpoint string `yaml:"endpoint"` // OTLP endpoint, e.g. "localhost:4317"
	Service  string `yaml:"service"`  // service name (default "barmkin")
}

// Log configures the optional JSON-lines audit log.
type Log struct {
	Path string `yaml:"path"` // expanded with ~ → $HOME
}

// Classifier configures the optional System One classifier (shadow.go,
// classifier.go). It only sees calls the regex rules already allowed,
// and in shadow mode - the only mode - it records what the classifier
// would have decided without ever changing the decision.
type Classifier struct {
	Enabled bool   `yaml:"enabled"` // master switch; absent block == false
	Mode    string `yaml:"mode"`    // "shadow" (default, and the only supported mode)

	BaseURL       string     `yaml:"base_url"`       // http(s) URL; requests go to POST {base_url}/v1/systemone
	Model         string     `yaml:"model"`          // model id sent with every request
	ResponseModel string     `yaml:"response_model"` // optional regex the response's model must match (default: exactly model)
	TimeoutMs     int        `yaml:"timeout_ms"`     // one deadline for credential lookup plus the request (default 1500)
	Credential    Credential `yaml:"credential"`     // bearer token source; empty == no Authorization header
	Redact        *bool      `yaml:"redact"`         // mask secrets in the command before sending (default true)

	Tools           []string `yaml:"tools"`            // normalized tool names to classify (default ["bash"])
	PermissionModes []string `yaml:"permission_modes"` // Claude Code permission_mode values to classify (default: all)
	SkipReadOnly    bool     `yaml:"skip_read_only"`   // skip commands made only of known read-only segments
	SkipAllowRules  bool     `yaml:"skip_allow_rules"` // skip commands an explicit allow rule matched

	Thresholds map[string]float64 `yaml:"thresholds"` // per-question reject-at override, keyed by question id
	Breaker    Breaker            `yaml:"breaker"`

	forcedOff     bool           // enabled in config, turned off by BARMKIN_CLASSIFIER=off
	err           error          // decode or validation error; disables the classifier only
	responseModel *regexp.Regexp // compiled ResponseModel
}

// Credential is where the bearer token comes from. Set at most one.
type Credential struct {
	File    string   `yaml:"file"`    // file holding the token; must be mode 0600
	Env     string   `yaml:"env"`     // environment variable holding the token (also visible to the agent's own shell)
	Command []string `yaml:"command"` // argv whose trimmed stdout is the token, e.g. a secrets-manager CLI
}

// Breaker is the per-session circuit breaker that stops paying the
// request timeout on every call while the endpoint is unavailable.
type Breaker struct {
	OpenAfterFailures int `yaml:"open_after_failures"` // consecutive failures that open it (default 1)
	CooldownS         int `yaml:"cooldown_s"`          // seconds before the next probe (default 60)
}

// UnmarshalYAML decodes the classifier block strictly: an unknown or
// mistyped key is a classifier error rather than a silently ignored
// setting. It never fails the whole config, so a broken classifier
// block can't take the regex rules down with it.
func (c *Classifier) UnmarshalYAML(n *yaml.Node) error {
	type plain Classifier
	errs := unknownKeys(n, reflect.TypeOf(plain{}), "")
	if err := n.Decode((*plain)(c)); err != nil {
		var te *yaml.TypeError
		if errors.As(err, &te) {
			for _, msg := range te.Errors {
				errs = append(errs, errors.New(msg))
			}
		} else {
			errs = append(errs, err)
		}
	}
	c.err = errors.Join(errs...)
	return nil
}

// unknownKeys reports each key of mapping node n that isn't a yaml
// field of struct type t, recursing into struct-typed fields.
func unknownKeys(n *yaml.Node, t reflect.Type, prefix string) []error {
	if n.Kind != yaml.MappingNode {
		return nil
	}
	var errs []error
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i], n.Content[i+1]
		found := false
		for j := 0; j < t.NumField(); j++ {
			f := t.Field(j)
			if f.IsExported() && strings.Split(f.Tag.Get("yaml"), ",")[0] == key.Value {
				found = true
				if f.Type.Kind() == reflect.Struct {
					errs = append(errs, unknownKeys(val, f.Type, prefix+key.Value+".")...)
				}
				break
			}
		}
		if !found {
			errs = append(errs, fmt.Errorf("line %d: unknown key %q", key.Line, prefix+key.Value))
		}
	}
	return errs
}

// active reports whether the classifier should run at all.
func (c *Classifier) active() bool {
	return c.Enabled && c.err == nil
}

// prepare applies defaults to an enabled classifier block and validates
// it, adding any problem to c.err. BARMKIN_CLASSIFIER=off turns the
// classifier off; no environment value can turn it on.
func (c *Classifier) prepare() {
	if c.Enabled && os.Getenv("BARMKIN_CLASSIFIER") == "off" {
		c.Enabled, c.forcedOff = false, true
	}
	if !c.Enabled {
		return
	}
	if c.Mode == "" {
		c.Mode = "shadow"
	}
	if c.TimeoutMs == 0 {
		c.TimeoutMs = 1500
	}
	if c.Redact == nil {
		on := true
		c.Redact = &on
	}
	if len(c.Tools) == 0 {
		c.Tools = []string{"bash"}
	}
	if c.Breaker.OpenAfterFailures == 0 {
		c.Breaker.OpenAfterFailures = 1
	}
	if c.Breaker.CooldownS == 0 {
		c.Breaker.CooldownS = 60
	}
	c.Credential.File = expandPath(c.Credential.File)

	errs := []error{c.err}
	if c.Mode != "shadow" {
		errs = append(errs, fmt.Errorf("mode %q is not supported (only \"shadow\")", c.Mode))
	}
	if u, err := url.Parse(c.BaseURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		errs = append(errs, fmt.Errorf("base_url %q must be an http:// or https:// URL", c.BaseURL))
	}
	if c.Model == "" {
		errs = append(errs, errors.New("model is required"))
	}
	if c.ResponseModel != "" {
		re, err := regexp.Compile(c.ResponseModel)
		if err != nil {
			errs = append(errs, fmt.Errorf("response_model: %w", err))
		}
		c.responseModel = re
	}
	if c.TimeoutMs < 0 {
		errs = append(errs, fmt.Errorf("timeout_ms %d must not be negative", c.TimeoutMs))
	}
	set := 0
	for _, s := range []bool{c.Credential.File != "", c.Credential.Env != "", len(c.Credential.Command) > 0} {
		if s {
			set++
		}
	}
	if set > 1 {
		errs = append(errs, errors.New("credential: set at most one of file, env, command"))
	}
	ids := make([]string, 0, len(c.Thresholds))
	for id := range c.Thresholds {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if t := c.Thresholds[id]; !knownQuestion(id) {
			errs = append(errs, fmt.Errorf("thresholds: unknown question %q", id))
		} else if t < 0 || t > 1 {
			errs = append(errs, fmt.Errorf("thresholds: %s=%v must be between 0 and 1", id, t))
		}
	}
	if c.Breaker.OpenAfterFailures < 0 || c.Breaker.CooldownS < 0 {
		errs = append(errs, errors.New("breaker: values must not be negative"))
	}
	c.err = errors.Join(errs...)
}

// classifierStatus returns a human-readable classifier status for `barmkin validate`.
func classifierStatus(c Classifier) string {
	switch {
	case c.err != nil:
		return "invalid (disabled)"
	case c.forcedOff:
		return "disabled by BARMKIN_CLASSIFIER=off"
	case !c.Enabled:
		return "disabled"
	}
	baseURL := c.BaseURL
	if u, err := url.Parse(c.BaseURL); err == nil {
		baseURL = u.Redacted()
	}
	return fmt.Sprintf("%s (%s, model=%s, timeout=%dms, credential=%s, redact=%t)",
		c.Mode, baseURL, c.Model, c.TimeoutMs, c.Credential.source(), *c.Redact)
}

// source names where the token comes from, never the token itself.
func (cr Credential) source() string {
	switch {
	case cr.File != "":
		return "file " + cr.File
	case cr.Env != "":
		return "env " + cr.Env
	case len(cr.Command) > 0:
		return "command " + cr.Command[0]
	}
	return "none"
}

// warnings lists what `barmkin validate` should flag in an enabled,
// valid block. It never reads or prints the token.
func (c Classifier) warnings() []string {
	if !c.Enabled || c.err != nil {
		return nil
	}
	var warns []string
	if u, _ := url.Parse(c.BaseURL); u.Scheme == "http" && !isLoopback(u.Hostname()) {
		warns = append(warns, "base_url is plain http to a non-local host: the command and token travel unencrypted")
	}
	switch cr := c.Credential; {
	case cr.File != "":
		if info, err := os.Stat(cr.File); err != nil {
			warns = append(warns, "credential: "+err.Error())
		} else if perm := info.Mode().Perm(); perm != 0o600 {
			warns = append(warns, fmt.Sprintf("credential: %s has mode %#o, want 0600", cr.File, perm))
		}
	case cr.Env != "":
		if os.Getenv(cr.Env) == "" {
			warns = append(warns, "credential: "+cr.Env+" is unset")
		}
	}
	return warns
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// compile validates the regex pattern and defaults Action to "deny".
func (r *Rule) compile() error {
	re, err := regexp.Compile(r.Pattern)
	if err != nil {
		return err
	}
	r.regex = re
	if r.Action == "" {
		r.Action = "deny"
	}
	return nil
}

// loadConfig reads and parses the YAML config file, compiles all rule
// regexes, and expands ~ in the log path.
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	cfg.Log.Path = expandPath(cfg.Log.Path)
	for i := range cfg.Rules {
		if err := cfg.Rules[i].compile(); err != nil {
			return nil, fmt.Errorf("rule %q: %w", cfg.Rules[i].Name, err)
		}
	}
	cfg.Classifier.prepare()
	return &cfg, nil
}

// otelStatus returns a human-readable OTel status string for `barmkin validate`.
func otelStatus(o OTel) string {
	if o.Endpoint == "" {
		return "disabled"
	}
	if o.Service == "" {
		return fmt.Sprintf("%s (service=barmkin)", o.Endpoint)
	}
	return fmt.Sprintf("%s (service=%s)", o.Endpoint, o.Service)
}

// logStatus returns a human-readable log status string for `barmkin validate`.
func logStatus(l Log) string {
	if l.Path == "" {
		return "disabled"
	}
	return l.Path
}

// defaultConfigPath resolves the config file location using the lookup order.
func defaultConfigPath() string {
	for _, p := range []string{
		os.Getenv("BARMKIN_CONFIG"),
		"/etc/barmkin/rules.yaml",
		filepath.Join(homeDir(), ".barmkin", "rules.yaml"),
	} {
		if p != "" && fileExists(p) {
			return p
		}
	}
	return filepath.Join(homeDir(), ".barmkin", "rules.yaml")
}

// expandPath replaces a leading ~ with the user's home directory.
func expandPath(p string) string {
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(homeDir(), p[2:])
	}
	if p == "~" {
		return homeDir()
	}
	return p
}

func homeDir() string {
	h, _ := os.UserHomeDir()
	return h
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
