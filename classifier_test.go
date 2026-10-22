package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// ── test helpers ────────────────────────────────────────────────────────

const testModel = "test-model-1.0"

// testClassifier returns an enabled, validated classifier pointed at
// baseURL, with HOME moved to a temp dir so breaker state is isolated.
func testClassifier(t *testing.T, baseURL string) *Classifier {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	c := &Classifier{Enabled: true, BaseURL: baseURL, Model: testModel, TimeoutMs: 1000}
	c.prepare()
	if c.err != nil {
		t.Fatalf("prepare: %v", c.err)
	}
	return c
}

// stub starts an endpoint that answers every question with the given
// probabilities, counting calls.
func stub(t *testing.T, probs map[string]float64) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		writeAnswers(w, testModel, probs)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func writeAnswers(w http.ResponseWriter, model string, probs map[string]float64) {
	answers := map[string]systemOneAnswer{}
	for id, p := range probs {
		p := p
		answers[id] = systemOneAnswer{Type: "noul", Noul: &p}
	}
	b, _ := json.Marshal(systemOneResponse{Model: model, ID: "req-1", Answers: answers})
	w.Write(b)
}

// allSafe answers every pinned question with a confident "yes".
func allSafe() map[string]float64 {
	probs := map[string]float64{}
	for _, q := range questions {
		probs[q.ID] = 0.97
	}
	return probs
}

func askErrKind(t *testing.T, c *Classifier) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.TimeoutMs)*time.Millisecond)
	defer cancel()
	_, err := classify(ctx, c, Request{}, "make test")
	if err == nil {
		t.Fatal("expected an error")
	}
	return errKind(err)
}

// ── authentication is the endpoint's business ─────────────────────────

func TestClassifier_SendsNoCredentials(t *testing.T) {
	var auth string
	var cookies int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		cookies = len(r.Cookies())
		writeAnswers(w, testModel, allSafe())
	}))
	defer srv.Close()

	if _, err := classify(context.Background(), testClassifier(t, srv.URL), Request{}, "make test"); err != nil {
		t.Fatal(err)
	}
	if auth != "" || cookies != 0 {
		t.Errorf("barmkin must send no credentials, got Authorization=%q and %d cookies", auth, cookies)
	}
}

// ── wire format ─────────────────────────────────────────────────────────

func TestClassifier_RequestShape(t *testing.T) {
	var path string
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		body, _ = io.ReadAll(r.Body)
		writeAnswers(w, testModel, allSafe())
	}))
	defer srv.Close()

	c := testClassifier(t, srv.URL+"/api/")
	if _, err := classify(context.Background(), c, Request{Cwd: "/work"}, "make test"); err != nil {
		t.Fatal(err)
	}
	if path != "/api/v1/systemone" {
		t.Errorf("path = %q, want /api/v1/systemone", path)
	}
	var sent systemOneRequest
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if sent.Model != testModel || sent.State["command"] != "make test" || sent.State["cwd"] != "/work" {
		t.Errorf("unexpected request: %s", body)
	}
	if len(sent.Questions) != len(questions) {
		t.Fatalf("sent %d questions, want %d", len(sent.Questions), len(questions))
	}
	for _, q := range questions {
		if got := sent.Questions[q.ID]; got.Type != "noul" || got.Instructions != q.Instructions {
			t.Errorf("question %q sent as %+v", q.ID, got)
		}
	}
}

func TestWireQuestion_AlwaysMarshalsInstructions(t *testing.T) {
	b, _ := json.Marshal(wireQuestion{Type: "noul"})
	if !bytes.Contains(b, []byte(`"instructions"`)) {
		t.Errorf("instructions key dropped: %s", b)
	}
}

func TestClassifier_ValidResponse(t *testing.T) {
	srv, _ := stub(t, map[string]float64{"no_secret_egress": 0.91, "no_outward_effect": 0.07, "no_fetched_code_execution": 0.5})
	ans, err := classify(context.Background(), testClassifier(t, srv.URL), Request{}, "make test")
	if err != nil {
		t.Fatal(err)
	}
	if ans.probs["no_secret_egress"] != 0.91 || ans.probs["no_outward_effect"] != 0.07 || ans.model != testModel || ans.requestID != "req-1" {
		t.Errorf("got %+v", ans)
	}
}

func TestClassifier_HTTPErrors(t *testing.T) {
	for _, code := range []int{400, 401, 403, 429, 500, 503} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
			}))
			defer srv.Close()
			if got := askErrKind(t, testClassifier(t, srv.URL)); got != fmt.Sprintf("http_%d", code) {
				t.Errorf("got %s", got)
			}
		})
	}
}

func TestClassifier_MalformedResponses(t *testing.T) {
	ok := `{"type":"noul","noul":0.9}`
	three := func(a, b, c string) string {
		return `{"no_secret_egress":` + a + `,"no_outward_effect":` + b + `,"no_fetched_code_execution":` + c + `}`
	}
	cases := []struct {
		name string
		body string
	}{
		{"not json", `not json`},
		{"wrong model", `{"model":"other-model","answers":` + three(ok, ok, ok) + `}`},
		{"model prefix only", `{"model":"test-model-1.0-preview","answers":` + three(ok, ok, ok) + `}`},
		{"no answers", `{"model":"` + testModel + `","answers":{}}`},
		{"missing answer", `{"model":"` + testModel + `","answers":{"no_secret_egress":` + ok + `,"no_outward_effect":` + ok + `}}`},
		{"unexpected answer id", `{"model":"` + testModel + `","answers":{"no_secret_egress":` + ok + `,"no_outward_effect":` + ok + `,"other":` + ok + `}}`},
		{"wrong type", `{"model":"` + testModel + `","answers":` + three(`{"type":"choice"}`, ok, ok) + `}`},
		{"null noul", `{"model":"` + testModel + `","answers":` + three(`{"type":"noul"}`, ok, ok) + `}`},
		{"noul above 1", `{"model":"` + testModel + `","answers":` + three(`{"type":"noul","noul":1.5}`, ok, ok) + `}`},
		{"negative noul", `{"model":"` + testModel + `","answers":` + three(`{"type":"noul","noul":-0.1}`, ok, ok) + `}`},
		{"string noul", `{"model":"` + testModel + `","answers":` + three(`{"type":"noul","noul":"0.9"}`, ok, ok) + `}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			if got := askErrKind(t, testClassifier(t, srv.URL)); got != "malformed_response" {
				t.Errorf("got %s, want malformed_response", got)
			}
		})
	}
}

func TestClassifier_ResponseModelPattern(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeAnswers(w, "vendor/test-model-1.0-20260917", allSafe())
	}))
	defer srv.Close()

	c := testClassifier(t, srv.URL)
	if got := askErrKind(t, c); got != "malformed_response" {
		t.Fatalf("without response_model a remapped model name must be rejected, got %s", got)
	}
	c.responseModel = regexp.MustCompile(`test-model-1\.0\b`)
	if _, err := classify(context.Background(), c, Request{}, "make test"); err != nil {
		t.Errorf("response_model should accept the remapped name: %v", err)
	}
}

func TestClassifier_RefusesRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/elsewhere", http.StatusFound)
	}))
	defer srv.Close()
	if got := askErrKind(t, testClassifier(t, srv.URL)); got != "network" {
		t.Errorf("got %s, want network", got)
	}
}

func TestClassifier_Timeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	c := testClassifier(t, srv.URL)
	c.TimeoutMs = 50
	start := time.Now()
	if got := askErrKind(t, c); got != "timeout" {
		t.Errorf("got %s, want timeout", got)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("a 50ms timeout took %v", elapsed)
	}
}

func TestClassifier_ConnectionRefusedIsNetwork(t *testing.T) {
	if got := askErrKind(t, testClassifier(t, "http://127.0.0.1:1")); got != "network" {
		t.Errorf("got %s, want network", got)
	}
}

func TestClassifier_RefusesToSendPrivateKeyMarkers(t *testing.T) {
	srv, calls := stub(t, allSafe())
	c := testClassifier(t, srv.URL)
	c.Redact = new(bool) // even with redaction off

	if _, err := classify(context.Background(), c, Request{}, "grep 'PRIVATE KEY' notes.txt"); errKind(err) != "refused_send" {
		t.Errorf("got %v, want refused_send", err)
	}
	if *calls != 0 {
		t.Errorf("a refused send reached the endpoint %d times", *calls)
	}
}

// ── redaction ───────────────────────────────────────────────────────────

func TestRedact(t *testing.T) {
	for _, in := range []string{
		"curl -H 'Authorization: Bearer abc.def-123' https://api.example.com",
		"export OPENAI_API_KEY=sk-abc123xyz789secret",
		"GITHUB_TOKEN=abc123 make release",
		"git clone https://ghp_abcdefghijklmnopqrstuvwxyz012345@github.com/x/y",
		"aws configure set aws_access_key_id AKIAABCDEFGHIJKLMNOP",
		"echo eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl",
	} {
		if got := redact(in); !strings.Contains(got, "[REDACTED]") {
			t.Errorf("redact(%q) = %q, nothing masked", in, got)
		}
	}
	plain := "git commit -m 'fix bug'"
	if got := redact(plain); got != plain {
		t.Errorf("redact(%q) = %q, want unchanged", plain, got)
	}
}

func TestClassify_RedactsByDefault(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		writeAnswers(w, testModel, allSafe())
	}))
	defer srv.Close()

	c := testClassifier(t, srv.URL)
	if _, err := classify(context.Background(), c, Request{}, "export DEPLOY_TOKEN=plaintext-marker-xyz"); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("plaintext-marker-xyz")) {
		t.Errorf("default redaction should mask the secret; sent %s", body)
	}

	c.Redact = new(bool)
	if _, err := classify(context.Background(), c, Request{}, "export DEPLOY_TOKEN=plaintext-marker-xyz"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("plaintext-marker-xyz")) {
		t.Errorf("redact: false should send the command as-is; sent %s", body)
	}
}

// ── config ──────────────────────────────────────────────────────────────

func loadClassifierConfig(t *testing.T, yamlText string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(yamlText), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig must not fail on a classifier problem: %v", err)
	}
	return cfg
}

func TestClassifierConfig_Defaults(t *testing.T) {
	c := loadClassifierConfig(t, `
classifier:
  enabled: true
  base_url: "http://127.0.0.1:8080"
  model: "m-1"
`).Classifier
	if c.err != nil {
		t.Fatal(c.err)
	}
	if c.Mode != "shadow" || c.TimeoutMs != 1500 || !*c.Redact || len(c.Tools) != 1 || c.Tools[0] != "bash" ||
		len(c.PermissionModes) != 0 || c.Breaker.OpenAfterFailures != 1 || c.Breaker.CooldownS != 60 {
		t.Errorf("unexpected defaults: %+v", c)
	}
	if !c.active() {
		t.Error("a valid enabled block should be active")
	}
}

func TestClassifierConfig_AllKeys(t *testing.T) {
	c := loadClassifierConfig(t, `
classifier:
  enabled: true
  mode: shadow
  base_url: "http://127.0.0.1:8080/api"
  model: "m-1"
  response_model: 'm-1\b'
  timeout_ms: 800
  redact: false
  tools: [bash, write]
  permission_modes: [auto]
  skip_read_only: true
  skip_allow_rules: true
  thresholds:
    no_outward_effect: 0.2
  breaker:
    open_after_failures: 3
    cooldown_s: 30
`).Classifier
	if c.err != nil {
		t.Fatal(c.err)
	}
	if c.TimeoutMs != 800 || *c.Redact || len(c.Tools) != 2 || !c.SkipReadOnly ||
		!c.SkipAllowRules || c.Thresholds["no_outward_effect"] != 0.2 || c.Breaker.OpenAfterFailures != 3 || c.responseModel == nil {
		t.Errorf("keys not applied: %+v", c)
	}
}

func TestClassifierConfig_Rejects(t *testing.T) {
	base := "classifier:\n  enabled: true\n  base_url: \"https://classifier.example\"\n  model: \"m-1\"\n"
	cases := []struct {
		name, yaml, want string
	}{
		{"unknown key", base + "  timout_ms: 10\n", `line 5: unknown key "timout_ms"`},
		{"unknown nested key", base + "  breaker:\n    cooldwn_s: 5\n", `unknown key "breaker.cooldwn_s"`},
		{"no credential settings", base + "  credential:\n    file: /x\n", `unknown key "credential"`},
		{"wrong type", base + "  timeout_ms: soon\n", "cannot unmarshal"},
		{"enforce mode", base + "  mode: enforce\n", `mode "enforce" is not supported`},
		{"unix socket", strings.Replace(base, "https://classifier.example", "unix:///run/classifier.sock", 1), "must be an http:// or https:// URL"},
		{"file url", strings.Replace(base, "https://classifier.example", "file:///tmp/x", 1), "must be an http:// or https:// URL"},
		{"no host", strings.Replace(base, "https://classifier.example", "https://", 1), "must be an http:// or https:// URL"},
		{"no model", strings.Replace(base, "  model: \"m-1\"\n", "", 1), "model is required"},
		{"bad response_model", base + "  response_model: '('\n", "response_model"},
		{"unknown question", base + "  thresholds:\n    is_fine: 0.5\n", `unknown question "is_fine"`},
		{"threshold out of range", base + "  thresholds:\n    no_secret_egress: 1.5\n", "must be between 0 and 1"},
		{"negative timeout", base + "  timeout_ms: -1\n", "must not be negative"},
		{"negative breaker", base + "  breaker:\n    cooldown_s: -5\n", "must not be negative"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := loadClassifierConfig(t, tc.yaml).Classifier
			if c.err == nil || !strings.Contains(c.err.Error(), tc.want) {
				t.Errorf("got err %v, want it to mention %q", c.err, tc.want)
			}
			if c.active() {
				t.Error("an invalid block must not be active")
			}
		})
	}
}

func TestClassifierConfig_InvalidBlockKeepsRules(t *testing.T) {
	cfg := loadClassifierConfig(t, `
rules:
  - name: "npm-publish"
    pattern: 'npm\s+publish'
classifier:
  enabled: true
  mode: enforce
  bogus: true
`)
	result := newEngine(cfg).evaluate([]byte(`{"tool":"bash","action":"ShellCommand","args":{"command":"npm publish"}}`))
	if result.Decision != "deny" {
		t.Errorf("a broken classifier block must leave the rules working, got %+v", result)
	}
}

func TestClassifierConfig_KillSwitchIsOffOnly(t *testing.T) {
	enabled := "classifier:\n  enabled: true\n  base_url: \"https://classifier.example\"\n  model: \"m-1\"\n"
	disabled := strings.Replace(enabled, "enabled: true", "enabled: false", 1)

	t.Setenv("BARMKIN_CLASSIFIER", "off")
	if c := loadClassifierConfig(t, enabled).Classifier; c.active() || !c.forcedOff {
		t.Error("BARMKIN_CLASSIFIER=off must turn an enabled classifier off")
	}
	t.Setenv("BARMKIN_CLASSIFIER", "on")
	if c := loadClassifierConfig(t, disabled).Classifier; c.active() {
		t.Error("no environment value may turn the classifier on")
	}
	if c := loadClassifierConfig(t, enabled).Classifier; !c.active() {
		t.Error("only the literal value off disables it")
	}
}
