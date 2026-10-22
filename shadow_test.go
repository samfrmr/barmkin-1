package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// everydayCommands are commands no rule in rules.yaml denies, used
// alongside the rule examples (which all deny).
var everydayCommands = []string{
	"ls -la", "git status", "git log --oneline", "make build", "go test ./...",
	"npm install", "docker ps", "cat README.md", "kubectl get pods",
	"echo hello && make test",
}

// ── opt-in: an unconfigured classifier changes nothing ──────────────────

var (
	tsField       = regexp.MustCompile(`"ts":"[^"]*"`)
	durationField = regexp.MustCompile(`"duration_ms":[0-9.e+-]+`)
)

// normalizeLog blanks the fields that vary run to run.
func normalizeLog(b []byte) string {
	s := tsField.ReplaceAllString(string(b), `"ts":"TS"`)
	return durationField.ReplaceAllString(s, `"duration_ms":0`)
}

// TestOptIn_UnconfiguredIsByteIdentical replays every rules.yaml example
// and a set of everyday commands, in both wire formats, through the
// shipped rules.yaml as-is and with a classifier block that is disabled,
// invalid, or switched off by BARMKIN_CLASSIFIER=off. Every variant
// must return byte-identical results, write byte-identical log lines,
// and never contact the endpoint.
func TestOptIn_UnconfiguredIsByteIdentical(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv, calls := stub(t, allSafe())

	rules, err := os.ReadFile(rulesYAMLPath(t))
	if err != nil {
		t.Fatal(err)
	}
	load := func(extra string) *Config {
		t.Helper()
		path := filepath.Join(t.TempDir(), "rules.yaml")
		if err := os.WriteFile(path, append(append([]byte{}, rules...), extra...), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg, err := loadConfig(path)
		if err != nil {
			t.Fatalf("loadConfig: %v", err)
		}
		return cfg
	}
	enabled := fmt.Sprintf("\nclassifier:\n  enabled: true\n  base_url: %q\n  model: %q\n", srv.URL, testModel)
	variants := map[string]*Config{
		"no block":       load(""),
		"disabled block": load(strings.Replace(enabled, "enabled: true", "enabled: false", 1)),
		"invalid block":  load(enabled + "  mode: enforce\n"),
	}
	t.Setenv("BARMKIN_CLASSIFIER", "off")
	variants["BARMKIN_CLASSIFIER=off"] = load(enabled)

	var inputs []string
	commands := append([]string{}, everydayCommands...)
	for _, r := range variants["no block"].Rules {
		if r.Example != "" {
			commands = append(commands, r.Example)
		}
	}
	for _, cmd := range commands {
		oc, _ := json.Marshal(map[string]any{"trajectory_id": "s1", "tool": "bash", "action": "ShellCommand", "args": map[string]any{"command": cmd}})
		cc, _ := json.Marshal(map[string]any{"session_id": "s2", "tool_name": "Bash", "tool_input": map[string]any{"command": cmd}, "cwd": "/work", "permission_mode": "auto"})
		inputs = append(inputs, string(oc), string(cc))
	}
	inputs = append(inputs, "not json")

	run := func(cfg *Config) (results, log string) {
		cfg.Log.Path = filepath.Join(t.TempDir(), "barmkin.log")
		e := newEngine(cfg)
		var out strings.Builder
		for _, in := range inputs {
			b, _ := json.Marshal(e.evaluate([]byte(in)))
			out.Write(b)
			out.WriteByte('\n')
		}
		e.close()
		data, err := os.ReadFile(cfg.Log.Path)
		if err != nil {
			t.Fatal(err)
		}
		return out.String(), normalizeLog(data)
	}

	wantResults, wantLog := run(variants["no block"])
	for name, cfg := range variants {
		gotResults, gotLog := run(cfg)
		if gotResults != wantResults {
			t.Errorf("%s: results differ from no block", name)
		}
		if gotLog != wantLog {
			t.Errorf("%s: log differs from no block", name)
		}
	}
	if *calls != 0 {
		t.Errorf("an unconfigured classifier contacted the endpoint %d times", *calls)
	}
}

// TestOptIn_LogLineShape pins the exact regex-only log line, so no new
// field can appear in it while the classifier is off.
func TestOptIn_LogLineShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "barmkin.log")
	e := newEngine(&Config{Rules: mustRules(t, [2]string{"npm-publish", `npm\s+publish`}), Log: Log{Path: path}})
	e.evaluate([]byte(`{"trajectory_id":"s1","tool":"bash","action":"ShellCommand","args":{"command":"make build"}}`))
	e.evaluate([]byte(`{"tool_name":"Bash","tool_input":{"command":"npm publish"},"session_id":"s2","permission_mode":"auto"}`))
	e.close()

	data, _ := os.ReadFile(path)
	want := `{"ts":"TS","trajectory_id":"s1","tool":"bash","action":"ShellCommand","decision":"allow","duration_ms":0,"content":"make build","agent":"opencode"}` + "\n" +
		`{"ts":"TS","trajectory_id":"s2","tool":"bash","action":"ShellCommand","decision":"deny","reason":"test","duration_ms":0,"rule":"npm-publish","content":"npm publish","agent":"claude-code"}` + "\n"
	if got := normalizeLog(data); got != want {
		t.Errorf("log lines changed:\ngot:  %s\nwant: %s", got, want)
	}
}

// ── shadow mode never changes a decision ────────────────────────────────

func shadowEngine(t *testing.T, srv *httptest.Server, rules ...[2]string) (*Engine, string) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "barmkin.log")
	cfg := &Config{Rules: mustRules(t, rules...), Log: Log{Path: logPath}, Classifier: *testClassifier(t, srv.URL)}
	return newEngine(cfg), logPath
}

func lastEntry(t *testing.T, logPath string) AuditEntry {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var entry AuditEntry
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &entry); err != nil {
		t.Fatal(err)
	}
	return entry
}

func TestShadow_RegexDenyNeverReachesClassifier(t *testing.T) {
	srv, calls := stub(t, allSafe())
	e, logPath := shadowEngine(t, srv, [2]string{"npm-publish", `npm\s+publish`})
	result := e.evaluate([]byte(`{"tool":"bash","action":"ShellCommand","args":{"command":"npm publish"}}`))
	e.close()

	if result.Decision != "deny" || result.Rule != "npm-publish" {
		t.Errorf("got %+v, want the regex deny", result)
	}
	if *calls != 0 {
		t.Errorf("a regex deny reached the classifier %d times", *calls)
	}
	if entry := lastEntry(t, logPath); entry.Classifier != nil {
		t.Errorf("a regex deny logged a classifier block: %+v", entry.Classifier)
	}
}

func TestShadow_DenyVerdictIsLoggedButAllowed(t *testing.T) {
	srv, calls := stub(t, map[string]float64{"no_secret_egress": 0.01, "no_outward_effect": 0.97, "no_fetched_code_execution": 0.97})
	e, logPath := shadowEngine(t, srv)
	result := e.evaluate([]byte(`{"tool_name":"Bash","tool_input":{"command":"make upload"},"session_id":"s1","permission_mode":"auto"}`))
	e.close()

	if result != (HookOutput{Decision: "allow"}) {
		t.Errorf("shadow mode changed the result: %+v", result)
	}
	if *calls != 1 {
		t.Fatalf("got %d classifier calls, want 1", *calls)
	}
	entry := lastEntry(t, logPath)
	if entry.Decision != "allow" || entry.Classifier == nil {
		t.Fatalf("got %+v", entry)
	}
	c := entry.Classifier
	if c.Mode != "shadow" || c.WouldDecision != "deny" || c.DecidingQuestion != "no_secret_egress" || c.Model != testModel || c.RequestID != "req-1" || c.Breaker != "closed" {
		t.Errorf("classifier block = %+v", c)
	}
	if c.Probabilities["no_secret_egress"] != 0.01 || c.Thresholds["no_secret_egress"] != 0.03 {
		t.Errorf("probabilities/thresholds not logged: %+v", c)
	}
}

func TestShadow_EveryFailureFailsOpen(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"http_500": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) },
		"malformed_response": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"model":"` + testModel + `","answers":{}}`))
		},
	}
	for want, h := range cases {
		t.Run(want, func(t *testing.T) {
			srv := httptest.NewServer(h)
			defer srv.Close()
			e, logPath := shadowEngine(t, srv)
			result := e.evaluate([]byte(`{"tool":"bash","action":"ShellCommand","args":{"command":"make upload"}}`))
			e.close()
			if result != (HookOutput{Decision: "allow"}) {
				t.Errorf("a classifier failure changed the result: %+v", result)
			}
			c := lastEntry(t, logPath).Classifier
			if c == nil || c.Error != want || c.WouldDecision != "" {
				t.Errorf("classifier block = %+v, want error %s and no verdict", c, want)
			}
		})
	}
}

// TestShadow_EvalExitCodes checks the CLI contract end to end: a regex
// deny still exits 2 and a classifier "deny" verdict still exits 0.
func TestShadow_EvalExitCodes(t *testing.T) {
	srv, _ := stub(t, map[string]float64{"no_secret_egress": 0.01, "no_outward_effect": 0.01, "no_fetched_code_execution": 0.01})
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "rules.yaml")
	cfg := fmt.Sprintf("rules:\n  - name: npm-publish\n    pattern: 'npm\\s+publish'\nclassifier:\n  enabled: true\n  base_url: %q\n  model: %q\n", srv.URL, testModel)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	for cmd, want := range map[string]int{"npm publish": 2, "make upload": 0} {
		in := fmt.Sprintf(`{"tool":"bash","action":"ShellCommand","args":{"command":%q}}`, cmd)
		if _, _, code := runBinary(t, dir, in, "-config", cfgPath, "eval"); code != want {
			t.Errorf("%q: exit %d, want %d", cmd, code, want)
		}
	}
}

// ── gating ──────────────────────────────────────────────────────────────

func TestGates(t *testing.T) {
	rules := mustRules(t, [2]string{"npm-publish", `npm\s+publish`})
	rules = append(rules, Rule{Name: "allow-dry-run", Pattern: `--dry-run`, Action: "allow"})
	if err := rules[1].compile(); err != nil {
		t.Fatal(err)
	}
	c := Classifier{Enabled: true, Tools: []string{"bash"}, PermissionModes: []string{"auto", "bypassPermissions"}, SkipReadOnly: true, SkipAllowRules: true}

	cases := []struct {
		name    string
		req     Request
		content string
		want    bool
	}{
		{"gated", Request{Tool: "bash", PermissionMode: "auto"}, "make deploy", true},
		{"tool not listed", Request{Tool: "write", PermissionMode: "auto"}, "notes.txt", false},
		{"tool matched case-insensitively", Request{Tool: "Bash"}, "make deploy", true},
		{"permission mode not listed", Request{Tool: "bash", PermissionMode: "default"}, "make deploy", false},
		{"no permission mode (opencode)", Request{Tool: "bash"}, "make deploy", true},
		{"read-only skipped", Request{Tool: "bash", PermissionMode: "auto"}, "ls -la | grep x", false},
		{"read-only then not", Request{Tool: "bash", PermissionMode: "auto"}, "ls && make deploy", true},
		{"allow rule skipped", Request{Tool: "bash", PermissionMode: "auto"}, "make deploy --dry-run", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.gates(tc.req, tc.content, rules); got != tc.want {
				t.Errorf("gates() = %v, want %v", got, tc.want)
			}
		})
	}

	off := c
	off.Enabled = false
	invalid := c
	invalid.err = fmt.Errorf("broken")
	for name, c := range map[string]Classifier{"disabled": off, "invalid": invalid} {
		if c.gates(Request{Tool: "bash"}, "make deploy", rules) {
			t.Errorf("%s classifier gated a call", name)
		}
	}
}

func TestIsReadOnlyCommand(t *testing.T) {
	cases := map[string]bool{
		"ls -la":                     true,
		"cat README.md":              true,
		"ls | grep foo":              true,
		"echo hi; ls":                true,
		"git status":                 true,
		"git log --oneline":          true,
		"git branch":                 true,
		"git branch -a":              true,
		"git remote -v":              true,
		"":                           false,
		"make clean":                 false,
		"ls && make clean":           false,
		"ls\nmake clean":             false,
		"ls & make clean":            false,
		"env make":                   false,
		"echo $(whoami)":             false,
		"cat `which go`":             false,
		"echo x > out.txt":           false,
		"cat <(date)":                false,
		"find . -delete":             false,
		"git push origin main":       false,
		"git branch -D main":         false,
		"git remote add x https://x": false,
		"git diff --output=/tmp/x":   false,
	}
	for cmd, want := range cases {
		if got := isReadOnlyCommand(cmd); got != want {
			t.Errorf("isReadOnlyCommand(%q) = %v, want %v", cmd, got, want)
		}
	}
}

// ── verdicts ────────────────────────────────────────────────────────────

func TestComposeVerdict(t *testing.T) {
	defaults := (&Classifier{}).thresholds()
	p := func(secret, outward, fetched float64) map[string]float64 {
		return map[string]float64{"no_secret_egress": secret, "no_outward_effect": outward, "no_fetched_code_execution": fetched}
	}
	cases := []struct {
		name         string
		probs        map[string]float64
		want, decide string
	}{
		{"all safe", p(0.95, 0.95, 0.95), "allow", ""},
		{"middle band allows", p(0.5, 0.5, 0.5), "allow", ""},
		{"hazard denies", p(0.01, 0.95, 0.95), "deny", "no_secret_egress"},
		{"exactly at threshold rejects", p(0.03, 0.95, 0.95), "deny", "no_secret_egress"},
		{"just above threshold allows", p(0.95, 0.95, 0.11), "allow", ""},
		{"fetched code denies", p(0.95, 0.95, 0.10), "deny", "no_fetched_code_execution"},
		{"soft rejection escalates", p(0.95, 0.05, 0.95), "escalate", "no_outward_effect"},
		{"hazard beats soft", p(0.95, 0.01, 0.02), "deny", "no_fetched_code_execution"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, deciding := composeVerdict(defaults, tc.probs)
			if got != tc.want || deciding != tc.decide {
				t.Errorf("got %s/%q, want %s/%q", got, deciding, tc.want, tc.decide)
			}
		})
	}
}

func TestComposeVerdict_ThresholdOverride(t *testing.T) {
	c := &Classifier{Thresholds: map[string]float64{"no_outward_effect": 0.5}}
	got, deciding := composeVerdict(c.thresholds(), map[string]float64{"no_secret_egress": 0.95, "no_outward_effect": 0.4, "no_fetched_code_execution": 0.95})
	if got != "escalate" || deciding != "no_outward_effect" {
		t.Errorf("got %s/%q, want escalate/no_outward_effect", got, deciding)
	}
}

// TestQuestionsPinned fails whenever the question set changes. Every
// logged verdict depends on this exact wording and these thresholds, so
// a change must be deliberate: update the hash in the same reviewed
// commit.
func TestQuestionsPinned(t *testing.T) {
	h := sha256.New()
	for _, q := range questions {
		fmt.Fprintf(h, "%s|%v|%s|%s\n", q.ID, q.RejectAt, q.OnReject, q.Instructions)
	}
	const want = "4c3521c8d0fc608c5157ddebdb81a76c66d8a276ff3fe4c2ba682d4f3b044003"
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		t.Errorf("question set changed: sha256 %s, pinned %s", got, want)
	}
	for _, q := range questions {
		if strings.TrimSpace(q.Instructions) == "" || (q.OnReject != "deny" && q.OnReject != "escalate") || q.RejectAt <= 0 || q.RejectAt >= 1 {
			t.Errorf("question %q is not well-formed: %+v", q.ID, q)
		}
	}
}

// ── breaker ─────────────────────────────────────────────────────────────

func TestBreaker_OpensAfterFailureAndSkipsCalls(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := testClassifier(t, srv.URL)
	c.Breaker.CooldownS = 3600
	req := Request{Tool: "bash", TrajectoryID: "sess-open"}

	first := runShadow(c, req, "make test")
	if first.Error != "http_503" || first.Breaker != "closed" {
		t.Errorf("first call: %+v", first)
	}
	second := runShadow(c, req, "make test")
	if second.Error != "breaker_open" || second.Breaker != "open" {
		t.Errorf("second call: %+v", second)
	}
	if calls != 1 {
		t.Errorf("an open breaker must skip the request, got %d calls", calls)
	}
	if other := runShadow(c, Request{Tool: "bash", TrajectoryID: "sess-other"}, "make test"); other.Breaker != "closed" {
		t.Errorf("the breaker is per session, another session got %q", other.Breaker)
	}
}

func TestBreaker_ProbesAfterCooldownAndResetsOnSuccess(t *testing.T) {
	srv, calls := stub(t, allSafe())
	c := testClassifier(t, srv.URL)
	c.Breaker.CooldownS = 60
	req := Request{Tool: "bash", TrajectoryID: "sess-probe"}

	opened := time.Now().UTC().Add(-30 * time.Second)
	saveBreakerState(req.TrajectoryID, breakerState{Failures: 1, OpenedAt: opened})
	if res := runShadow(c, req, "make test"); res.Breaker != "open" || *calls != 0 {
		t.Fatalf("within cooldown: breaker=%s calls=%d", res.Breaker, *calls)
	}
	if st := loadBreakerState(req.TrajectoryID); !st.OpenedAt.Equal(opened) {
		t.Errorf("a skipped call moved opened_at from %v to %v", opened, st.OpenedAt)
	}

	saveBreakerState(req.TrajectoryID, breakerState{Failures: 1, OpenedAt: opened.Add(-time.Minute)})
	res := runShadow(c, req, "make test")
	if res.Breaker != "half_open" || res.WouldDecision != "allow" || *calls != 1 {
		t.Errorf("after cooldown: %+v calls=%d, want one successful probe", res, *calls)
	}
	if st := loadBreakerState(req.TrajectoryID); st.Failures != 0 || !st.OpenedAt.IsZero() {
		t.Errorf("success should reset the breaker, got %+v", st)
	}
}

func TestBreaker_RefusedSendDoesNotOpenIt(t *testing.T) {
	srv, calls := stub(t, allSafe())
	c := testClassifier(t, srv.URL)
	req := Request{Tool: "bash", TrajectoryID: "sess-refused"}

	if res := runShadow(c, req, "grep 'PRIVATE KEY' notes.txt"); res.Error != "refused_send" {
		t.Fatalf("got %+v, want refused_send", res)
	}
	if res := runShadow(c, req, "make test"); res.Breaker != "closed" || res.Error != "" || *calls != 1 {
		t.Errorf("next call: %+v calls=%d, want a normal classification", res, *calls)
	}
}

func TestBreaker_ConcurrentWritesNeverCorrupt(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			saveBreakerState("sess-concurrent", breakerState{Failures: n})
		}(i)
	}
	wg.Wait()
	data, err := os.ReadFile(breakerPath("sess-concurrent"))
	if err != nil || json.Unmarshal(data, &breakerState{}) != nil {
		t.Errorf("state file unreadable after concurrent writes: %v %q", err, data)
	}
	if leftovers, _ := filepath.Glob(breakerPath("sess-concurrent") + ".tmp-*"); len(leftovers) != 0 {
		t.Errorf("leaked temp files: %v", leftovers)
	}
}

func TestBreakerPath_SanitizesSessionID(t *testing.T) {
	t.Setenv("HOME", "/home/u")
	if got := breakerPath("../../etc/x"); got != "/home/u/.barmkin/state/______etc_x.json" {
		t.Errorf("got %s", got)
	}
	if got := breakerPath(""); got != "/home/u/.barmkin/state/unknown.json" {
		t.Errorf("got %s", got)
	}
}

func TestRunShadow_TimeoutCoversCredentialAndRequest(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	c := testClassifier(t, srv.URL)
	c.TimeoutMs = 500
	c.Credential = Credential{Command: []string{"sh", "-c", "sleep 0.3; printf zz-test-token-93f1"}}
	start := time.Now()
	res := runShadow(c, Request{Tool: "bash", TrajectoryID: "sess-deadline"}, "make test")
	if res.Error != "timeout" {
		t.Errorf("got %+v, want timeout", res)
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Errorf("took %v, want about one timeout_ms", elapsed)
	}
}

// ── validate and stats ──────────────────────────────────────────────────

func TestValidate_ReportsClassifier(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("rules: []\n"+body), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	valid := write("valid.yaml", "classifier:\n  enabled: true\n  base_url: \"http://classifier.example\"\n  model: \"m-1\"\n  credential:\n    env: BARMKIN_TEST_UNSET_TOKEN\n")
	invalid := write("invalid.yaml", "classifier:\n  enabled: true\n  mode: enforce\n")

	stdout, _, code := runBinary(t, dir, "", "-config", valid, "validate")
	for _, want := range []string{
		"classifier: shadow (http://classifier.example, model=m-1, timeout=1500ms, credential=env BARMKIN_TEST_UNSET_TOKEN, redact=true)",
		"⚠ base_url is plain http to a non-local host",
		"⚠ credential: BARMKIN_TEST_UNSET_TOKEN is unset",
		"config valid",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("valid config: output lacks %q:\n%s", want, stdout)
		}
	}
	if code != 0 {
		t.Errorf("valid config: exit %d", code)
	}

	stdout, _, code = runBinary(t, dir, "", "-config", invalid, "validate")
	if code != 1 || !strings.Contains(stdout, "classifier: invalid (disabled)") || !strings.Contains(stdout, `✗ mode "enforce" is not supported`) {
		t.Errorf("invalid config: exit %d, output:\n%s", code, stdout)
	}
}

func TestStats_SummarizesShadowVerdicts(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "barmkin.log")
	lines := []string{
		`{"decision":"deny","rule":"npm-publish"}`,
		`{"decision":"allow"}`,
		`{"decision":"allow","classifier":{"mode":"shadow","would_decision":"allow"}}`,
		`{"decision":"allow","classifier":{"mode":"shadow","would_decision":"deny"}}`,
		`{"decision":"allow","classifier":{"mode":"shadow","would_decision":"deny"}}`,
		`{"decision":"allow","classifier":{"mode":"shadow","error":"timeout"}}`,
	}
	if err := os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(cfgPath, []byte(fmt.Sprintf("log:\n  path: %q\n", logPath)), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, _, _ := runBinary(t, dir, "", "-config", cfgPath, "stats")
	want := "classifier (shadow, never acted on):\n" +
		"  classified:      4\n" +
		"  unavailable:     1\n" +
		"  would allow:     1\n" +
		"  would escalate:  0\n" +
		"  would deny:      2\n"
	if !strings.HasSuffix(stdout, want) || !strings.Contains(stdout, "allows:  5\n") {
		t.Errorf("stats output:\n%s\nwant it to end with:\n%s", stdout, want)
	}
}
