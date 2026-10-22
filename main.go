// Barmkin - lightweight regex guardrail for AI coding agents.
//
// Barmkin evaluates tool calls from Claude Code and opencode before they execute.
// It matches the command content against a set of regex rules and blocks
// (exit 2) or allows (exit 0) the call. No daemon, no LLM, no network -
// just regex, sub-millisecond per evaluation.
//
// The one opt-in exception is the classifier block in rules.yaml: in
// shadow mode it asks a System One endpoint you configure about calls
// the rules allowed, and logs what it would have decided. It never
// changes a decision (shadow.go).
//
// Usage:
//
//	barmkin eval        Read JSON from stdin, evaluate, exit 0 (allow) or 2 (deny)
//	barmkin test        Run built-in test vectors
//	barmkin validate    Check config: rule names, patterns, examples
//	barmkin stats       Aggregate decisions from the log file
//	barmkin version     Print version
//
// Config lookup order (first match wins):
//
//	$BARMKIN_CONFIG → /etc/barmkin/rules.yaml → ~/.barmkin/rules.yaml
//
// Hook protocol:
//
//	Claude Code pipes {"tool_name":"Bash","tool_input":{"command":"..."}}
//	to stdin of the configured hook command. Exit 0 allows the call;
//	exit 2 blocks it and stderr is shown to the LLM.
//
//	Opencode spawns barmkin eval as a subprocess from the TS plugin
//	(barmkin.ts) on every tool.execute.before event.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

const version = "1.0.0"

// verbose enables stderr debug output when -v is passed.
var verbose bool

func main() {
	configPath, cmd := parseArgs(os.Args[1:])
	if configPath == "" {
		configPath = defaultConfigPath()
	}

	switch cmd {
	case "eval":
		cmdEval(configPath)
	case "validate":
		cmdValidate(configPath)
	case "test":
		cmdTest(configPath)
	case "stats":
		cmdStats(configPath)
	case "version":
		fmt.Printf("barmkin v%s\n", version)
	default:
		usage()
		os.Exit(1)
	}
}

// parseArgs extracts the global -config and -v flags from anywhere
// in the argument list. The first remaining positional argument is
// the subcommand. If no positional is given, defaults to "eval".
func parseArgs(args []string) (configPath, cmd string) {
	var positional []string
	for i := 0; i < len(args); {
		switch args[i] {
		case "-config":
			if i+1 >= len(args) {
				fatalf("-config requires a path")
			}
			configPath = args[i+1]
			i += 2
		case "-v", "--verbose":
			verbose = true
			i++
		default:
			positional = append(positional, args[i])
			i++
		}
	}
	if len(positional) > 0 {
		cmd = positional[0]
	} else {
		cmd = "eval"
	}
	return
}

// cmdEval is the primary hook entry point. It reads a JSON request from
// stdin (from Claude Code or the opencode TS plugin), evaluates it against
// all rules, and exits:
//
//	exit 0 - command allowed (silent)
//	exit 2 - command denied (reason written to stderr for the LLM)
//
// On config errors barmkin fails open (exit 0) so a misconfigured guardrail
// never blocks productive work.
//
// stdin read has a 2-second deadline to prevent a stuck pipe from
// freezing the agent.
func cmdEval(configPath string) {
	data, err := readStdinWithTimeout(2 * time.Second)
	if err != nil || len(data) == 0 {
		return
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "[barmkin] config error: %v (failing open)\n", err)
		}
		return
	}
	if verbose && cfg.Classifier.err != nil {
		fmt.Fprintf(os.Stderr, "[barmkin] classifier config error: %v (classifier disabled)\n", cfg.Classifier.err)
	}

	engine := newEngine(cfg)
	defer engine.close()
	result := engine.evaluate(data)

	if result.Decision == "deny" {
		msg := result.Reason
		if msg == "" {
			msg = fmt.Sprintf("blocked by rule: %s", result.Rule)
		}
		fmt.Fprintf(os.Stderr, "[barmkin] %s\n", msg)
		os.Exit(2)
	}
}

// cmdValidate loads the config and reports:
//   - Each rule name with a checkmark or error
//   - Warnings for rules missing reason or example
//   - OTel and log status
//
// Exits 1 if any rule has an error (bad regex, missing name, duplicate).
func cmdValidate(configPath string) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		fatalf("config: %v", err)
	}

	fmt.Printf("config: %s\n", configPath)
	fmt.Printf("rules:  %d\n\n", len(cfg.Rules))

	seen := map[string]bool{}
	errs, warns := 0, 0

	for _, r := range cfg.Rules {
		switch {
		case r.Name == "":
			fmt.Printf("  ✗ <unnamed>: missing name\n")
			errs++
			continue
		case seen[r.Name]:
			fmt.Printf("  ✗ %s: duplicate rule name\n", r.Name)
			errs++
			continue
		case r.Pattern == "":
			fmt.Printf("  ✗ %s: empty pattern\n", r.Name)
			errs++
			seen[r.Name] = true
			continue
		case r.Reason == "":
			fmt.Printf("  ⚠ %s: no reason\n", r.Name)
			warns++
		case r.Example == "":
			fmt.Printf("  ⚠ %s: no example (not covered by test)\n", r.Name)
			warns++
		}
		seen[r.Name] = true
		fmt.Printf("  ✓ %s\n", r.Name)
	}

	fmt.Printf("\notel: %s\n", otelStatus(cfg.OTel))
	fmt.Printf("log:  %s\n", logStatus(cfg.Log))

	// Silent unless the classifier is enabled or broken, so a config
	// without one validates exactly as before.
	if c := cfg.Classifier; c.Enabled || c.forcedOff || c.err != nil {
		fmt.Printf("classifier: %s\n", classifierStatus(c))
		if c.err != nil {
			for _, line := range strings.Split(c.err.Error(), "\n") {
				fmt.Printf("  ✗ %s\n", line)
				errs++
			}
		}
		for _, w := range c.warnings() {
			fmt.Printf("  ⚠ %s\n", w)
			warns++
		}
	}

	if warns > 0 {
		fmt.Printf("\n%d warning(s)\n", warns)
	}
	if errs > 0 {
		fmt.Printf("%d error(s) - config invalid\n", errs)
		os.Exit(1)
	}
	fmt.Println("config valid")
}

// cmdTest runs two built-in test vectors through the engine:
//
//	BARMKIN-TEST-DENY   - must match the test-deny rule (expected deny)
//	BARMKIN-TEST-ALLOW  - must not match any rule (expected allow)
//
// Test vectors do not write to the audit log. Exits 1 if any vector
// produces an unexpected result.
func cmdTest(configPath string) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		fatalf("config: %v", err)
	}
	cfg.Log.Path = ""              // don't log test vectors
	cfg.Classifier.Enabled = false // the vectors test the rules; shadow mode can't change them

	vectors := []struct {
		label   string
		content string
		want    string
	}{
		{"deny", "BARMKIN-TEST-DENY", "deny"},
		{"allow", "BARMKIN-TEST-ALLOW", "allow"},
	}

	engine := newEngine(cfg)
	defer engine.close()

	passed := 0
	for _, v := range vectors {
		req := fmt.Sprintf(`{"tool":"bash","action":"test","args":{"command":%q}}`, v.content)
		resp := engine.evaluate([]byte(req))

		got := resp.Decision
		ok := got == v.want
		if ok {
			passed++
		}

		mark := "●"
		if !ok {
			mark = "✗"
		}

		detail := got
		if resp.Rule != "" {
			detail = fmt.Sprintf("%s (%s)", got, resp.Rule)
		}
		if !ok {
			detail += " - UNEXPECTED"
		}
		fmt.Printf("  %s  %-5s  %-20s  %s\n", mark, v.label, v.content, detail)
	}

	fmt.Printf("\n%d/%d passed", passed, len(vectors))
	if passed == len(vectors) {
		fmt.Println(" - barmkin is active")
	} else {
		fmt.Println(" - barmkin may be misconfigured")
		os.Exit(1)
	}
}

// cmdStats reads the JSON-lines log file and prints aggregated counts:
// total events, allows, denies, and per-rule hit counts.
func cmdStats(configPath string) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		fatalf("config: %v", err)
	}
	if cfg.Log.Path == "" {
		fmt.Println("logging disabled")
		return
	}

	f, err := os.Open(cfg.Log.Path)
	if err != nil {
		fmt.Println("no log file")
		return
	}
	defer f.Close()

	var events, allows, denies int
	hits := map[string]int{}
	var classified, unavailable int
	would := map[string]int{}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 65536), 65536)
	for scanner.Scan() {
		var entry AuditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		events++
		if entry.Decision == "deny" {
			denies++
			if entry.Rule != "" {
				hits[entry.Rule]++
			}
		} else {
			allows++
		}
		if c := entry.Classifier; c != nil {
			classified++
			if c.Error != "" {
				unavailable++
			} else {
				would[c.WouldDecision]++
			}
		}
	}

	fmt.Printf("events:  %d\n", events)
	fmt.Printf("allows:  %d\n", allows)
	fmt.Printf("denies:  %d\n", denies)
	if len(hits) > 0 {
		fmt.Println("hits:")
		rules := make([]string, 0, len(hits))
		for rule := range hits {
			rules = append(rules, rule)
		}
		sort.Strings(rules)
		for _, rule := range rules {
			fmt.Printf("  %-24s %d\n", rule, hits[rule])
		}
	}
	if classified > 0 {
		fmt.Println("classifier (shadow, never acted on):")
		fmt.Printf("  %-16s %d\n", "classified:", classified)
		fmt.Printf("  %-16s %d\n", "unavailable:", unavailable)
		for _, v := range []string{"allow", "escalate", "deny"} {
			fmt.Printf("  %-16s %d\n", "would "+v+":", would[v])
		}
	}
}

// usage prints the help text to stderr.
func usage() {
	fmt.Fprint(os.Stderr, `barmkin v`+version+` - regex guardrail for coding agents

Usage: barmkin [-config <path>] [-v] <command>

Commands:
  eval       Evaluate from stdin (exit 2 = deny, exit 0 = allow)
  validate   Validate config file
  test       Run test vectors (deny + allow)
  stats      Show statistics from log file
  version    Print version
`)
}

// fatalf prints an error to stderr and exits 1.
func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[barmkin] "+format+"\n", args...)
	os.Exit(1)
}

// readStdinWithTimeout reads all of stdin, blocking at most timeout.
// If the deadline expires, returns whatever was read so far (possibly
// empty) and an error. This prevents a misconfigured hook or stuck
// pipe from freezing the agent indefinitely.
func readStdinWithTimeout(timeout time.Duration) ([]byte, error) {
	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		data, err := io.ReadAll(os.Stdin)
		ch <- result{data, err}
	}()
	select {
	case r := <-ch:
		return r.data, r.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("stdin read timed out after %s", timeout)
	}
}
