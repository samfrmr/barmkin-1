package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestGolden_UnconfiguredBinary pins what a user sees from the barmkin
// binary when no classifier is configured: validate, test, eval (exit
// codes and stderr), stats and the log file, byte for byte.
//
// testdata/unconfigured.golden was captured from barmkin as it was
// before the classifier existed, by running this test against that
// build:
//
//	BARMKIN_GOLDEN_BIN=/path/to/old/barmkin go test -run TestGolden -update
//
// The same transcript must come out of the current binary both with no
// classifier block and with a disabled one.
var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// TestMain lets tests run the test binary as barmkin itself.
func TestMain(m *testing.M) {
	if os.Getenv("BARMKIN_TEST_AS_BINARY") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// runBinary runs barmkin (this test binary, or $BARMKIN_GOLDEN_BIN)
// with HOME set to home and returns stdout, stderr and the exit code.
func runBinary(t *testing.T, home, stdin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	bin := os.Getenv("BARMKIN_GOLDEN_BIN")
	if bin == "" {
		bin = os.Args[0]
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "BARMKIN_TEST_AS_BINARY=1", "HOME="+home, "BARMKIN_CONFIG=")
	cmd.Stdin = strings.NewReader(stdin)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("run %v: %v", args, err)
		}
		code = exit.ExitCode()
	}
	return so.String(), se.String(), code
}

var goldenEvalInputs = []string{
	`{"trajectory_id":"s1","tool":"bash","action":"ShellCommand","args":{"command":"npm publish"}}`,
	`{"trajectory_id":"s1","tool":"bash","action":"ShellCommand","args":{"command":"npm publish --dry-run"}}`,
	`{"trajectory_id":"s1","tool":"bash","action":"ShellCommand","args":{"command":"dropdb prod"}}`,
	`{"tool_name":"Bash","tool_input":{"command":"make build"},"session_id":"s2","cwd":"/work","permission_mode":"auto"}`,
	`{"tool_name":"Bash","tool_input":{"command":"npm publish"},"session_id":"s2","permission_mode":"bypassPermissions"}`,
	`not json`,
	``,
}

// goldenTranscript runs the fixture config plus extra through every
// user-facing command and returns a normalized transcript.
func goldenTranscript(t *testing.T, extra string) string {
	t.Helper()
	fixture, err := os.ReadFile(filepath.Join("testdata", "unconfigured.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "rules.yaml")
	logPath := filepath.Join(dir, "barmkin.log")
	cfg := strings.ReplaceAll(string(fixture), "{{LOG}}", logPath) + extra
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	var out strings.Builder
	run := func(stdin string, args ...string) {
		stdout, stderr, code := runBinary(t, dir, stdin, append([]string{"-config", cfgPath}, args...)...)
		fmt.Fprintf(&out, "$ barmkin %s\n", strings.Join(args, " "))
		if stdin != "" {
			fmt.Fprintf(&out, "< %s\n", stdin)
		}
		out.WriteString(stdout)
		for _, line := range strings.SplitAfter(stderr, "\n") {
			if line != "" {
				out.WriteString("! " + line)
			}
		}
		fmt.Fprintf(&out, "exit %d\n\n", code)
	}
	run("", "validate")
	run("", "test")
	for _, in := range goldenEvalInputs {
		run(in, "eval")
	}
	run("", "stats")

	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	out.WriteString("$ cat barmkin.log\n" + normalizeLog(log))
	return strings.ReplaceAll(out.String(), dir, "$DIR")
}

func TestGolden_UnconfiguredBinary(t *testing.T) {
	goldenPath := filepath.Join("testdata", "unconfigured.golden")
	variants := map[string]string{
		"no classifier block": "",
		"disabled classifier": "\nclassifier:\n  enabled: false\n  base_url: \"http://127.0.0.1:1\"\n  model: \"test-model-1.0\"\n",
	}

	if *update {
		if err := os.WriteFile(goldenPath, []byte(goldenTranscript(t, "")), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	for name, extra := range variants {
		if got := goldenTranscript(t, extra); got != string(want) {
			t.Errorf("%s: output differs from %s:\n%s", name, goldenPath, got)
		}
	}
}
