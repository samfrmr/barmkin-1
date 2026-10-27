package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode"
)

// TestPersona_ReflowKeepsWording rewraps every question at several
// widths, down to one word per line and up to one line per question:
// the parsed wording, and so every request, must not change.
func TestPersona_ReflowKeepsWording(t *testing.T) {
	want, err := questionWording()
	if err != nil {
		t.Fatal(err)
	}
	for _, width := range []int{1, 30, 52, 100, 2000} {
		var b strings.Builder
		b.WriteString("# Persona\n\nCommentary.\n")
		for _, id := range questionIDs() {
			b.WriteString("\n" + personaQuestionHeading + id + "\n\n")
			line := ""
			for _, word := range strings.Fields(want[id]) {
				if line != "" && len(line)+1+len(word) > width {
					b.WriteString(line + "\n")
					line = ""
				}
				if line != "" {
					line += " "
				}
				line += word
			}
			b.WriteString("  " + line + " \r\n")
		}
		got, err := parsePersona(b.String(), questionIDs())
		if err != nil {
			t.Fatalf("width %d: %v", width, err)
		}
		for _, id := range questionIDs() {
			if got[id] != want[id] {
				t.Errorf("width %d: %s = %q, want %q", width, id, got[id], want[id])
			}
		}
	}
}

func TestPersona_Strict(t *testing.T) {
	ids := []string{"a", "b"}
	cases := []struct{ name, src, want string }{
		{"unknown question", "## Question: a\n\nA?\n\n## Question: c\n\nC?\n", `line 5: unknown question "c"`},
		{"duplicate question", "## Question: a\n\nA?\n\n## Question: a\n\nA?\n", `line 5: question "a" appears twice`},
		{"missing question", "## Question: a\n\nA?\n", `question "b" is missing`},
		{"empty question", "## Question: a\n\n## Question: b\n\nB?\n", `line 1: question "a" is empty`},
		{"empty last question", "## Question: a\n\nA?\n\n## Question: b\n\n", `line 5: question "b" is empty`},
		{"two paragraphs", "## Question: a\n\nA?\n\nAnd more?\n\n## Question: b\n\nB?\n", `line 5: question "a" has more than one paragraph`},
		{"split hyphenated word", "## Question: a\n\nAny third-\nparty state?\n\n## Question: b\n\nB?\n", "line 3: line ends in a hyphen"},
		{"other heading", "# Title\n\n## Notes\n\n## Question: a\n\nA?\n\n## Question: b\n\nB?\n", `line 3: unexpected heading "## Notes"`},
		{"heading inside a question", "## Question: a\n\nA?\n### Why\n\n## Question: b\n\nB?\n", `line 4: unexpected heading "### Why"`},
		{"second title", "# Title\n\n## Question: a\n\nA?\n\n# Again\n\n## Question: b\n\nB?\n", `line 7: unexpected heading "# Again"`},
		{"heading without a space", "## Question:a\n\nA?\n\n## Question: b\n\nB?\n", `line 1: unexpected heading "## Question:a"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePersona(tc.src, ids)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}

	got, err := parsePersona("Preamble.\n# Title\n\nCommentary, *kept out*.\n\n## Question: b\n\nIs *this*\n  sent  as-is?\n\n## Question: a\n\nA?", ids)
	if err != nil {
		t.Fatal(err)
	}
	if got["a"] != "A?" || got["b"] != "Is *this* sent  as-is?" || len(got) != 2 {
		t.Errorf("got %q", got)
	}
}

// TestPersona_SingleSource fails if a question's wording appears in Go
// source, where it could drift from the persona.
func TestPersona_SingleSource(t *testing.T) {
	wording, err := questionWording()
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	collapse := regexp.MustCompile(`\s+`)
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		flat := collapse.ReplaceAllString(string(src), " ")
		for id, text := range wording {
			// The first clause is enough to catch a copy.
			clause := strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == '?' })[0]
			if strings.Contains(flat, clause) {
				t.Errorf("%s contains the wording of %s: %q", f, id, clause)
			}
		}
	}
}

// TestPersona_BrokenDisablesOnlyTheClassifier: a malformed persona is a
// classifier error, reported by validate, and the classifier stays off.
func TestPersona_BrokenDisablesOnlyTheClassifier(t *testing.T) {
	orig := questionWording
	t.Cleanup(func() { questionWording = orig })
	questionWording = func() (map[string]string, error) {
		return parsePersona("# Persona\n", questionIDs())
	}

	c := &Classifier{Enabled: true, BaseURL: "http://127.0.0.1:1", Model: testModel}
	c.prepare()
	if c.err == nil || !strings.Contains(c.err.Error(), "persona: question") || c.active() {
		t.Errorf("err = %v, active = %v; want a persona error and the classifier off", c.err, c.active())
	}
	if got := classifierStatus(*c); got != "invalid (disabled)" {
		t.Errorf("status = %q", got)
	}
}

// TestPersona_UnconfiguredNeverReadsIt: without an enabled classifier,
// barmkin doesn't touch the persona at all.
func TestPersona_UnconfiguredNeverReadsIt(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	orig := questionWording
	t.Cleanup(func() { questionWording = orig })
	read := false
	questionWording = func() (map[string]string, error) {
		read = true
		return orig()
	}

	for name, block := range map[string]string{
		"no block":       "",
		"disabled block": "classifier:\n  enabled: false\n  base_url: \"http://127.0.0.1:1\"\n  model: \"m-1\"\n",
	} {
		path := filepath.Join(t.TempDir(), "rules.yaml")
		if err := os.WriteFile(path, []byte("rules: []\n"+block), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg, err := loadConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		newEngine(cfg).evaluate([]byte(`{"tool_name":"Bash","tool_input":{"command":"make build"},"session_id":"s1"}`))
		if read {
			t.Errorf("%s: the persona was read", name)
		}
	}
}

// TestPersona_FileIsPlainText keeps the embedded file to printable
// text, so nothing invisible can reach a request.
func TestPersona_FileIsPlainText(t *testing.T) {
	for i, r := range personaFile {
		if r != '\n' && r != '\r' && !unicode.IsPrint(r) {
			t.Fatalf("classifier-persona.md: byte %d is %U", i, r)
		}
	}
}
