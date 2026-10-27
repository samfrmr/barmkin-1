// Classifier persona: the wording of the pinned questions.
//
// The text of every question lives in classifier-persona.md, embedded
// in the binary at build time, so it reads and reviews as prose; the
// ids, thresholds and verdicts code acts on stay in shadow.go. Only an
// enabled classifier parses it, so an unconfigured barmkin never does,
// and a malformed file is a classifier error like any other: it turns
// off the classifier, never the rules.
package main

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"
)

//go:embed classifier-persona.md
var personaFile string

const personaQuestionHeading = "## Question: "

// questionWording returns each pinned question's instructions, parsed
// from the embedded persona once, on first use.
var questionWording = sync.OnceValues(func() (map[string]string, error) {
	return parsePersona(personaFile, questionIDs())
})

func questionIDs() []string {
	ids := make([]string, len(questions))
	for i, q := range questions {
		ids[i] = q.ID
	}
	return ids
}

// parsePersona reads one paragraph of instructions per question id.
// It is strict, and every error names the line: below a single "# "
// title, the only heading allowed is "## Question: <id>", once for each
// id in ids. A question's lines are trimmed and joined with single
// spaces, so reflowing the file never changes a request; a blank line
// inside a question, or a line ending in a hyphen (which the join would
// turn into "third- party"), is an error. Text before the first
// question is commentary.
func parsePersona(src string, ids []string) (map[string]string, error) {
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	out := make(map[string]string, len(ids))
	var id string // question being read; "" while in commentary
	var body []string
	var start int
	blank, headed := false, false
	flush := func() error {
		if id == "" {
			return nil
		}
		if len(body) == 0 {
			return fmt.Errorf("persona line %d: question %q is empty", start, id)
		}
		out[id] = strings.Join(body, " ")
		return nil
	}
	for i, line := range strings.Split(src, "\n") {
		n := i + 1
		line = strings.TrimRight(line, " \t\r")
		switch {
		case strings.HasPrefix(line, "#"):
			if err := flush(); err != nil {
				return nil, err
			}
			id, body, blank = "", nil, false
			switch next := strings.TrimPrefix(line, personaQuestionHeading); {
			case next != line:
				if !want[next] {
					return nil, fmt.Errorf("persona line %d: unknown question %q", n, next)
				}
				if _, dup := out[next]; dup {
					return nil, fmt.Errorf("persona line %d: question %q appears twice", n, next)
				}
				id, start = next, n
			case strings.HasPrefix(line, "# ") && !headed:
				// the title
			default:
				return nil, fmt.Errorf("persona line %d: unexpected heading %q", n, line)
			}
			headed = true
		case id == "":
			// commentary
		case strings.TrimSpace(line) == "":
			blank = len(body) > 0
		case blank:
			return nil, fmt.Errorf("persona line %d: question %q has more than one paragraph", n, id)
		case strings.HasSuffix(line, "-"):
			return nil, fmt.Errorf("persona line %d: line ends in a hyphen; rejoin it, since a line break reads as a space", n)
		default:
			body = append(body, strings.TrimSpace(line))
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	for _, q := range ids {
		if _, ok := out[q]; !ok {
			return nil, fmt.Errorf("persona: question %q is missing", q)
		}
	}
	return out, nil
}
