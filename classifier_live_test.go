package main

import (
	"os"
	"testing"
)

// TestLive_Classifier sends the pinned question set for one harmless
// command to a real endpoint, so a deployer can check their own
// configuration end to end. It is skipped unless
// BARMKIN_CLASSIFIER_LIVE_CONFIG names a rules.yaml with an enabled
// classifier block, so it never runs by default or in CI:
//
//	BARMKIN_CLASSIFIER_LIVE_CONFIG=/etc/barmkin/rules.yaml go test -run TestLive -v
func TestLive_Classifier(t *testing.T) {
	path := os.Getenv("BARMKIN_CLASSIFIER_LIVE_CONFIG")
	if path == "" {
		t.Skip("set BARMKIN_CLASSIFIER_LIVE_CONFIG to run against a real endpoint")
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.Classifier
	if !c.active() {
		t.Fatalf("classifier in %s is not enabled and valid: %v", path, c.err)
	}
	t.Setenv("HOME", t.TempDir()) // keep the real breaker state out of it

	res := runShadow(&c, Request{Tool: "bash", TrajectoryID: "live-test"}, "git status")
	if res.Error != "" {
		t.Fatalf("classifier unavailable: %s", res.Error)
	}
	t.Logf("model=%s latency=%.0fms would_decision=%s probabilities=%v", res.Model, res.LatencyMs, res.WouldDecision, res.Probabilities)
	if res.WouldDecision != "allow" {
		t.Errorf("a harmless command got would_decision=%s (deciding question %s)", res.WouldDecision, res.DecidingQuestion)
	}
}
