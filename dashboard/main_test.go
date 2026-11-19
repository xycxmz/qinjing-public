package main

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
)

func renderPage(t *testing.T, page string, d *Data) string {
	t.Helper()
	tmpl, err := template.New("").Funcs(funcMap).ParseFS(assets, "templates/*.html")
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, page, PageData{Data: d, Title: "test", Active: "scores"}); err != nil {
		t.Fatalf("execute %s: %v", page, err)
	}
	return buf.String()
}

func f64(v float64) *float64 { return &v }

func demoRun(synthetic bool) Run {
	return Run{
		RunID: "demo-001", Product: "demo-hids", Timestamp: "2026-11-19T00:00:00Z",
		Synthetic: synthetic,
		Meta: RunMeta{
			CorpusSHA256: "abc123", Calibre: "v2.2", RunKind: "COMPLETE",
			TargetKernel: "5.99-test", TargetDistro: "Test OS 7", Host: "selftest",
		},
		Totals: Totals{Cases: 8, FP: 2, Attack: 6},
		Detection: Detection{
			Detectable: 4, Hit: 3, Strict: 2, Anyhit: 3, Notrun: 1,
			SignalRate: f64(0.75), StrictRate: f64(0.5), AnyhitRate: f64(0.75),
		},
		FP: FP{Evaluable: 2, Legacy: 2, Violations: 1, AttemptRate: f64(0.5), VerifiedRate: nil},
		PerClass: []RunClassRow{
			{Class: "net_scan_external", Cases: 1, Detected: 1, Missed: 0, MedianLatencyMs: f64(500), TechTagged: 1},
			{Class: "net_recon_local", Cases: 1, Detected: 0, Missed: 1, MedianLatencyMs: nil, TechTagged: 0},
		},
	}
}

// The shipped corpus has zero real-machine runs, so the scores page must show
// the pending placeholder and never a score or a demo badge.
func TestScoresEmptyPlaceholder(t *testing.T) {
	out := renderPage(t, "scores.html", &Data{Meta: Meta{Calibre: "v2.2"}, Runs: []Run{}})
	for _, want := range []string{"Pending real-machine measurement", "0 runs"} {
		if !strings.Contains(out, want) {
			t.Errorf("empty scores page missing %q", want)
		}
	}
	if strings.Contains(out, "demo-badge") {
		t.Error("empty scores page must not render a SYNTHETIC DEMO badge")
	}
}

// A synthetic run must be unmistakably labelled and still render the score
// framework (rates, N/A for empty denominators, per-class table).
func TestScoresSyntheticRunLabelled(t *testing.T) {
	out := renderPage(t, "scores.html", &Data{Runs: []Run{demoRun(true)}})
	for _, want := range []string{"demo-badge", "SYNTHETIC DEMO", "demo-hids", "75%", "N/A", "net_scan_external", "500"} {
		if !strings.Contains(out, want) {
			t.Errorf("synthetic run page missing %q", want)
		}
	}
}

// A real (non-synthetic) run renders scores WITHOUT the demo badge.
func TestScoresRealRunNoBadge(t *testing.T) {
	out := renderPage(t, "scores.html", &Data{Runs: []Run{demoRun(false)}})
	if strings.Contains(out, "demo-badge") {
		t.Error("real run must not carry a SYNTHETIC DEMO badge")
	}
	if !strings.Contains(out, "demo-hids") {
		t.Error("real run page missing product name")
	}
}

// An incomplete run must be disclosed as not publishable.
func TestScoresInterruptedDisclosed(t *testing.T) {
	r := demoRun(false)
	r.Meta.RunKind = "INTERRUPTED"
	out := renderPage(t, "scores.html", &Data{Runs: []Run{r}})
	if !strings.Contains(out, "not a complete, publishable run") {
		t.Error("INTERRUPTED run must be disclosed as not publishable")
	}
}

func TestFmtNullable(t *testing.T) {
	if got := fmtRate(nil); got != "N/A" {
		t.Errorf("fmtRate(nil) = %q, want N/A", got)
	}
	if got := fmtRate(f64(0.75)); got != "75%" {
		t.Errorf("fmtRate(0.75) = %q, want 75%%", got)
	}
	if got := fmtMs(nil); got != "–" {
		t.Errorf("fmtMs(nil) = %q, want dash", got)
	}
	if got := fmtMs(f64(500)); got != "500" {
		t.Errorf("fmtMs(500) = %q, want 500", got)
	}
}

// The committed artifact must parse and stay honest: empty runs, real totals.
func TestLoadCommittedData(t *testing.T) {
	d, err := loadData("dashboard_data.json")
	if err != nil {
		t.Fatalf("load committed data: %v", err)
	}
	if len(d.Runs) != 0 {
		t.Errorf("shipped dashboard_data.json must have empty runs, got %d", len(d.Runs))
	}
	if d.Totals.Cases != 1075 || d.Totals.Classes != 52 {
		t.Errorf("committed totals drift: %+v", d.Totals)
	}
	if len(d.TechniqueHeatmap) != d.Meta.TechniquesCovered {
		t.Error("heatmap count != meta.techniques_covered")
	}
}