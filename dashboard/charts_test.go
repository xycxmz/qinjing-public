package main

import (
	"strings"
	"testing"
)

// Precision is detected attack cases over detected plus FP violations; an
// empty denominator is N/A, never coerced to zero.
func TestRunPrecision(t *testing.T) {
	r := demoRun(false) // Hit=3, Violations=1
	p := runPrecision(r)
	if p == nil || *p != 0.75 {
		t.Errorf("runPrecision = %v, want 0.75 (3/4)", p)
	}
	r.Detection.Hit = 0
	r.FP.Violations = 0
	if p := runPrecision(r); p != nil {
		t.Errorf("runPrecision on empty denominator = %v, want nil", p)
	}
}

// The scatter plots one point per run that has both an FPR and a precision;
// x is FPR, y is precision, and a run missing either axis is excluded.
func TestBuildScatter(t *testing.T) {
	pts := buildScatter([]Run{demoRun(true)})
	if len(pts) != 1 {
		t.Fatalf("scatter points = %d, want 1", len(pts))
	}
	if pts[0].FPR != 0.5 || pts[0].Precision != 0.75 {
		t.Errorf("point = FPR %v precision %v, want 0.5/0.75", pts[0].FPR, pts[0].Precision)
	}
	if !pts[0].Synthetic || pts[0].Label != "demo-hids" {
		t.Errorf("point must carry synthetic flag + product label: %+v", pts[0])
	}
	// Higher precision sits higher (smaller pixel Y); higher FPR sits right.
	if pts[0].Y >= scatterPlotY+scatterPlotH/2 {
		t.Errorf("precision 0.75 must plot in the upper half, Y=%v", pts[0].Y)
	}
	noFPR := demoRun(false)
	noFPR.FP.AttemptRate = nil
	if pts := buildScatter([]Run{noFPR}); len(pts) != 0 {
		t.Errorf("run without FPR must be excluded, got %d points", len(pts))
	}
}

// With no runs the scatter is an honest empty state, never an invented plot.
func TestScatterSVGEmptyState(t *testing.T) {
	out := string(renderScatterSVG(nil, "en"))
	if strings.Contains(out, "<svg") {
		t.Error("empty scatter must not render an SVG plot")
	}
	if !strings.Contains(out, "activates when a real run is scored") {
		t.Errorf("empty scatter must explain it activates on a real run: %q", out)
	}
}

// A synthetic run renders a real SVG plot, labelled SYNTHETIC so it can never
// pass as a product result.
func TestScatterSVGSynthetic(t *testing.T) {
	out := string(renderScatterSVG([]Run{demoRun(true)}, "en"))
	for _, want := range []string{"<svg", "<circle", "demo-hids", "synthetic", "Precision", "False-positive rate"} {
		if !strings.Contains(out, want) {
			t.Errorf("synthetic scatter missing %q", want)
		}
	}
}

// The heatmap sorts classes by mean FPR descending (worst first) and bands
// each cell; a nil FPR cell is N/A, not zero.
func TestBuildFPRHeatmapSort(t *testing.T) {
	runs := []Run{
		{Product: "A", PerClass: []RunClassRow{
			{Class: "low", FPR: f64(0.01)}, {Class: "high", FPR: f64(0.30)}}},
		{Product: "B", PerClass: []RunClassRow{
			{Class: "low", FPR: f64(0.02)}, {Class: "high", FPR: f64(0.40)}}},
	}
	v := buildFPRHeatmap(runs)
	if !v.HasData || len(v.Rows) != 2 {
		t.Fatalf("heatmap HasData=%v rows=%d, want true/2", v.HasData, len(v.Rows))
	}
	if v.Rows[0].Class != "high" || v.Rows[1].Class != "low" {
		t.Errorf("heatmap must sort by mean FPR desc: %s then %s", v.Rows[0].Class, v.Rows[1].Class)
	}
	if v.Rows[0].Mean == nil || *v.Rows[0].Mean != 0.35 {
		t.Errorf("high mean = %v, want 0.35", v.Rows[0].Mean)
	}
	if v.Rows[0].Cells[0].Band != fprBand(0.30) {
		t.Errorf("cell band = %s, want %s", v.Rows[0].Cells[0].Band, fprBand(0.30))
	}
}

// No runs: honest empty state. Runs whose per-class FPR is all nil (the scorer
// today): a distinct "not measured" note, never a misleading all-zero matrix.
func TestFPRHeatmapEmptyAndUnmeasured(t *testing.T) {
	empty := string(renderFPRHeatmap(nil, "en"))
	if strings.Contains(empty, "<table") {
		t.Error("empty heatmap must not render a table")
	}
	if !strings.Contains(empty, "activates when a real run is scored") {
		t.Errorf("empty heatmap must explain activation: %q", empty)
	}
	v := buildFPRHeatmap([]Run{demoRun(false)}) // PerClass FPR all nil
	if v.HasData {
		t.Error("heatmap with all-nil per-class FPR must report HasData=false")
	}
	out := string(renderFPRHeatmap([]Run{demoRun(false)}, "en"))
	if !strings.Contains(out, "no per-class false-positive rate is measured yet") {
		t.Errorf("unmeasured heatmap must disclose the gap: %q", out)
	}
	if strings.Contains(out, "<table") {
		t.Error("unmeasured heatmap must not render a zero-filled table")
	}
}

// A synthetic fixture with per-class FPR renders the matrix table with band
// classes and class names, sorted by mean.
func TestFPRHeatmapSynthetic(t *testing.T) {
	runs := []Run{
		{Product: "A", Synthetic: true, PerClass: []RunClassRow{
			{Class: "net_scan_external", FPR: f64(0.0)},
			{Class: "archive_staging", FPR: f64(0.25)}}},
	}
	out := string(renderFPRHeatmap(runs, "en"))
	for _, want := range []string{"<table", "net_scan_external", "archive_staging", "fpr-3", "fpr-0"} {
		if !strings.Contains(out, want) {
			t.Errorf("synthetic heatmap missing %q", want)
		}
	}
	// archive_staging (mean 0.25) sorts above net_scan_external (mean 0).
	if strings.Index(out, "archive_staging") > strings.Index(out, "net_scan_external") {
		t.Error("heatmap rows must be sorted by mean FPR descending")
	}
}

// Through the real mux the committed (empty) scores page shows both chart empty
// states and no SVG plot; the methodology panel still renders.
func TestScoresChartsEmptyHTTP(t *testing.T) {
	d, err := loadData("dashboard_data.json")
	if err != nil {
		t.Fatalf("load committed data: %v", err)
	}
	s := testServer(t, d)
	code, body := getBody(t, s, "/scores")
	if code != 200 {
		t.Fatalf("/scores status = %d, want 200", code)
	}
	if strings.Contains(body, "<svg") {
		t.Error("committed empty scores page must not render a scatter SVG")
	}
	if strings.Contains(body, "demo-badge") {
		t.Error("committed empty scores page must not render a synthetic badge")
	}
	for _, want := range []string{"Precision versus false-positive rate", "FPR heatmap", "Statistical methodology"} {
		if !strings.Contains(body, want) {
			t.Errorf("empty scores page missing chart section %q", want)
		}
	}
}