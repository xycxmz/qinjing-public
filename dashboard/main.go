// Command dashboard is the qinjing coverage dashboard (phase 1).
//
// It is a server-rendered multi-page app (owner decision D1: Go SSR MPA) that
// reads dashboard/dashboard_data.json - produced by tools/gen_dashboard_data.py
// from the zero-dependency Python toolchain - and renders the corpus's own
// coverage capability: totals, ATT&CK tactic coverage, technique heatmap,
// signal-class distribution and reference-bench provisioning.
//
// Honesty premise: every number here is a measured property
// of the CORPUS, not a product detection score. Product scores need real-machine
// runs (suspended) and live in the empty runs[] array; the /scores page shows a
// "pending real-machine run" placeholder and never invents a number.
//
// Standard library only: net/http + html/template + embed. No third-party deps,
// mirroring the Python toolchain's zero-dependency discipline.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed templates static
var assets embed.FS

// tacticNames maps ATT&CK tactic ids to display names for the pinned matrix
// (v20.1). Sourced from docs/11 (WebFetch-verified against attack.mitre.org):
// v19 split Defense Evasion into Stealth (TA0005) + Defense Impairment (TA0112),
// giving 15 enterprise tactics.
var tacticNames = map[string]string{
	"TA0043": "Reconnaissance",
	"TA0042": "Resource Development",
	"TA0001": "Initial Access",
	"TA0002": "Execution",
	"TA0003": "Persistence",
	"TA0004": "Privilege Escalation",
	"TA0005": "Stealth",
	"TA0112": "Defense Impairment",
	"TA0006": "Credential Access",
	"TA0007": "Discovery",
	"TA0008": "Lateral Movement",
	"TA0009": "Collection",
	"TA0011": "Command and Control",
	"TA0010": "Exfiltration",
	"TA0040": "Impact",
}

type Meta struct {
	CorpusSHA256      string `json:"corpus_sha256"`
	Version           string `json:"version"`
	Calibre           string `json:"calibre"`
	AttackVersion     string `json:"attack_version"`
	MatrixTechniques  int    `json:"matrix_techniques"`
	TechniquesCovered int    `json:"techniques_covered"`
	GeneratedBy       string `json:"generated_by"`
}

type Totals struct {
	Cases         int            `json:"cases"`
	FP            int            `json:"fp"`
	Attack        int            `json:"attack"`
	Classes       int            `json:"classes"`
	Impact        map[string]int `json:"impact"`
	Modes         map[string]int `json:"modes"`
	AttackExpect  map[string]int `json:"attack_expect"`
	AttackNoClass int            `json:"attack_no_class"`
}

type TacticRow struct {
	Tactic      string `json:"tactic"`
	Covered     int    `json:"covered"`
	MatrixTotal int    `json:"matrix_total"`
	Cases       int    `json:"cases"`
}

func (t TacticRow) Name() string {
	if n, ok := tacticNames[t.Tactic]; ok {
		return n
	}
	return t.Tactic
}

type TechRow struct {
	TechniqueID string `json:"techniqueID"`
	Name        string `json:"name"`
	Score       int    `json:"score"`
	Detectable  int    `json:"detectable"`
	Gap         int    `json:"gap"`
}

type ClassRow struct {
	Class           string            `json:"class"`
	Cases           int               `json:"cases"`
	Detectable      int               `json:"detectable"`
	Gap             int               `json:"gap"`
	ExpectBreakdown map[string]int    `json:"expect_breakdown"`
	ModeBreakdown   map[string]int    `json:"mode_breakdown"`
	Anchors         []string          `json:"anchors"`
	Counterpart     string            `json:"counterpart"`
	AdapterRules    []AdapterMapping  `json:"adapter_rules"`
}

// AdapterMapping is one adapter's rule mapping for a signal class (P1
// expected detection profile). Rules are the adapter's own rule identifiers
// (xiezhi seed names, wazuh native rule ids); ExecveClassifiers counts the
// wazuh execve argv regexes targeting the class (the regexes stay in the
// adapter source, only the count is published).
type AdapterMapping struct {
	Adapter           string   `json:"adapter"`
	Rules             []string `json:"rules"`
	ExecveClassifiers int      `json:"execve_classifiers"`
}

// BenignRow is one benign_ops_* subfamily in the FP page census (P1):
// group (form / persona), case count, and up to three representative case ids.
type BenignRow struct {
	Subfamily string   `json:"subfamily"`
	Group     string   `json:"group"`
	Cases     int      `json:"cases"`
	Examples  []string `json:"examples"`
}

// Case is one corpus case in the catalog (P2), mirroring the cases[]
// array from gen_dashboard_data.py. Cmd is the linted, public-safe command
// (TEST-NET / example domains / /tmp/qinjing-* only); the generator's
// sensitive scan gates the artifact before it ever reaches this struct.
type Case struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Tactic          string   `json:"tactic"`
	Technique       string   `json:"technique"`
	TechniqueName   string   `json:"technique_name"`
	Platforms       []string `json:"platforms"`
	Mode            string   `json:"mode"`
	Bin             string   `json:"bin"`
	Expect          string   `json:"expect"`
	ExpectedSignals []string `json:"expected_signals"`
	RelatedSignals  []string `json:"related_signals"`
	Impact          string   `json:"impact"`
	Bucket          string   `json:"bucket"`
	Cmd             string   `json:"cmd"`
	CreatesProcess  bool     `json:"creates_process"`
}

// tacticName resolves a tactic id to its display name; BENIGN (the benign
// group) and unknown ids render as-is.
func tacticName(id string) string {
	if n, ok := tacticNames[id]; ok {
		return n
	}
	return id
}

type ProvRow struct {
	Class      string `json:"class"`
	Cases      int    `json:"cases"`
	Evaluable  bool   `json:"evaluable"`
	ServiceDep bool   `json:"service_dep"`
	SimOnly    bool   `json:"sim_only"`
}

type Provisioning struct {
	CorpusClasses  int       `json:"corpus_classes"`
	EvaluableRef   int       `json:"evaluable_ref"`
	ServiceDep     int       `json:"service_dep"`
	SimOnlyClasses []string  `json:"sim_only_classes"`
	Rows           []ProvRow `json:"rows"`
}

// RunMeta is the scorer --out-json meta block: the measurement identity that
// must travel with every score so a number can always be traced to exact bytes.
type RunMeta struct {
	CorpusSHA256  string `json:"corpus_sha256"`
	Calibre       string `json:"calibre"`
	MinSeverity   string `json:"min_severity"`
	GraceMs       int    `json:"grace_ms"`
	RunKind       string `json:"run_kind"`
	Host          string `json:"host"`
	TargetKernel  string `json:"target_kernel"`
	TargetDistro  string `json:"target_distro"`
}

type Detection struct {
	Detectable       int      `json:"detectable"`
	Hit              int      `json:"hit"`
	Strict           int      `json:"strict"`
	Anyhit           int      `json:"anyhit"`
	Notrun           int      `json:"notrun"`
	TransportInvalid int      `json:"transport_invalid"`
	NotMeasured      int      `json:"not_measured"`
	SignalRate       *float64   `json:"signal_rate"`
	StrictRate       *float64   `json:"strict_rate"`
	AnyhitRate       *float64   `json:"anyhit_rate"`
	SignalCI95       []*float64 `json:"signal_ci95"`
}

type FP struct {
	Evaluable         int      `json:"evaluable"`
	Verified          int      `json:"verified"`
	Attempt           int      `json:"attempt"`
	Legacy            int      `json:"legacy"`
	Violations        int      `json:"violations"`
	ViolationsVerified int     `json:"violations_verified"`
	VerifiedRate      *float64 `json:"verified_rate"`
	AttemptRate       *float64 `json:"attempt_rate"`
	AttemptUpper95    *float64 `json:"attempt_upper95"`
}

// LatencyInfo and AggregationInfo carry the docs/11 C6/C11 disclosures so the
// scores page never presents a latency or rate without its calibre and bounds.
type LatencyInfo struct {
	Subset          string `json:"subset"`
	NegativeDropped int    `json:"negative_dropped"`
	Calibre         string `json:"calibre"`
}

type AggregationInfo struct {
	MicroSignalRate *float64 `json:"micro_signal_rate"`
	MacroSignalRate *float64 `json:"macro_signal_rate"`
	TotalScore      *float64 `json:"total_score"`
	Note            string   `json:"note"`
}

// StrictProcess is the C8 parallel process-coherence view (cross-check of the
// heuristic, not a re-attribution).
type StrictProcess struct {
	Coherent       int    `json:"coherent"`
	Incoherent     int    `json:"incoherent"`
	Unattributable int    `json:"unattributable"`
	AuidAvailable  bool   `json:"auid_available"`
	Note           string `json:"note"`
}

// Tiers is the G3 MITRE-style detection-quality distribution (additive).
// PerClass mirrors the scorer's tiers.per_class block so the /case evidence
// section can show the tier split for a case's expected classes.
type Tiers struct {
	Totals   map[string]int `json:"totals"`
	PerClass []TierClassRow `json:"per_class"`
	Note     string         `json:"note"`
}

type TierClassRow struct {
	Class     string `json:"class"`
	Technique int    `json:"technique"`
	Tactic    int    `json:"tactic"`
	General   int    `json:"general"`
	None      int    `json:"none"`
}

type RunClassRow struct {
	Class           string   `json:"class"`
	Cases           int      `json:"cases"`
	Detected        int      `json:"detected"`
	Missed          int      `json:"missed"`
	NotMeasured     int      `json:"not_measured"`
	MedianLatencyMs *float64   `json:"median_latency_ms"`
	TechTagged      int        `json:"tech_tagged"`
	LatencyN        int        `json:"latency_n"`
	NegativeDropped int        `json:"negative_dropped"`
	HitCI95         []*float64 `json:"hit_ci95"`
	// FPR is a forward-compatible per-class false-positive rate slot for the
	// FPR heatmap. The scorer aggregates FP globally today (benign cases carry
	// no expected signal class), so real runs leave this nil and the heatmap
	// cell renders N/A until a scorer extension emits per-class FPR.
	FPR *float64 `json:"fpr"`
}

type RunAggRow struct {
	Name       string `json:"name"`
	Cases      int    `json:"cases"`
	Detectable int    `json:"detectable"`
	Detected   int    `json:"detected"`
	Anyhit     int    `json:"anyhit"`
}

// Run is one phase-2 score record. The measurement core mirrors
// scorer --out-json; the identity fields (run_id/product/timestamp) and the
// Synthetic flag are added by whatever ingests a run into runs[]. Synthetic
// marks UI-debugging demo data so the page can label it SYNTHETIC DEMO and
// never let it pass as a real product result (honesty premise).
type Run struct {
	RunID       string        `json:"run_id"`
	Product     string        `json:"product"`
	Timestamp   string        `json:"timestamp"`
	Synthetic   bool          `json:"synthetic"`
	Meta        RunMeta       `json:"meta"`
	Totals      Totals        `json:"totals"`
	Detection   Detection     `json:"detection"`
	FP          FP            `json:"fp"`
	PerClass    []RunClassRow   `json:"per_class"`
	ByTactic    []RunAggRow     `json:"by_tactic"`
	ByTechnique []RunAggRow     `json:"by_technique"`
	Latency     LatencyInfo     `json:"latency"`
	Aggregation AggregationInfo `json:"aggregation"`
	Strict      StrictProcess   `json:"strict_process"`
	Tiers       Tiers           `json:"tiers"`

	// Forward-compatible P3 slots. The scorer does not emit these
	// today and the shipped runs[] is empty, so they stay zero until a run
	// ingestion fills them; the page renders an honest empty state meanwhile.
	// ArtifactReport/ExecLog/Alerts link the raw evidence whose sha triple
	// (corpus/exec-log/alerts, in the markdown report) pins the exact input.
	// Version keys the run into a benchmark-version group; Deprecated marks a
	// retired run, hidden by default but kept (archived, not deleted).
	// LabelSourceCounts splits labels by native/adapter/reviewer origin;
	// Modifiers carries MITRE-style run modifiers; DurationMs is the run
	// wall-clock cost (nil = not recorded).
	ArtifactReport    string         `json:"artifact_report"`
	ArtifactExecLog   string         `json:"artifact_exec_log"`
	ArtifactAlerts    string         `json:"artifact_alerts"`
	Version           string         `json:"version"`
	Deprecated        bool           `json:"deprecated"`
	LabelSourceCounts map[string]int `json:"label_source_counts"`
	Modifiers         []string       `json:"modifiers"`
	DurationMs        *int64         `json:"duration_ms"`
}

// Data mirrors dashboard_data.json. NavigatorLayer is kept
// raw so /layer.json serves the exact bytes the Python toolchain emitted.
type Data struct {
	Meta              Meta            `json:"meta"`
	Totals            Totals          `json:"totals"`
	TacticCoverage    []TacticRow     `json:"tactic_coverage"`
	TechniqueHeatmap  []TechRow       `json:"technique_heatmap"`
	Uncovered         []TechRow       `json:"uncovered"`
	ClassDistribution []ClassRow      `json:"class_distribution"`
	BenignDistribution []BenignRow    `json:"benign_distribution"`
	Cases             []Case          `json:"cases"`
	Provisioning      Provisioning    `json:"provisioning"`
	NavigatorLayer    json.RawMessage `json:"navigator_layer"`
	NavigatorLayerURL string          `json:"navigator_layer_url"`
	Runs              []Run           `json:"runs"`
}

type PageData struct {
	Data   *Data
	Title  string
	Active string
	Lang   string
	Cases  *CasesView // /cases catalog state (nil on other pages)
	Case   *CaseView  // /case detail state (nil on other pages)
	FP     *FPView    // /fp page state (nil on other pages)
	Scores *ScoresView // /scores run-history state (nil on other pages)
}

// T translates a UI string for the current language.
// Templates call {{$.T "English literal"}}; zh catalog lives in i18n.go.
func (p PageData) T(s string) string { return translate(p.Lang, s) }

// langOf resolves the UI language from ?lang= then the lang cookie, default en.
// A ?lang= value is persisted via cookie so the choice survives navigation.
func langOf(w http.ResponseWriter, r *http.Request) string {
	lang := r.URL.Query().Get("lang")
	if lang != "en" && lang != "zh" {
		if c, err := r.Cookie("lang"); err == nil {
			lang = c.Value
		}
	}
	if lang != "en" && lang != "zh" {
		lang = "en"
	}
	if q := r.URL.Query().Get("lang"); q == "en" || q == "zh" {
		http.SetCookie(w, &http.Cookie{Name: "lang", Value: q, Path: "/"})
	}
	return lang
}

func loadData(path string) (*Data, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d Data
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &d, nil
}

func pct(n, d int) int {
	if d == 0 {
		return 0
	}
	return n * 100 / d
}

// heatClass buckets a technique case-count into the same three bands the
// Navigator layer gradient uses (1-2 / 3-5 / 6+), so the dashboard heatmap and
// the Navigator overlay read identically.
func heatClass(score int) string {
	switch {
	case score >= 6:
		return "heat-3"
	case score >= 3:
		return "heat-2"
	default:
		return "heat-1"
	}
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func maxClassCases(rows []ClassRow) int {
	m := 0
	for _, r := range rows {
		if r.Cases > m {
			m = r.Cases
		}
	}
	return m
}

// fmtRate renders a nullable scorer rate (0..1) as a percentage. A nil rate is
// the scorer's N/A (empty denominator), shown as "N/A" - never coerced to 0%.
func fmtRate(v *float64) string {
	if v == nil {
		return "N/A"
	}
	return fmt.Sprintf("%.0f%%", *v*100)
}

// fmtMs renders a nullable median latency in ms; nil (no detection) is a dash.
func fmtMs(v *float64) string {
	if v == nil {
		return "–"
	}
	return fmt.Sprintf("%.0f", *v)
}

// fmtCI renders a two-sided exact binomial interval as percentages.
func fmtCI(ci []*float64) string {
	if len(ci) != 2 || ci[0] == nil || ci[1] == nil {
		return "N/A"
	}
	return fmt.Sprintf("[%.0f%%, %.0f%%]", *ci[0]*100, *ci[1]*100)
}

// fmtDuration renders a nullable run wall-clock duration: seconds above one
// second, milliseconds below. nil (not recorded) is a dash, never coerced to 0.
func fmtDuration(v *int64) string {
	if v == nil {
		return "–"
	}
	if *v >= 1000 {
		return fmt.Sprintf("%.1f s", float64(*v)/1000)
	}
	return fmt.Sprintf("%d ms", *v)
}

// Catalog filtering. The /cases page is server-rendered with no
// JS: the query is parsed at the boundary into a caseFilter, and filterCases
// is a pure transform from (cases, filter) to a page of rows. Dropdown options
// use the canonical vocabularies so they never depend on map iteration order.
const casesPerPage = 50

var tacticOrder = []string{"BENIGN", "TA0043", "TA0042", "TA0001", "TA0002",
	"TA0003", "TA0004", "TA0005", "TA0112", "TA0006", "TA0007", "TA0008",
	"TA0009", "TA0011", "TA0010", "TA0040"}
var modeOrder = []string{"real", "sim-missing-bin", "sim-builtin"}
var expectOrder = []string{"detectable", "gap", "silent"}
var platformOrder = []string{"linux"}

type caseFilter struct {
	Tactic   string
	Mode     string
	Expect   string
	Platform string
	Query    string // lowercased substring over id/name/cmd
	Page     int    // 1-based request page
}

func parseCaseFilter(q url.Values) caseFilter {
	f := caseFilter{
		Tactic:   q.Get("tactic"),
		Mode:     q.Get("mode"),
		Expect:   q.Get("expect"),
		Platform: q.Get("platform"),
		Query:    strings.ToLower(strings.TrimSpace(q.Get("q"))),
		Page:     1,
	}
	if n, err := strconv.Atoi(q.Get("page")); err == nil && n > 0 {
		f.Page = n
	}
	return f
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// tierFor resolves a signal class to its G3 tier row in a run (nil when the
// run did not tier that class), so the /case evidence table can show the tier
// split beside the class-level detection stats.
func tierFor(rows []TierClassRow, class string) *TierClassRow {
	for i := range rows {
		if rows[i].Class == class {
			return &rows[i]
		}
	}
	return nil
}

func caseMatches(c Case, f caseFilter) bool {
	if f.Tactic != "" && c.Tactic != f.Tactic {
		return false
	}
	if f.Mode != "" && c.Mode != f.Mode {
		return false
	}
	if f.Expect != "" && c.Expect != f.Expect {
		return false
	}
	if f.Platform != "" && !containsStr(c.Platforms, f.Platform) {
		return false
	}
	if f.Query != "" &&
		!strings.Contains(strings.ToLower(c.ID), f.Query) &&
		!strings.Contains(strings.ToLower(c.Name), f.Query) &&
		!strings.Contains(strings.ToLower(c.Cmd), f.Query) {
		return false
	}
	return true
}

// filterCases returns the matching page (corpus order preserved), the matched
// total, the page count (>=1), and the effective page (clamped into range).
func filterCases(cases []Case, f caseFilter) (rows []Case, total, pages, page int) {
	matched := make([]Case, 0)
	for _, c := range cases {
		if caseMatches(c, f) {
			matched = append(matched, c)
		}
	}
	total = len(matched)
	pages = (total + casesPerPage - 1) / casesPerPage
	if pages < 1 {
		pages = 1
	}
	page = f.Page
	if page < 1 {
		page = 1
	}
	if page > pages {
		page = pages
	}
	lo := (page - 1) * casesPerPage
	hi := lo + casesPerPage
	if hi > total {
		hi = total
	}
	return matched[lo:hi], total, pages, page
}

func orderedKeys(set map[string]bool, order []string) []string {
	out := make([]string, 0, len(set))
	for _, k := range order {
		if set[k] {
			out = append(out, k)
			delete(set, k)
		}
	}
	rest := make([]string, 0, len(set))
	for k := range set {
		rest = append(rest, k)
	}
	sort.Strings(rest)
	return append(out, rest...)
}

// CasesView is the per-request /cases state the template renders.
type CasesView struct {
	Rows       []Case
	Total      int // matches after filtering
	GrandTotal int // all catalog cases
	Page       int
	Pages      int
	PerPage    int
	Filter     caseFilter
	Tactics    []string
	Modes      []string
	Expects    []string
	Platforms  []string
}

// PageURL builds a /cases link that preserves the active filter and sets the
// page. Language rides the lang cookie, so it is not repeated here.
func (v *CasesView) PageURL(page int) string {
	q := url.Values{}
	if v.Filter.Tactic != "" {
		q.Set("tactic", v.Filter.Tactic)
	}
	if v.Filter.Mode != "" {
		q.Set("mode", v.Filter.Mode)
	}
	if v.Filter.Expect != "" {
		q.Set("expect", v.Filter.Expect)
	}
	if v.Filter.Platform != "" {
		q.Set("platform", v.Filter.Platform)
	}
	if v.Filter.Query != "" {
		q.Set("q", v.Filter.Query)
	}
	q.Set("page", strconv.Itoa(page))
	return "/cases?" + q.Encode()
}

func buildCasesView(cases []Case, f caseFilter) *CasesView {
	rows, total, pages, page := filterCases(cases, f)
	tactics, modes, expects, platforms := map[string]bool{}, map[string]bool{},
		map[string]bool{}, map[string]bool{}
	for _, c := range cases {
		tactics[c.Tactic] = true
		modes[c.Mode] = true
		expects[c.Expect] = true
		for _, p := range c.Platforms {
			platforms[p] = true
		}
	}
	return &CasesView{
		Rows: rows, Total: total, GrandTotal: len(cases),
		Page: page, Pages: pages, PerPage: casesPerPage, Filter: f,
		Tactics:   orderedKeys(tactics, tacticOrder),
		Modes:     orderedKeys(modes, modeOrder),
		Expects:   orderedKeys(expects, expectOrder),
		Platforms: orderedKeys(platforms, platformOrder),
	}
}

// contributeURL is the public contribution entry: uncovered
// techniques and gap cases link here so a visitor can propose a case in the
// public repo. The private repo path is never exposed.
const contributeURL = "https://github.com/xycxmz/qinjing-public/issues"

// CaseClass resolves one signal class to its anchors + external counterpart
// for the detail page's expected/related signal sections.
type CaseClass struct {
	Class        string
	Anchors      []string
	Counterpart  string
	AdapterRules []AdapterMapping
}

// CaseView is the per-request /case detail state: the case plus its resolved
// signal classes and the contribution entry.
type CaseView struct {
	Case          Case
	Expected      []CaseClass
	Related       []CaseClass
	ContributeURL string
}

func findCase(cases []Case, id string) (Case, bool) {
	for _, c := range cases {
		if c.ID == id {
			return c, true
		}
	}
	return Case{}, false
}

func buildCaseView(d *Data, c Case) *CaseView {
	byClass := make(map[string]ClassRow, len(d.ClassDistribution))
	for _, r := range d.ClassDistribution {
		byClass[r.Class] = r
	}
	resolve := func(names []string) []CaseClass {
		out := make([]CaseClass, 0, len(names))
		for _, n := range names {
			r := byClass[n]
			out = append(out, CaseClass{Class: n, Anchors: r.Anchors,
				Counterpart: r.Counterpart, AdapterRules: r.AdapterRules})
		}
		return out
	}
	return &CaseView{
		Case: c, Expected: resolve(c.ExpectedSignals),
		Related: resolve(c.RelatedSignals), ContributeURL: contributeURL,
	}
}

// FPView is the per-request /fp state: the benign census split into the form
// and persona groups with subtotals and the bar-chart maximum.
type FPView struct {
	FormRows     []BenignRow
	PersonaRows  []BenignRow
	FormTotal    int
	PersonaTotal int
	Total        int
	MaxCases     int
}

func buildFPView(rows []BenignRow) *FPView {
	v := &FPView{}
	for _, r := range rows {
		if r.Group == "form" {
			v.FormRows = append(v.FormRows, r)
			v.FormTotal += r.Cases
		} else {
			v.PersonaRows = append(v.PersonaRows, r)
			v.PersonaTotal += r.Cases
		}
		v.Total += r.Cases
		if r.Cases > v.MaxCases {
			v.MaxCases = r.Cases
		}
	}
	return v
}

// RunGroup is one benchmark-version bucket of visible runs (P3 version
// governance). An empty Version means the run recorded no version.
type RunGroup struct {
	Version string
	Runs    []Run
}

// ScoresView is the per-request /scores state. Deprecated runs are hidden by
// default and revealed by ?show_deprecated=1 (LMArena Show Deprecated); the
// archive banner reports how many retired runs are kept. Groups buckets the
// visible runs by version for the run history; Runs is the same visible set
// flat, which the scatter and heatmap consume so archived runs never pollute
// the comparison charts by default. Both are derived once by buildScoresView.
type ScoresView struct {
	Groups         []RunGroup
	Runs           []Run
	Archived       int
	ShowDeprecated bool
	Total          int
}

// buildScoresView is a pure transform from (runs, toggle) to the page state.
// Version groups are ordered by version string with the unversioned bucket
// last, so the history never depends on map iteration order.
func buildScoresView(runs []Run, showDeprecated bool) *ScoresView {
	v := &ScoresView{ShowDeprecated: showDeprecated, Total: len(runs)}
	byVersion := map[string][]Run{}
	for _, r := range runs {
		if r.Deprecated {
			v.Archived++
			if !showDeprecated {
				continue
			}
		}
		v.Runs = append(v.Runs, r)
		byVersion[r.Version] = append(byVersion[r.Version], r)
	}
	keys := make([]string, 0, len(byVersion))
	for k := range byVersion {
		if k != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if _, ok := byVersion[""]; ok {
		keys = append(keys, "")
	}
	for _, k := range keys {
		v.Groups = append(v.Groups, RunGroup{Version: k, Runs: byVersion[k]})
	}
	return v
}

// parseShowDeprecated reads the archive toggle at the request boundary.
func parseShowDeprecated(q url.Values) bool {
	s := q.Get("show_deprecated")
	return s == "1" || s == "true"
}

func add(a, b int) int { return a + b }

var funcMap = template.FuncMap{
	"pct":           pct,
	"heatClass":     heatClass,
	"shortSHA":      shortSHA,
	"maxClassCases": maxClassCases,
	"fmtRate":       fmtRate,
	"fmtMs":         fmtMs,
	"fmtCI":         fmtCI,
	"fmtDuration":   fmtDuration,
	"add":           add,
	"tacticName":    tacticName,
	"hasStr":        containsStr,
	"tierFor":       tierFor,
	"scatterSVG":    renderScatterSVG,
	"fprHeatmap":    renderFPRHeatmap,
}

type server struct {
	mu       sync.RWMutex
	data     *Data
	tmpl     *template.Template
	dataPath string
}

// reload re-reads dashboard_data.json and swaps it in atomically (SIGHUP).
// A bad file leaves the previous data serving rather than crashing the public
// instance; the error is logged for the operator.
func (s *server) reload() {
	d, err := loadData(s.dataPath)
	if err != nil {
		log.Printf("reload failed, keeping previous data: %v", err)
		return
	}
	s.mu.Lock()
	s.data = d
	s.mu.Unlock()
	log.Printf("reloaded data: corpus %s, %d cases, runs=%d",
		shortSHA(d.Meta.CorpusSHA256), d.Totals.Cases, len(d.Runs))
}

// secure wraps the mux with security headers and cache policy. No JS is used,
// so script-src is 'none'; inline style attributes (bar widths) require
// style-src 'unsafe-inline'. Static assets are immutable-ish (long cache);
// data endpoints must revalidate so a refresh is visible.
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
		switch {
		case strings.HasPrefix(r.URL.Path, "/static/"):
			h.Set("Cache-Control", "public, max-age=86400")
		case r.URL.Path == "/data.json" || r.URL.Path == "/layer.json":
			h.Set("Cache-Control", "no-cache")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) render(w http.ResponseWriter, r *http.Request, page, title, active string) {
	s.renderWith(w, r, page, title, active, nil)
}

// renderWith is render plus an optional hook that fills per-request view state
// (the /cases catalog and /case detail) from the loaded data before execution.
func (s *server) renderWith(w http.ResponseWriter, r *http.Request, page, title, active string, fill func(*PageData)) {
	s.mu.RLock()
	d := s.data
	s.mu.RUnlock()
	lang := langOf(w, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	pd := PageData{Data: d, Title: translate(lang, title), Active: active, Lang: lang}
	if fill != nil {
		fill(&pd)
	}
	if err := s.tmpl.ExecuteTemplate(w, page, pd); err != nil {
		log.Printf("render %s: %v", page, err)
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		s.render(w, r, "overview.html", "Overview", "overview")
	})
	mux.HandleFunc("/coverage", func(w http.ResponseWriter, r *http.Request) {
		s.render(w, r, "coverage.html", "Tactic coverage", "coverage")
	})
	mux.HandleFunc("/matrix", func(w http.ResponseWriter, r *http.Request) {
		s.render(w, r, "matrix.html", "Technique heatmap", "matrix")
	})
	mux.HandleFunc("/classes", func(w http.ResponseWriter, r *http.Request) {
		s.render(w, r, "classes.html", "Signal classes", "classes")
	})
	mux.HandleFunc("/cases", func(w http.ResponseWriter, r *http.Request) {
		f := parseCaseFilter(r.URL.Query())
		s.renderWith(w, r, "cases.html", "Case catalog", "cases", func(pd *PageData) {
			pd.Cases = buildCasesView(pd.Data.Cases, f)
		})
	})
	mux.HandleFunc("/case", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		s.mu.RLock()
		d := s.data
		s.mu.RUnlock()
		c, ok := findCase(d.Cases, id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		s.renderWith(w, r, "case.html", "Case "+c.ID, "cases", func(pd *PageData) {
			pd.Case = buildCaseView(d, c)
		})
	})
	mux.HandleFunc("/provisioning", func(w http.ResponseWriter, r *http.Request) {
		s.render(w, r, "provisioning.html", "Provisioning", "provisioning")
	})
	mux.HandleFunc("/scores", func(w http.ResponseWriter, r *http.Request) {
		show := parseShowDeprecated(r.URL.Query())
		s.renderWith(w, r, "scores.html", "Product scores", "scores", func(pd *PageData) {
			pd.Scores = buildScoresView(pd.Data.Runs, show)
		})
	})
	mux.HandleFunc("/fp", func(w http.ResponseWriter, r *http.Request) {
		s.renderWith(w, r, "fp.html", "False positives", "fp", func(pd *PageData) {
			pd.FP = buildFPView(pd.Data.BenignDistribution)
		})
	})
	mux.HandleFunc("/layer.json", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		layer := s.data.NavigatorLayer
		s.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(layer)
	})
	mux.HandleFunc("/data.json", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		d := s.data
		s.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		enc := json.NewEncoder(w)
		enc.SetIndent("", " ")
		_ = enc.Encode(d)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/static/", http.FileServer(http.FS(assets)))
	return secure(mux)
}

func main() {
	dataPath := flag.String("data", "dashboard_data.json",
		"path to dashboard_data.json (from tools/gen_dashboard_data.py)")
	addr := flag.String("addr", "127.0.0.1:8090", "listen address")
	flag.Parse()

	d, err := loadData(*dataPath)
	if err != nil {
		log.Fatalf("load data: %v", err)
	}
	tmpl, err := template.New("").Funcs(funcMap).ParseFS(assets, "templates/*.html")
	if err != nil {
		log.Fatalf("parse templates: %v", err)
	}
	s := &server{data: d, tmpl: tmpl, dataPath: *dataPath}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// SIGHUP reloads data (public refresh pipeline); SIGINT/SIGTERM drain.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sg := range sig {
			if sg == syscall.SIGHUP {
				s.reload()
				continue
			}
			log.Printf("shutting down (%s)", sg)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
			return
		}
	}()

	log.Printf("qinjing dashboard: corpus %s version %s, %d cases, %d/%d techniques; runs=%d",
		shortSHA(d.Meta.CorpusSHA256), d.Meta.Version, d.Totals.Cases,
		d.Meta.TechniquesCovered, d.Meta.MatrixTechniques, len(d.Runs))
	log.Printf("listening on http://%s", *addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}