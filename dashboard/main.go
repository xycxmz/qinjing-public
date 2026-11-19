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
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"sync"
)

//go:embed templates static
var assets embed.FS

// tacticNames maps ATT&CK tactic ids to display names for the pinned matrix
// (v20.1). Names verified against attack.mitre.org:
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
	Class      string `json:"class"`
	Cases      int    `json:"cases"`
	Detectable int    `json:"detectable"`
	Gap        int    `json:"gap"`
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
	SignalRate       *float64 `json:"signal_rate"`
	StrictRate       *float64 `json:"strict_rate"`
	AnyhitRate       *float64 `json:"anyhit_rate"`
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
}

type RunClassRow struct {
	Class           string   `json:"class"`
	Cases           int      `json:"cases"`
	Detected        int      `json:"detected"`
	Missed          int      `json:"missed"`
	MedianLatencyMs *float64 `json:"median_latency_ms"`
	TechTagged      int      `json:"tech_tagged"`
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
	PerClass    []RunClassRow `json:"per_class"`
	ByTactic    []RunAggRow   `json:"by_tactic"`
	ByTechnique []RunAggRow   `json:"by_technique"`
}

// Data mirrors dashboard_data.json. NavigatorLayer is kept
// raw so /layer.json serves the exact bytes the Python toolchain emitted.
type Data struct {
	Meta              Meta            `json:"meta"`
	Totals            Totals          `json:"totals"`
	TacticCoverage    []TacticRow     `json:"tactic_coverage"`
	TechniqueHeatmap  []TechRow       `json:"technique_heatmap"`
	ClassDistribution []ClassRow      `json:"class_distribution"`
	Provisioning      Provisioning    `json:"provisioning"`
	NavigatorLayer    json.RawMessage `json:"navigator_layer"`
	NavigatorLayerURL string          `json:"navigator_layer_url"`
	Runs              []Run           `json:"runs"`
}

type PageData struct {
	Data   *Data
	Title  string
	Active string
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

var funcMap = template.FuncMap{
	"pct":           pct,
	"heatClass":     heatClass,
	"shortSHA":      shortSHA,
	"maxClassCases": maxClassCases,
	"fmtRate":       fmtRate,
	"fmtMs":         fmtMs,
}

type server struct {
	mu   sync.RWMutex
	data *Data
	tmpl *template.Template
}

func (s *server) render(w http.ResponseWriter, page, title, active string) {
	s.mu.RLock()
	d := s.data
	s.mu.RUnlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	pd := PageData{Data: d, Title: title, Active: active}
	if err := s.tmpl.ExecuteTemplate(w, page, pd); err != nil {
		log.Printf("render %s: %v", page, err)
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

func (s *server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		s.render(w, "overview.html", "Overview", "overview")
	})
	mux.HandleFunc("/coverage", func(w http.ResponseWriter, r *http.Request) {
		s.render(w, "coverage.html", "Tactic coverage", "coverage")
	})
	mux.HandleFunc("/matrix", func(w http.ResponseWriter, r *http.Request) {
		s.render(w, "matrix.html", "Technique heatmap", "matrix")
	})
	mux.HandleFunc("/classes", func(w http.ResponseWriter, r *http.Request) {
		s.render(w, "classes.html", "Signal classes", "classes")
	})
	mux.HandleFunc("/provisioning", func(w http.ResponseWriter, r *http.Request) {
		s.render(w, "provisioning.html", "Provisioning", "provisioning")
	})
	mux.HandleFunc("/scores", func(w http.ResponseWriter, r *http.Request) {
		s.render(w, "scores.html", "Product scores", "scores")
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
	return mux
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
	s := &server{data: d, tmpl: tmpl}

	log.Printf("qinjing dashboard: corpus %s version %s, %d cases, %d/%d techniques; runs=%d",
		shortSHA(d.Meta.CorpusSHA256), d.Meta.Version, d.Totals.Cases,
		d.Meta.TechniquesCovered, d.Meta.MatrixTechniques, len(d.Runs))
	log.Printf("listening on http://%s", *addr)
	if err := http.ListenAndServe(*addr, s.routes()); err != nil {
		log.Fatal(err)
	}
}