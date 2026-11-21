package main

import (
	"fmt"
	"html/template"
	"sort"
	"strings"
)

// This module owns the precision-FPR tradeoff charts (learning HIDBench
// Fig.3/Fig.4). Both are server-rendered with no JavaScript: the
// scatter is an SVG built from typed points, the heatmap an HTML table of
// band-colored cells. Every dynamic string is HTML-escaped here because the
// renderers return template.HTML; numeric coordinates carry no markup.
//
// Honesty: a chart renders only what a run measured. Empty runs[] gives an
// honest empty state, never an invented plot. Per-class FPR is a forward-
// compatible slot the scorer does not emit today (benign cases carry no
// expected signal class), so real runs show N/A cells until it does.

// Scatter plot geometry (SVG user units). x maps FPR 0..1 left..right; y maps
// precision 0..1 bottom..top, so the ideal corner (high precision, low FPR) is
// top-left.
const (
	scatterW     = 560
	scatterH     = 400
	scatterPlotX = 70
	scatterPlotY = 30
	scatterPlotW = 440
	scatterPlotH = 300
)

type scatterPoint struct {
	X, Y      float64
	Label     string
	FPR       float64
	Precision float64
	Synthetic bool
}

// runPrecision is detected attack cases over detected plus FP violations, the
// case-level precision proxy. An empty denominator is nil (N/A), never zero.
func runPrecision(r Run) *float64 {
	denom := r.Detection.Hit + r.FP.Violations
	if denom == 0 {
		return nil
	}
	p := float64(r.Detection.Hit) / float64(denom)
	return &p
}

func runLabel(r Run) string {
	if r.Product != "" {
		return r.Product
	}
	if r.RunID != "" {
		return r.RunID
	}
	return "run"
}

// buildScatter keeps one point per run that has both an FPR (all-attempt tier)
// and a precision; a run missing either axis cannot be placed and is excluded.
func buildScatter(runs []Run) []scatterPoint {
	pts := make([]scatterPoint, 0, len(runs))
	for _, r := range runs {
		prec := runPrecision(r)
		if prec == nil || r.FP.AttemptRate == nil {
			continue
		}
		fpr := *r.FP.AttemptRate
		pts = append(pts, scatterPoint{
			X:         scatterPlotX + fpr*scatterPlotW,
			Y:         scatterPlotY + (1-*prec)*scatterPlotH,
			Label:     runLabel(r),
			FPR:       fpr,
			Precision: *prec,
			Synthetic: r.Synthetic,
		})
	}
	return pts
}

func renderScatterSVG(runs []Run, lang string) template.HTML {
	pts := buildScatter(runs)
	if len(pts) == 0 {
		return template.HTML(`<p class="muted chart-empty">` +
			template.HTMLEscapeString(translate(lang,
				"No run has both a precision and a false-positive rate yet; the scatter activates when a real run is scored.")) +
			`</p>`)
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="scatter" viewBox="0 0 %d %d" role="img" aria-label="%s">`,
		scatterW, scatterH,
		template.HTMLEscapeString(translate(lang, "Precision versus false-positive rate")))
	fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d" class="plot-bg"/>`,
		scatterPlotX, scatterPlotY, scatterPlotW, scatterPlotH)
	for _, f := range []float64{0, 0.25, 0.5, 0.75, 1} {
		x := scatterPlotX + f*scatterPlotW
		y := scatterPlotY + (1-f)*scatterPlotH
		fmt.Fprintf(&b, `<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" class="grid"/>`,
			x, scatterPlotY, x, scatterPlotY+scatterPlotH)
		fmt.Fprintf(&b, `<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" class="grid"/>`,
			scatterPlotX, y, scatterPlotX+scatterPlotW, y)
		fmt.Fprintf(&b, `<text x="%.1f" y="%d" class="tick tick-x">%d%%</text>`,
			x, scatterPlotY+scatterPlotH+20, int(f*100))
		fmt.Fprintf(&b, `<text x="%d" y="%.1f" class="tick tick-y">%d%%</text>`,
			scatterPlotX-8, y+4, int(f*100))
	}
	fmt.Fprintf(&b, `<line x1="%d" y1="%d" x2="%d" y2="%d" class="axis"/>`,
		scatterPlotX, scatterPlotY, scatterPlotX, scatterPlotY+scatterPlotH)
	fmt.Fprintf(&b, `<line x1="%d" y1="%d" x2="%d" y2="%d" class="axis"/>`,
		scatterPlotX, scatterPlotY+scatterPlotH, scatterPlotX+scatterPlotW, scatterPlotY+scatterPlotH)
	fmt.Fprintf(&b, `<text x="%d" y="%d" class="axis-title">%s</text>`,
		scatterPlotX+scatterPlotW/2, scatterH-12,
		template.HTMLEscapeString(translate(lang, "False-positive rate (all attempts)")))
	fmt.Fprintf(&b, `<text x="%d" y="%d" class="axis-title" transform="rotate(-90 %d %d)">%s</text>`,
		18, scatterPlotY+scatterPlotH/2, 18, scatterPlotY+scatterPlotH/2,
		template.HTMLEscapeString(translate(lang, "Precision")))
	fmt.Fprintf(&b, `<text x="%d" y="%d" class="ideal">%s</text>`,
		scatterPlotX+10, scatterPlotY+18,
		template.HTMLEscapeString(translate(lang, "ideal: high precision, low FPR")))
	for _, p := range pts {
		cls := "dot"
		if p.Synthetic {
			cls = "dot synthetic"
		}
		fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="6" class="%s"><title>%s — FPR %.0f%%, precision %.0f%%</title></circle>`,
			p.X, p.Y, cls, template.HTMLEscapeString(p.Label), p.FPR*100, p.Precision*100)
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" class="dotlabel">%s</text>`,
			p.X+9, p.Y-9, template.HTMLEscapeString(p.Label))
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

// fprBand buckets a false-positive rate into four directional bands: low FPR
// is good (light green), high FPR is bad (deep red). The direction is disclosed
// in the legend so the color scale never reads as ambiguous.
func fprBand(v float64) string {
	switch {
	case v <= 0:
		return "fpr-0"
	case v <= 0.05:
		return "fpr-1"
	case v <= 0.20:
		return "fpr-2"
	default:
		return "fpr-3"
	}
}

type heatmapCell struct {
	FPR  *float64
	Band string
}

type heatmapRow struct {
	Class string
	Cells []heatmapCell
	Mean  *float64
}

type heatmapView struct {
	RunLabels []string
	Rows      []heatmapRow
	HasData   bool
}

// buildFPRHeatmap builds the class x run FPR matrix, sorting classes by mean
// FPR descending (worst first). A nil per-class FPR is an N/A cell, excluded
// from the mean; HasData is false when no cell carries a measured FPR.
func buildFPRHeatmap(runs []Run) heatmapView {
	classSet := map[string]bool{}
	for _, r := range runs {
		for _, pc := range r.PerClass {
			classSet[pc.Class] = true
		}
	}
	fpr := map[string]map[int]*float64{}
	for ri, r := range runs {
		for _, pc := range r.PerClass {
			if fpr[pc.Class] == nil {
				fpr[pc.Class] = map[int]*float64{}
			}
			fpr[pc.Class][ri] = pc.FPR
		}
	}
	rows := make([]heatmapRow, 0, len(classSet))
	hasData := false
	for class := range classSet {
		cells := make([]heatmapCell, len(runs))
		var sum float64
		var n int
		for ri := range runs {
			v := fpr[class][ri]
			band := "fpr-na"
			if v != nil {
				band = fprBand(*v)
				sum += *v
				n++
				hasData = true
			}
			cells[ri] = heatmapCell{FPR: v, Band: band}
		}
		var mean *float64
		if n > 0 {
			m := sum / float64(n)
			mean = &m
		}
		rows = append(rows, heatmapRow{Class: class, Cells: cells, Mean: mean})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		mi, mj := rows[i].Mean, rows[j].Mean
		if mi == nil {
			return false
		}
		if mj == nil {
			return true
		}
		return *mi > *mj
	})
	labels := make([]string, len(runs))
	for i, r := range runs {
		labels[i] = runLabel(r)
	}
	return heatmapView{RunLabels: labels, Rows: rows, HasData: hasData}
}

func renderFPRHeatmap(runs []Run, lang string) template.HTML {
	if len(runs) == 0 {
		return template.HTML(`<p class="muted chart-empty">` +
			template.HTMLEscapeString(translate(lang,
				"No runs recorded yet; the FPR heatmap activates when a real run is scored.")) +
			`</p>`)
	}
	v := buildFPRHeatmap(runs)
	if !v.HasData {
		return template.HTML(`<p class="muted chart-empty">` +
			template.HTMLEscapeString(translate(lang,
				"Runs exist but no per-class false-positive rate is measured yet; the scorer aggregates FP globally. The heatmap activates when a real run is scored with per-class FPR.")) +
			`</p>`)
	}
	var b strings.Builder
	b.WriteString(`<div class="tablewrap"><table class="grid fpr-heatmap"><thead><tr><th>`)
	b.WriteString(template.HTMLEscapeString(translate(lang, "Class")))
	b.WriteString(`</th>`)
	for _, lbl := range v.RunLabels {
		fmt.Fprintf(&b, `<th class="num">%s</th>`, template.HTMLEscapeString(lbl))
	}
	fmt.Fprintf(&b, `<th class="num">%s</th></tr></thead><tbody>`,
		template.HTMLEscapeString(translate(lang, "Mean")))
	for _, row := range v.Rows {
		fmt.Fprintf(&b, `<tr><td><code>%s</code></td>`, template.HTMLEscapeString(row.Class))
		for _, cell := range row.Cells {
			if cell.FPR == nil {
				b.WriteString(`<td class="num fpr-na">N/A</td>`)
			} else {
				fmt.Fprintf(&b, `<td class="num %s">%.0f%%</td>`, cell.Band, *cell.FPR*100)
			}
		}
		if row.Mean == nil {
			b.WriteString(`<td class="num fpr-na">N/A</td>`)
		} else {
			fmt.Fprintf(&b, `<td class="num %s">%.0f%%</td>`, fprBand(*row.Mean), *row.Mean*100)
		}
		b.WriteString(`</tr>`)
	}
	b.WriteString(`</tbody></table></div>`)
	return template.HTML(b.String())
}