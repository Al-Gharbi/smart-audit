package reporter

import (
	"fmt"
	"html/template"
	"os"
	"strings"

	"github.com/Al-Gharbi/smart-audit/internal/analyzer"
)

type HTMLReporter struct{}

func (h *HTMLReporter) Generate(report *analyzer.AuditReport, outputPath string) error {
	funcMap := template.FuncMap{
		"lower":   strings.ToLower,
		"sevClass": func(sev string) string {
			switch strings.ToUpper(sev) {
			case "CRITICAL": return "sev-critical"
			case "HIGH":     return "sev-high"
			case "MEDIUM":   return "sev-medium"
			case "LOW":      return "sev-low"
			default:         return "sev-info"
			}
		},
		"sevIcon": func(sev string) string {
			switch strings.ToUpper(sev) {
			case "CRITICAL": return "⬟"
			case "HIGH":     return "▲"
			case "MEDIUM":   return "◆"
			case "LOW":      return "●"
			default:         return "○"
			}
		},
		"sevLabel": func(sev string) string {
			switch strings.ToUpper(sev) {
			case "CRITICAL": return "Critical"
			case "HIGH":     return "High"
			case "MEDIUM":   return "Medium"
			case "LOW":      return "Low"
			default:         return "Info"
			}
		},
		"hasSwc": func(s string) bool {
			return s != "" && s != "custom" && !strings.HasPrefix(s, "slither:")
		},
		"riskBar": func(score float64) int { return int(score * 10) },
		"riskClass": func(score float64) string {
			switch {
			case score >= 7: return "risk-critical"
			case score >= 4: return "risk-high"
			case score >= 2: return "risk-medium"
			default:         return "risk-low"
			}
		},
		"ovClass": func(r string) string {
			switch r {
			case "CRITICAL": return "ov-critical"
			case "HIGH":     return "ov-high"
			case "MEDIUM":   return "ov-medium"
			default:         return "ov-low"
			}
		},
		"add":        func(a, b int) int { return a + b },
		"findingNum": func(i int) string { return fmt.Sprintf("F-%02d", i+1) },
		"pct": func(n, total int) int {
			if total == 0 { return 0 }
			return (n * 100) / total
		},
	}

	tmpl, err := template.New("r").Funcs(funcMap).Parse(htmlTpl)
	if err != nil {
		return fmt.Errorf("template parse: %w", err)
	}
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()
	return tmpl.Execute(f, report)
}

const htmlTpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{{.Title}} · {{.ReportID}}</title>
<style>
:root{
  --ink:#0d0f14;--ink-m:#4a5060;--page:#f7f8fa;--srf:#ffffff;--bdr:#e2e5ec;
  --mono:'JetBrains Mono','Fira Code',monospace;
  --sans:'Inter','Segoe UI',system-ui,sans-serif;
  --cc:#c0392b;--bgc:#fff0ef;--bdc:#f5bbb8;
  --ch:#b85c00;--bgh:#fff5eb;--bdh:#f0c89a;
  --cm:#906d00;--bgm:#fffae8;--bdm:#e8d698;
  --cl:#1a5fa8;--bgl:#eef4ff;--bdl:#afc8f0;
  --ci:#3d4760;--bgi:#f1f3f8;--bdi:#c4cadb;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{font-size:15px;scroll-behavior:smooth}
body{font-family:var(--sans);background:var(--page);color:var(--ink);line-height:1.65}
.wrap{max-width:960px;margin:0 auto;padding:0 24px}

/* cover */
header{background:#0d0f14;color:#fff;padding:52px 0 44px}
.ci{max-width:960px;margin:0 auto;padding:0 24px;display:flex;align-items:flex-start;gap:32px}
.ct{flex:1}
.eye{font-size:11px;font-weight:600;letter-spacing:.14em;text-transform:uppercase;color:#8b92a8;margin-bottom:10px}
.ctitle{font-size:30px;font-weight:700;line-height:1.2;margin-bottom:16px}
.cmeta{display:flex;flex-wrap:wrap;gap:16px;font-size:12px;color:#9199b0}
.rid{font-family:var(--mono);background:#1c2033;color:#7b88b0;padding:3px 8px;border-radius:4px;font-size:11px}
.obadge{display:flex;flex-direction:column;align-items:center;justify-content:center;
  min-width:110px;border-radius:10px;padding:14px 18px;text-align:center;font-weight:700;flex-shrink:0}
.ov-critical{background:var(--cc);color:#fff}
.ov-high{background:var(--ch);color:#fff}
.ov-medium{background:var(--cm);color:#fff}
.ov-low{background:var(--cl);color:#fff}
.obadge .lbl{font-size:10px;text-transform:uppercase;letter-spacing:.1em;opacity:.8;margin-bottom:4px}
.obadge .val{font-size:18px}

/* sections */
section{padding:36px 0}
section+section{border-top:1px solid var(--bdr)}
.stitle{font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--ink-m);margin-bottom:20px}

/* cards */
.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:28px}
.card{border-radius:8px;border:1px solid var(--bdr);padding:16px 14px 12px;background:var(--srf)}
.cnum{font-size:32px;font-weight:700;line-height:1;font-variant-numeric:tabular-nums;margin-bottom:5px}
.clbl{font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--ink-m)}
.c-critical .cnum{color:var(--cc)} .c-high .cnum{color:var(--ch)}
.c-medium .cnum{color:var(--cm)}   .c-low .cnum{color:var(--cl)}
.c-info .cnum{color:var(--ci)}

/* sev bar */
.sbar-track{height:7px;border-radius:4px;background:var(--bdr);overflow:hidden;display:flex}
.sbar-track span{height:100%}
.bc{background:var(--cc)} .bh{background:var(--ch)}
.bm{background:var(--cm)} .bl{background:var(--cl)} .bi{background:#c4cadb}
.sleg{display:flex;flex-wrap:wrap;gap:10px;margin-top:7px;font-size:11px;color:var(--ink-m)}
.sleg span{display:flex;align-items:center;gap:4px}
.sdot{width:8px;height:8px;border-radius:50%;display:inline-block}

/* scope table */
.stbl{width:100%;border-collapse:collapse;font-size:13px}
.stbl th{background:#f1f3f7;text-align:left;padding:9px 14px;font-size:11px;font-weight:700;
  text-transform:uppercase;letter-spacing:.06em;color:var(--ink-m);border-bottom:1px solid var(--bdr)}
.stbl td{padding:11px 14px;border-bottom:1px solid var(--bdr);vertical-align:middle}
.stbl tr:last-child td{border-bottom:none}
.stbl tbody tr:hover{background:#f8f9fc}
.fname{font-family:var(--mono);font-size:12px}
.sver{font-family:var(--mono);font-size:11px;background:#f1f3f7;padding:2px 6px;border-radius:3px}
.rpill{display:inline-flex;align-items:center;gap:5px;font-size:11px;font-weight:700;
  padding:3px 9px;border-radius:20px;white-space:nowrap}
.risk-critical{background:var(--bgc);color:var(--cc);border:1px solid var(--bdc)}
.risk-high    {background:var(--bgh);color:var(--ch);border:1px solid var(--bdh)}
.risk-medium  {background:var(--bgm);color:var(--cm);border:1px solid var(--bdm)}
.risk-low     {background:var(--bgl);color:var(--cl);border:1px solid var(--bdl)}
.mbar{width:56px;height:5px;border-radius:3px;background:var(--bdr);overflow:hidden;display:inline-block;vertical-align:middle;margin-left:5px}
.mbf{height:100%;border-radius:3px;background:currentColor}

/* findings */
.cb{margin-bottom:32px}
.ch{display:flex;align-items:center;gap:12px;margin-bottom:14px;padding-bottom:12px;border-bottom:2px solid var(--bdr)}
.cicon{width:34px;height:34px;border-radius:8px;background:#1c2033;color:#8b92a8;
  font-size:15px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.cname{font-family:var(--mono);font-size:14px;font-weight:600}
.cstat{font-size:12px;color:var(--ink-m);margin-top:2px}
.noiss{padding:16px;border-radius:8px;background:#f0faf4;border:1px solid #b2e0c4;
  font-size:13px;color:#1a6b3a;display:flex;align-items:center;gap:8px}

details.finding{border:1px solid var(--bdr);border-radius:10px;overflow:hidden;margin-bottom:12px;background:var(--srf)}
details[open] summary{border-bottom:1px solid var(--bdr)}
summary.fhead{padding:14px 18px;display:flex;align-items:flex-start;gap:12px;
  cursor:pointer;list-style:none}
summary.fhead::-webkit-details-marker{display:none}
.sbadge{display:inline-flex;align-items:center;gap:5px;font-size:11px;font-weight:700;
  padding:4px 10px;border-radius:5px;white-space:nowrap;flex-shrink:0}
.sev-critical{background:var(--bgc);color:var(--cc);border:1px solid var(--bdc)}
.sev-high    {background:var(--bgh);color:var(--ch);border:1px solid var(--bdh)}
.sev-medium  {background:var(--bgm);color:var(--cm);border:1px solid var(--bdm)}
.sev-low     {background:var(--bgl);color:var(--cl);border:1px solid var(--bdl)}
.sev-info    {background:var(--bgi);color:var(--ci);border:1px solid var(--bdi)}
.ftw{flex:1;min-width:0}
.fid{font-size:11px;font-family:var(--mono);color:var(--ink-m);margin-bottom:3px}
.ftitle{font-size:14px;font-weight:600}
.floc{font-size:11px;font-family:var(--mono);color:var(--ink-m);margin-top:3px}
.chev{font-size:11px;color:var(--ink-m);flex-shrink:0;margin-top:4px;transition:transform .2s}
details[open] .chev{transform:rotate(180deg)}
.swctag{display:inline-block;font-family:var(--mono);font-size:10px;padding:1px 6px;
  border-radius:3px;background:#f1f3f7;border:1px solid var(--bdr);color:var(--ink-m);
  text-decoration:none;margin-left:5px}
.swctag:hover{background:var(--ink);color:#fff}

.fbody{padding:18px}
.flbl{font-size:10px;font-weight:700;letter-spacing:.09em;text-transform:uppercase;
  color:var(--ink-m);margin-bottom:6px}
.fblk{margin-bottom:16px}
.fblk:last-child{margin-bottom:0}
.fdesc{font-size:13px;line-height:1.7}
.codebox{background:#0d1117;border-radius:8px;padding:14px;overflow-x:auto;margin-top:2px}
.codebox pre{font-family:var(--mono);font-size:12px;line-height:1.7;color:#cdd9e5;margin:0}
.rec{background:#f4f8ff;border-left:3px solid var(--cl);border-radius:0 8px 8px 0;
  padding:11px 15px;font-size:13px;line-height:1.6}
.refs{display:flex;flex-direction:column;gap:5px}
.refs a{font-size:12px;color:var(--cl);text-decoration:none;font-family:var(--mono)}
.refs a:hover{text-decoration:underline}

footer{text-align:center;padding:36px 0;font-size:12px;color:var(--ink-m);border-top:1px solid var(--bdr)}
footer a{color:inherit}
@media print{details{display:block}summary{display:none}.fbody{display:block!important}
  header{background:#000!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
</style>
</head>
<body>
<header>
  <div class="ci">
    <div class="ct">
      <div class="eye">Automated Security Assessment</div>
      <h1 class="ctitle">{{.Title}}</h1>
      <div class="cmeta">
        <span>📅 {{.Timestamp}}</span>
        <span>⏱ {{.Duration}}</span>
        <span>🔧 smart-audit v{{.Version}}</span>
        <span class="rid">{{.ReportID}}</span>
      </div>
    </div>
    <div class="obadge {{ovClass .Summary.OverallRisk}}">
      <div class="lbl">Overall Risk</div>
      <div class="val">{{.Summary.OverallRisk}}</div>
    </div>
  </div>
</header>

<div class="wrap">

<section>
  <div class="stitle">Executive Summary</div>
  <div class="cards">
    <div class="card c-critical"><div class="cnum">{{.Summary.Critical}}</div><div class="clbl">Critical</div></div>
    <div class="card c-high">   <div class="cnum">{{.Summary.High}}</div>    <div class="clbl">High</div></div>
    <div class="card c-medium"> <div class="cnum">{{.Summary.Medium}}</div>  <div class="clbl">Medium</div></div>
    <div class="card c-low">    <div class="cnum">{{.Summary.Low}}</div>     <div class="clbl">Low</div></div>
    <div class="card c-info">   <div class="cnum">{{.Summary.Info}}</div>    <div class="clbl">Info</div></div>
  </div>
  {{if gt .Summary.TotalFindings 0}}
  <div class="sbar-track">
    <span class="bc" style="width:{{pct .Summary.Critical .Summary.TotalFindings}}%"></span>
    <span class="bh" style="width:{{pct .Summary.High     .Summary.TotalFindings}}%"></span>
    <span class="bm" style="width:{{pct .Summary.Medium   .Summary.TotalFindings}}%"></span>
    <span class="bl" style="width:{{pct .Summary.Low      .Summary.TotalFindings}}%"></span>
    <span class="bi" style="width:{{pct .Summary.Info     .Summary.TotalFindings}}%"></span>
  </div>
  <div class="sleg">
    <span><span class="sdot" style="background:var(--cc)"></span>Critical</span>
    <span><span class="sdot" style="background:var(--ch)"></span>High</span>
    <span><span class="sdot" style="background:var(--cm)"></span>Medium</span>
    <span><span class="sdot" style="background:var(--cl)"></span>Low</span>
    <span><span class="sdot" style="background:#c4cadb"></span>Info</span>
  </div>
  {{end}}
</section>

<section>
  <div class="stitle">Scope — {{.Summary.TotalContracts}} Contract(s)</div>
  <table class="stbl">
    <thead><tr><th>Contract</th><th>Solidity</th><th>LOC</th><th>Findings</th><th>Risk Score</th></tr></thead>
    <tbody>
    {{range .Contracts}}
    <tr>
      <td><span class="fname">📄 {{.FileName}}</span></td>
      <td><span class="sver">{{.SolidityVersion}}</span></td>
      <td>{{.LinesOfCode}}</td>
      <td>{{len .Findings}}</td>
      <td>
        <span class="rpill {{riskClass .RiskScore}}">
          {{printf "%.1f" .RiskScore}}/10
          <span class="mbar"><span class="mbf" style="width:{{riskBar .RiskScore}}%"></span></span>
        </span>
      </td>
    </tr>
    {{end}}
    </tbody>
  </table>
</section>

<section>
  <div class="stitle">Findings</div>
  {{range .Contracts}}
  <div class="cb">
    <div class="ch">
      <div class="cicon">📄</div>
      <div>
        <div class="cname">{{.FileName}}</div>
        <div class="cstat">{{.LinesOfCode}} LOC · Solidity {{.SolidityVersion}} · Risk {{printf "%.1f" .RiskScore}}/10</div>
      </div>
    </div>
    {{if eq (len .Findings) 0}}
      <div class="noiss">✅ No vulnerabilities detected in this contract.</div>
    {{else}}
      {{range $i,$f := .Findings}}
      <details class="finding">
        <summary class="fhead">
          <span class="sbadge {{sevClass $f.Severity}}">{{sevIcon $f.Severity}} {{sevLabel $f.Severity}}</span>
          <div class="ftw">
            <div class="fid">
              {{findingNum $i}} · {{$f.ID}}
              {{if hasSwc $f.SWC}}
              <a class="swctag" href="https://swcregistry.io/docs/{{$f.SWC}}" target="_blank" rel="noopener">{{$f.SWC}}</a>
              {{end}}
            </div>
            <div class="ftitle">{{$f.Title}}</div>
            <div class="floc">{{$f.File}}:{{$f.Line}}</div>
          </div>
          <span class="chev">▾</span>
        </summary>
        <div class="fbody">
          <div class="fblk">
            <div class="flbl">Description</div>
            <div class="fdesc">{{$f.Description}}</div>
          </div>
          {{if $f.CodeSnippet}}
          <div class="fblk">
            <div class="flbl">Vulnerable Code — line {{$f.Line}}</div>
            <div class="codebox"><pre>{{$f.CodeSnippet}}</pre></div>
          </div>
          {{end}}
          <div class="fblk">
            <div class="flbl">Recommendation</div>
            <div class="rec">{{$f.Recommendation}}</div>
          </div>
          {{if $f.References}}
          <div class="fblk">
            <div class="flbl">References</div>
            <div class="refs">{{range $f.References}}<a href="{{.}}" target="_blank" rel="noopener">→ {{.}}</a>{{end}}</div>
          </div>
          {{end}}
        </div>
      </details>
      {{end}}
    {{end}}
  </div>
  {{end}}
</section>
</div>

<footer>
  <p>Generated by <a href="https://github.com/Al-Gharbi/smart-audit">smart-audit</a> — Automated static analysis for Solidity.</p>
  <p style="margin-top:5px;font-size:11px">⚠ Automated analysis complements but does not replace manual audit. Review all findings before mainnet deployment.</p>
</footer>
</body>
</html>`
