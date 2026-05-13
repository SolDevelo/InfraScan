/* InfraScan PDF Report Generator
 * Generates a standalone, beautifully formatted HTML document in a popup window
 * and triggers window.print() so the user can save it as PDF.
 */
function buildPdfDocument(results, summary, metadata, gradeReport) {
    const esc = (t) => t == null ? '' : String(t)
        .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

    // ── Meta ──────────────────────────────────────────────────────────────────
    const repoName  = esc(metadata?.repository_name || metadata?.repository_url || '—');
    const repoUrl   = esc(metadata?.repository_url  || '');
    const branch    = esc(metadata?.branch           || 'default');
    const scanDate  = esc(metadata?.scan_timestamp   || new Date().toLocaleString());
    const resources = esc(metadata?.resource_count   || '—');
    const scannerLabel = {
        comprehensive: 'Comprehensive (Cost + Security + Containers)',
        regex:         'Fast — Cost Optimization Only',
        checkov:       'Security — IaC Security Only',
        containers:    'Containers — Container Vulnerabilities Only',
    }[summary?.scanner_used] || esc(summary?.scanner_used || '—');

    // Detect container scanner from findings
    const containerScannerName =
        results.some(r => r.scanner === 'grype')        ? 'Grype' :
        results.some(r => r.scanner === 'docker-scout') ? 'Docker Scout' : null;

    // ── Split findings ────────────────────────────────────────────────────────
    const costResults      = results.filter(r => r.scanner === 'regex');
    const iacResults       = results.filter(r => r.scanner === 'checkov');
    const containerResults = results.filter(r => r.scanner === 'grype' || r.scanner === 'docker-scout');

    // Group by rule_id, deduplicated
    function groupByRule(arr) {
        const map = {};
        arr.forEach(f => {
            const k = f.rule_id || f.rule_name;
            if (!map[k]) map[k] = [];
            if (!map[k].some(e => e.file === f.file && e.line === f.line && e.match_content === f.match_content))
                map[k].push(f);
        });
        const order = {Critical:0,High:1,Medium:2,Low:3,Info:4};
        return Object.entries(map).sort(([,a],[,b]) =>
            (order[a[0].severity]||9) - (order[b[0].severity]||9));
    }

    const costGroups = groupByRule(costResults);
    const iacGroups  = groupByRule(iacResults);

    // Container: group by image
    const imageMap = {};
    containerResults.forEach(f => {
        const img = f.image || 'Unknown Image';
        if (!imageMap[img]) imageMap[img] = [];
        imageMap[img].push(f);
    });

    // ── Helpers ───────────────────────────────────────────────────────────────
    const SEV_FG = {Critical:'#B91C1C',High:'#C2410C',Medium:'#B45309',Low:'#475569',Info:'#64748B'};
    const SEV_BG = {Critical:'#FEE2E2',High:'#FFEDD5',Medium:'#FEF3C7',Low:'#F1F5F9',Info:'#F8FAFC'};
    const sevBadge = (s) =>
        `<span style="display:inline-block;padding:1px 7px;border-radius:99px;font-size:0.7rem;font-weight:700;background:${SEV_BG[s]||'#F1F5F9'};color:${SEV_FG[s]||'#475569'};">${esc(s)}</span>`;

    const GRADE_COLOR = {A:'#059669',B:'#2563EB',C:'#D97706',D:'#EF4444',F:'#B91C1C'};
    const gc = (l) => GRADE_COLOR[l] || '#64748B';

    const trunc = (t, n=120) => t ? (t.length > n ? t.substring(0,n)+'…' : t) : '';

    // ── Grade cards ───────────────────────────────────────────────────────────
    function gradeCard(label, g, icon, accent) {
        if (!g) return '';
        const sb = g.severity_breakdown || {};
        return `<div style="flex:1;min-width:130px;border:1.5px solid #E2E8F0;border-top:4px solid ${accent};border-radius:8px;padding:14px 10px;text-align:center;">
            <div style="font-size:1.6rem;line-height:1;">${icon}</div>
            <div style="font-size:0.65rem;text-transform:uppercase;letter-spacing:.07em;color:#64748B;font-weight:700;margin:6px 0 8px;">${label}</div>
            <div style="font-size:2.4rem;font-weight:900;color:${accent};line-height:1;">${esc(g.letter)}</div>
            <div style="font-size:0.8rem;color:#64748B;margin-top:4px;">${g.percentage}%</div>
            <div style="font-size:0.72rem;color:#94A3B8;margin-top:3px;">${g.violations} issues</div>
            <div style="margin-top:7px;font-size:0.7rem;line-height:1.8;">
                ${sb.critical>0 ? `<span style="color:#B91C1C;font-weight:700;">${sb.critical} Crit </span>` : ''}
                ${sb.high>0     ? `<span style="color:#C2410C;font-weight:700;">${sb.high} High </span>` : ''}
                ${sb.medium>0   ? `<span style="color:#B45309;font-weight:700;">${sb.medium} Med </span>` : ''}
                ${sb.low>0      ? `<span style="color:#475569;font-weight:700;">${sb.low} Low</span>` : ''}
            </div>
        </div>`;
    }

    const gradesSection = gradeReport ? `
<section class="section">
  <h2 class="section-title" style="color:#1E293B;">📊 Infrastructure Report Card</h2>
  <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px;">
    ${gradeCard('Overall',   gradeReport.overall,   '🎯', gc(gradeReport.overall?.letter))}
    ${gradeCard('Cost',      gradeReport.cost,      '💰', '#059669')}
    ${gradeCard('IaC Security', gradeReport.security,'🔒', '#4F46E5')}
    ${gradeReport.container ? gradeCard('Containers', gradeReport.container,'🐳','#2563EB') : ''}
  </div>
  ${(gradeReport.analysis?.recommendations?.length > 0) ? `
  <div class="infobox">
    <div class="infobox-title">💡 Key Recommendations</div>
    <ul style="margin:6px 0 0 0;padding-left:18px;">
      ${gradeReport.analysis.recommendations.map(r=>`<li style="margin-bottom:3px;">${esc(r)}</li>`).join('')}
    </ul>
  </div>` : ''}
</section>` : '';

    // ── Cost table ────────────────────────────────────────────────────────────
    const TH = (txt, w='') =>
        `<th style="text-align:left;padding:7px 8px;font-weight:700;${w?'width:'+w+';':''}">${txt}</th>`;

    function costTable() {
        if (costGroups.length === 0) return showIaC() || containerScannerName ? `
<section class="section">
  <h2 class="section-title" style="color:#059669;">💰 Cost Optimization</h2>
  <div class="empty-box">✅ No cost issues found.</div>
</section>` : '';

        const rows = costGroups.map(([,findings],i) => {
            const f = findings[0];
            const bg = i%2 ? '#F8FFF9' : '#FFFFFF';
            const files = findings.slice(0,3).map(fi =>
                `<div class="cell-small" title="${esc(fi.file)}">${esc(trunc(fi.file,50))}${fi.line?':'+fi.line:''}</div>`).join('')
                + (findings.length>3 ? `<div class="cell-small muted">+${findings.length-3} more…</div>` : '');
            return `<tr style="background:${bg};">
              <td class="td"><div class="rule-name">${esc(f.rule_name)}</div><div class="cell-small muted">${esc(trunc(f.description))}</div></td>
              <td class="td" style="text-align:center;">${sevBadge(f.severity)}</td>
              <td class="td" style="text-align:center;font-weight:700;">${findings.length}</td>
              <td class="td"><span style="font-weight:700;color:#059669;">${esc(f.estimated_savings||'—')}</span></td>
              <td class="td"><div class="cell-small">${esc(trunc(f.remediation,140))}</div>${files}</td>
            </tr>`;
        }).join('');

        return `<section class="section">
  <h2 class="section-title" style="color:#059669;">💰 Cost Optimization — ${costGroups.length} rules, ${costResults.length} occurrences</h2>
  <table class="data-table" style="--hdr:#F0FDF4;--hdr-bdr:#A7F3D0;--hdr-fg:#166534;">
    <thead><tr style="background:var(--hdr);border-bottom:2px solid var(--hdr-bdr);">
      ${TH('Rule / Description','30%')}${TH('Severity','9%')}${TH('Files','6%')}${TH('Savings','12%')}${TH('Fix & Locations')}
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>
</section>`;
    }

    // ── IaC Security table ────────────────────────────────────────────────────
    function showIaC() { return iacResults.length > 0 || summary?.scanner_used === 'checkov' || summary?.scanner_used === 'comprehensive'; }

    function iacTable() {
        if (!showIaC() && iacGroups.length === 0) return '';
        if (iacGroups.length === 0) return `
<section class="section">
  <h2 class="section-title" style="color:#4F46E5;">🔒 IaC Security</h2>
  <div class="empty-box">✅ No IaC security issues found.</div>
</section>`;

        const rows = iacGroups.map(([ruleId,findings],i) => {
            const f = findings[0];
            const bg = i%2 ? '#F8F9FF' : '#FFFFFF';
            const resources = findings.slice(0,4).map(fi => {
                const res = fi.match_content?.startsWith('Resource: ')
                    ? fi.match_content.replace('Resource: ','')
                    : `${fi.file}${fi.line?':'+fi.line:''}`;
                return `<div class="cell-small">${esc(trunc(res,60))}</div>`;
            }).join('') + (findings.length>4?`<div class="cell-small muted">+${findings.length-4} more…</div>`:'');
            return `<tr style="background:${bg};">
              <td class="td" style="font-family:monospace;font-size:0.72rem;white-space:nowrap;">${esc(ruleId)}</td>
              <td class="td"><div class="rule-name">${esc(f.rule_name)}</div><div class="cell-small muted">${esc(trunc(f.description))}</div></td>
              <td class="td" style="text-align:center;">${sevBadge(f.severity)}</td>
              <td class="td" style="text-align:center;font-weight:700;">${findings.length}</td>
              <td class="td">${resources}</td>
              <td class="td"><div class="cell-small">${esc(trunc(f.remediation,130))}</div></td>
            </tr>`;
        }).join('');

        return `<section class="section">
  <h2 class="section-title" style="color:#4F46E5;">🔒 IaC Security — ${iacGroups.length} checks, ${iacResults.length} occurrences</h2>
  <table class="data-table" style="--hdr:#EEF2FF;--hdr-bdr:#C7D2FE;--hdr-fg:#3730A3;">
    <thead><tr style="background:var(--hdr);border-bottom:2px solid var(--hdr-bdr);">
      ${TH('Check ID','10%')}${TH('Check Name','24%')}${TH('Severity','9%')}${TH('Hits','5%')}${TH('Resources','22%')}${TH('Fix')}
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>
</section>`;
    }

    // ── Container Security table ──────────────────────────────────────────────
    function containerTable() {
        if (!containerScannerName && containerResults.length === 0) return '';
        if (containerResults.length === 0) return `
<section class="section">
  <h2 class="section-title" style="color:#2563EB;">🐳 Container Security</h2>
  <div class="empty-box">✅ No container vulnerabilities found.</div>
</section>`;

        const sortedImages = Object.entries(imageMap).sort((a,b) => {
            const val = {Critical:4,High:3,Medium:2,Low:1,Info:0};
            const worstOf = arr => Math.max(...arr.map(f=>val[f.severity]||0));
            return worstOf(b[1]) - worstOf(a[1]);
        });

        const rows = sortedImages.flatMap(([image, vulns],imgIdx) => {
            const ordered = [...vulns].sort((a,b)=>{
                const v={Critical:4,High:3,Medium:2,Low:1,Info:0};
                return (v[b.severity]||0)-(v[a.severity]||0);
            });
            const imgBg = imgIdx%2 ? '#EFF6FF' : '#F0F9FF';
            const imgRow = `<tr>
              <td class="td img-cell" colspan="5" style="background:${imgBg};font-weight:700;color:#1E40AF;padding:8px 10px;">
                🐳 ${esc(image)}
                <span style="font-weight:400;color:#64748B;font-size:0.75rem;margin-left:8px;">${vulns.length} vulnerabilities</span>
                ${containerScannerName ? `<span style="font-weight:400;color:#94A3B8;font-size:0.72rem;margin-left:6px;">via ${esc(containerScannerName)}</span>` : ''}
              </td>
            </tr>`;
            const cveRows = ordered.map(v => `<tr>
              <td class="td" style="font-family:monospace;font-size:0.72rem;white-space:nowrap;">${esc(v.rule_id||'—')}</td>
              <td class="td"><div class="rule-name">${esc(v.package)}</div><div class="cell-small muted">v${esc(v.package_version)}</div></td>
              <td class="td" style="text-align:center;">${sevBadge(v.severity)}</td>
              <td class="td" style="font-size:0.72rem;">${v.fix_version && v.fix_version!=='N/A' ? `<span style="color:#059669;font-weight:700;">→ ${esc(v.fix_version)}</span>` : '<span class="muted">No fix yet</span>'}</td>
              <td class="td"><div class="cell-small muted">${esc(trunc(v.description,100))}</div></td>
            </tr>`).join('');
            return [imgRow, cveRows];
        }).join('');

        return `<section class="section">
  <h2 class="section-title" style="color:#2563EB;">🐳 Container Security — ${containerResults.length} vulnerabilities in ${Object.keys(imageMap).length} image(s)${containerScannerName ? ` · Scanner: <span style="font-weight:600;">${esc(containerScannerName)}</span>` : ''}</h2>
  <table class="data-table" style="--hdr:#EFF6FF;--hdr-bdr:#BFDBFE;--hdr-fg:#1E40AF;">
    <thead><tr style="background:var(--hdr);border-bottom:2px solid var(--hdr-bdr);">
      ${TH('CVE / ID','12%')}${TH('Package','18%')}${TH('Severity','9%')}${TH('Fix Version','12%')}${TH('Description')}
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>
</section>`;
    }

    // ── Assemble full document ────────────────────────────────────────────────
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>InfraScan Report — ${repoName}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', system-ui, sans-serif;
    font-size: 12px;
    color: #1E293B;
    background: #FFFFFF;
    padding: 28px 32px;
    line-height: 1.5;
  }
  @page { size: A4 portrait; margin: 12mm 10mm 16mm 10mm; }
  @media print {
    body { padding: 0; }
    .no-print { display: none !important; }
    section { page-break-inside: avoid; }
    tr { page-break-inside: avoid; }
  }

  /* ── Header ── */
  .pdf-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 3px solid #4F46E5;
    padding-bottom: 14px;
    margin-bottom: 20px;
  }
  .pdf-logo-block { display: flex; align-items: center; gap: 12px; }
  .pdf-logo-name {
    font-size: 1.6rem;
    font-weight: 900;
    background: linear-gradient(135deg, #4F46E5, #818CF8);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    letter-spacing: -0.5px;
  }
  .pdf-logo-tag {
    font-size: 0.7rem;
    color: #64748B;
    font-weight: 500;
    letter-spacing: 0.05em;
    text-transform: uppercase;
  }
  .pdf-report-title {
    font-size: 0.8rem;
    font-weight: 600;
    color: #4F46E5;
    text-align: right;
  }
  .pdf-soldevelo {
    font-size: 0.72rem;
    color: #94A3B8;
    text-align: right;
    margin-top: 2px;
  }

  /* ── Sections ── */
  .section { margin-bottom: 24px; }
  .section-title {
    font-size: 0.9rem;
    font-weight: 700;
    padding-bottom: 6px;
    border-bottom: 2px solid #E2E8F0;
    margin-bottom: 12px;
  }

  /* ── Metadata table ── */
  .meta-table { width: 100%; border-collapse: collapse; margin-bottom: 0; }
  .meta-table td { padding: 5px 10px; font-size: 0.78rem; border-bottom: 1px solid #F1F5F9; }
  .meta-table td:first-child { color: #64748B; font-weight: 600; width: 160px; white-space: nowrap; }
  .meta-table td:last-child  { color: #1E293B; }
  .meta-table tr:last-child td { border-bottom: none; }

  /* ── Data tables ── */
  .data-table { width: 100%; border-collapse: collapse; font-size: 0.75rem; }
  .data-table thead th { padding: 7px 8px; color: var(--hdr-fg); font-weight: 700; }
  .data-table tbody tr { border-bottom: 1px solid #F1F5F9; }
  .data-table tbody tr:last-child { border-bottom: none; }
  .td { padding: 6px 8px; vertical-align: top; }
  .rule-name { font-weight: 600; color: #1E293B; margin-bottom: 2px; }
  .cell-small { font-size: 0.7rem; color: #475569; line-height: 1.4; }
  .muted { color: #94A3B8 !important; }
  .img-cell { border-top: 2px solid #BFDBFE; }

  /* ── Info box ── */
  .infobox {
    background: #F8FAFC;
    border: 1px solid #E2E8F0;
    border-left: 4px solid #4F46E5;
    border-radius: 6px;
    padding: 10px 14px;
    font-size: 0.78rem;
    color: #475569;
  }
  .infobox-title { font-weight: 700; color: #1E293B; margin-bottom: 4px; }
  .empty-box {
    background: #F8FAFC;
    border: 1px dashed #CBD5E1;
    border-radius: 6px;
    padding: 14px;
    text-align: center;
    color: #64748B;
    font-size: 0.8rem;
  }

  /* ── Footer ── */
  .pdf-footer {
    margin-top: 28px;
    padding-top: 10px;
    border-top: 1px solid #E2E8F0;
    font-size: 0.7rem;
    color: #94A3B8;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  /* ── Print button (hidden in print) ── */
  .print-btn {
    position: fixed; bottom: 24px; right: 24px;
    background: #4F46E5; color: #fff; border: none;
    border-radius: 8px; padding: 10px 20px;
    font-size: 0.85rem; font-weight: 700;
    cursor: pointer; box-shadow: 0 4px 12px rgba(79,70,229,.4);
    transition: background .2s;
  }
  .print-btn:hover { background: #4338CA; }
</style>
</head>
<body>

<!-- ── HEADER ── -->
<header class="pdf-header">
  <div class="pdf-logo-block">
    <div>
      <div class="pdf-logo-name">🔍 InfraScan</div>
      <div class="pdf-logo-tag">Infrastructure Security Report</div>
    </div>
  </div>
  <div>
    <div class="pdf-report-title">${repoName}</div>
    <div class="pdf-soldevelo">by SolDevelo · infrascan.soldevelo.com</div>
  </div>
</header>

<!-- ── SCAN METADATA ── -->
<section class="section">
  <h2 class="section-title" style="color:#1E293B;">📋 Scan Information</h2>
  <table class="meta-table">
    <tr><td>Repository</td><td><a href="${repoUrl}" style="color:#4F46E5;text-decoration:none;">${repoName}</a></td></tr>
    <tr><td>Branch</td><td>${branch}</td></tr>
    <tr><td>Scan Date</td><td>${scanDate}</td></tr>
    <tr><td>Analysis Scope</td><td>${scannerLabel}</td></tr>
    ${containerScannerName ? `<tr><td>Container Scanner</td><td>${esc(containerScannerName)}</td></tr>` : ''}
    <tr><td>Resources Scanned</td><td>${resources}</td></tr>
    <tr><td>Total Findings</td><td><strong>${results.length}</strong>
      (${costResults.length} Cost · ${iacResults.length} IaC Security · ${containerResults.length} Container)</td></tr>
  </table>
</section>

<!-- ── GRADE REPORT CARD ── -->
${gradesSection}

<!-- ── COST FINDINGS ── -->
${costTable()}

<!-- ── IAC SECURITY FINDINGS ── -->
${iacTable()}

<!-- ── CONTAINER SECURITY FINDINGS ── -->
${containerTable()}

<!-- ── FOOTER ── -->
<div class="pdf-footer">
  <span>Generated by <strong>InfraScan</strong> · <a href="https://infrascan.soldevelo.com" style="color:#4F46E5;text-decoration:none;">infrascan.soldevelo.com</a></span>
  <span>© 2026 <a href="https://soldevelo.com" style="color:#4F46E5;text-decoration:none;">SolDevelo</a> · ${scanDate}</span>
</div>

<!-- ── PRINT BUTTON (hidden when printing) ── -->
<button class="print-btn no-print" onclick="window.print()">⬇ Save as PDF</button>

</body>
</html>`;
}
