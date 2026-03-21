/**
 * Dashboard Component — Premium Advanced Analytics View
 */
const Dashboard = {
  report: null,

  render(report) {
    this.report = report;
    document.getElementById('results-target-title').textContent = report.target;
    this.renderSummary(report);
    this.renderTab('overview');
    this.setupTabListeners();
    if(ReportExport) ReportExport.setReport(report);
  },

  renderSummary(report) {
    const strip = document.getElementById('summary-strip');
    const profile = report.profile || {};
    const summary = profile.summary || {};

    const riskLevel = summary.riskLevel || 'Low';
    let riskColor = 'var(--status-low)';
    if (riskLevel === 'Critical' || riskLevel === 'High') riskColor = 'var(--status-high)';
    if (riskLevel === 'Medium') riskColor = 'var(--status-medium)';

    strip.innerHTML = `
      <div class="summary-card" style="border-left: 4px solid var(--accent-primary)">
        <div class="summary-label">Target Architecture</div>
        <div class="summary-value">${report.targetType.toUpperCase()}</div>
      </div>
      <div class="summary-card" style="border-left: 4px solid #8A2BE2">
        <div class="summary-label">Total Entities</div>
        <div class="summary-value">${summary.totalEntities || 0}</div>
      </div>
      <div class="summary-card" style="border-left: 4px solid #f39c12">
        <div class="summary-label">Correlations</div>
        <div class="summary-value">${summary.totalRelationships || 0}</div>
      </div>
      <div class="summary-card" style="border-left: 4px solid ${riskColor}">
        <div class="summary-label">Threat Index</div>
        <div class="summary-value" style="color: ${riskColor}">${summary.riskScore || 0}</div>
      </div>
    `;
  },

  setupTabListeners() {
    const tabs = document.querySelectorAll('#result-tabs .tab');
    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        tabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        this.renderTab(tab.dataset.tab);
      });
    });
  },

  renderTab(tabName) {
    const container = document.getElementById('tab-content');
    const r = this.report || {};
    const results = r.results || {};

    switch (tabName) {
      case 'overview': container.innerHTML = this.renderOverview(r); break;
      case 'entityMatrix': container.innerHTML = this.renderEntityMatrix(r.profile); break;
      case 'whois': container.innerHTML = this.renderWhois(results.whois); break;
      case 'dns': container.innerHTML = this.renderDNS(results.dns, results.subdomains); break;
      case 'social': container.innerHTML = this.renderSocial(results.social); break;
      case 'breach': container.innerHTML = this.renderBreach(results.breach, results.pastes); break;
      case 'search': container.innerHTML = this.renderSearch(results.search); break;
      case 'wayback': container.innerHTML = this.renderWayback(results.wayback); break;
      case 'networkMap': 
        if (window.NetworkMap) NetworkMap.render(r); 
        else container.innerHTML = '<p class="text-muted">Network Map component not loaded.</p>';
        break;
      case 'ssl': container.innerHTML = this.renderSSL(results.ssl); break;
      case 'headers': container.innerHTML = this.renderHeaders(results.headers); break;
      case 'tech': container.innerHTML = this.renderTech(results.tech); break;
      case 'dmarc': container.innerHTML = this.renderDmarc(results.dmarc); break;
      case 'ports': container.innerHTML = this.renderPorts(results.ports); break;
      case 'takeover': container.innerHTML = this.renderTakeover(results.takeover); break;
      default: container.innerHTML = '<p class="text-muted">No data available.</p>';
    }
  },

  renderOverview(r) {
    const profile = r.profile || {};
    const riskFactors = profile.riskFactors || [];
    
    let html = '<div style="display:grid; grid-template-columns: 1fr 1fr; gap:2rem;">';
    
    // Risk Factors
    html += `<div><h3><span class="material-icons-outlined" style="vertical-align: middle; color:var(--status-high);">warning</span> Risk Analysis</h3>`;
    if (riskFactors.length > 0) {
      html += `<table class="data-table"><thead><tr><th>Severity</th><th>Factor</th><th>Details</th></tr></thead><tbody>`;
      riskFactors.forEach(rf => {
         let sevColor = rf.severity === 'high' ? 'var(--status-high)' : (rf.severity === 'medium' ? 'var(--status-medium)' : 'var(--status-low)');
         html += `<tr>
            <td style="color:${sevColor}; font-weight:bold;">${rf.severity.toUpperCase()}</td>
            <td>${rf.factor}</td>
            <td class="text-muted"><small>${rf.description}</small></td>
         </tr>`;
      });
      html += `</tbody></table>`;
    } else {
      html += `<p class="text-muted">No threat vectors identified in current scan parameters.</p>`;
    }
    html += `</div>`;

    // System Log
    html += `<div><h3><span class="material-icons-outlined" style="vertical-align: middle;">dvr</span> System Log</h3>`;
    let hasErrors = false;
    html += `<ul style="list-style:none; padding-left:0;">`;
    if (r.errors && Object.keys(r.errors).length > 0) {
      hasErrors = true;
      Object.entries(r.errors).forEach(([k, v]) => {
         html += `<li style="padding: 10px; border-left: 3px solid var(--status-high); background: rgba(255,71,87,0.05); margin-bottom: 8px;">
           <strong style="color:var(--status-high); text-transform:uppercase;">${k} Module Error:</strong> <span class="mono">${v}</span>
         </li>`;
      });
    }
    if (!hasErrors) {
       html += `<li style="padding: 10px; background: rgba(46,213,115,0.05); border-left: 3px solid var(--status-low); color: var(--status-low);">All modules executed nominally. Zero exceptions caught.</li>`;
    }
    html += `</ul></div>`;

    html += '</div>';
    return html;
  },

  renderEntityMatrix(profile) {
    if (!profile || !profile.entities || profile.entities.length === 0) {
      return '<p class="text-muted">No entities extracted for correlation mapping.</p>';
    }

    let html = `<h3>Entity Correlation Matrix</h3>
    <p class="text-muted" style="margin-bottom:1.5rem;">Cross-referenced data points discovered during reconnaissance.</p>
    <table class="data-table">
      <thead>
        <tr>
          <th>Classification</th>
          <th>Identifier / Value</th>
          <th>Source Module</th>
        </tr>
      </thead>
      <tbody>`;
    
    profile.entities.forEach(ent => {
      let badgeClass = 'entity-badge ';
      switch(ent.type) {
        case 'IP': badgeClass += 'entity-ip'; break;
        case 'domain': badgeClass += 'entity-domain'; break;
        case 'email': badgeClass += 'entity-email'; break;
        case 'person': badgeClass += 'entity-person'; break;
        case 'repository': badgeClass += 'entity-repo'; break;
        default: badgeClass += 'entity-ip';
      }

      html += `<tr>
        <td><span class="${badgeClass}">${ent.type.toUpperCase()}</span></td>
        <td class="mono" style="color:var(--text-main);">${ent.name || ent.value}</td>
        <td class="text-muted">${ent.source}</td>
      </tr>`;
    });

    html += `</tbody></table>`;
    return html;
  },

  renderWhois(data) {
    if (!data) return '<p class="text-muted">Query yielded no WHOIS records.</p>';
    let html = `<h3>WHOIS Registry Data</h3>`;

    if (data.extracted) {
      html += '<table class="data-table"><tbody>';
      Object.entries(data.extracted).forEach(([k, v]) => {
        const val = Array.isArray(v) ? v.join('<br>') : v;
        html += `<tr><th style="width:200px;">${k.replace(/([A-Z])/g, ' $1').toUpperCase()}</th><td class="mono" style="color:var(--accent-primary);">${val || 'REDACTED'}</td></tr>`;
      });
      html += '</tbody></table>';
    }

    if (data.raw) {
      html += `<h4 style="margin-top:2rem;">RAW TCP STREAM</h4>
      <pre style="background:rgba(0,0,0,0.3); padding:1rem; border:1px solid var(--border-light); font-family:var(--font-mono); font-size:0.8rem; overflow-x:auto;">${this.escapeHtml(data.raw)}</pre>`;
    }

    return html;
  },

  renderDNS(dnsData, subData) {
    let html = `<div style="display:grid; grid-template-columns: 2fr 1fr; gap: 2rem;"><div>`;
    html += `<h3>DNS Infrastructure Records</h3>`;

    if (dnsData?.records) {
      const rec = dnsData.records;
      html += '<table class="data-table"><thead><tr><th style="width:80px;">Class</th><th>RDATA</th></tr></thead><tbody>';
      ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME'].forEach(type => {
        if (rec[type]) {
           rec[type].forEach(v => {
             const valStr = typeof v === 'object' ? JSON.stringify(v) : v;
             html += `<tr><td><span class="entity-badge entity-ip">${type}</span></td><td class="mono">${this.escapeHtml(valStr)}</td></tr>`;
           });
        }
      });
      html += '</tbody></table>';
    } else {
        html += `<p class="text-muted">No DNS records returned.</p>`;
    }
    
    html += `</div><div>`;

    if (dnsData?.insights?.length > 0) {
      html += '<h3>Security Posture</h3><ul style="list-style:none; padding:0;">';
      dnsData.insights.forEach(i => {
         const icon = i.value.includes('Missing') || i.value.includes('vulnerable') ? '<span class="material-icons-outlined" style="color:var(--status-high); font-size:16px;">gpp_bad</span>' : '<span class="material-icons-outlined" style="color:var(--status-low); font-size:16px;">gpp_good</span>';
         html += `<li style="background:var(--bg-surface-elevated); padding:0.8rem; border-radius:6px; margin-bottom:10px; border-left:2px solid var(--border-light);">
           <div style="font-weight:600; font-size:0.85rem; margin-bottom:4px;">${icon} ${i.label}</div>
           <div class="text-muted mono" style="font-size:0.8rem;">${i.value}</div>
         </li>`;
      });
      html += '</ul>';
    }

    html += `</div></div>`;

    if (subData?.found?.length > 0) {
      html += `<h3 style="margin-top:2rem;">Subdomain Discovery Engine [${subData.found.length} Nodes]</h3>
      <table class="data-table"><thead><tr><th>Node Addr</th><th>Resolution (IPv4/IPv6)</th></tr></thead><tbody>`;
      subData.found.forEach(s => {
         html += `<tr><td class="mono" style="color:var(--accent-primary);">${s.subdomain}</td><td class="mono text-muted">${s.addresses.join(', ')}</td></tr>`;
      });
      html += '</tbody></table>';
    }

    return html;
  },

  renderSocial(data) {
    if (!data) return '<p class="text-muted">No Social Intelligence Found.</p>';
    let html = ``;

    if (data.profiles?.found?.length) {
      html += '<h3>Digital Footprint: Social Platforms</h3>';
      html += '<div style="display:flex; flex-wrap:wrap; gap:10px; margin-bottom:2rem;">';
      data.profiles.found.forEach(p => {
        html += `<a href="${p.url}" target="_blank" style="text-decoration:none;">
          <div style="background:var(--bg-surface-elevated); border:1px solid rgba(0,240,255,0.2); padding:1rem; border-radius:8px; display:flex; align-items:center; gap:10px; transition:all 0.2s;">
            <span class="material-icons-outlined" style="color:var(--accent-primary);">account_circle</span>
            <div>
               <div style="font-weight:600; color:var(--text-main); font-size:0.9rem;">${p.platform}</div>
               <div class="text-muted" style="font-size:0.75rem; text-transform:uppercase;">${p.category}</div>
            </div>
          </div>
        </a>`;
      });
      html += '</div>';
    }

    if (data.github?.results?.repos?.length) {
      html += '<h3>Code Intelligence: GitHub Repositories</h3><table class="data-table"><thead><tr><th>Repository</th><th>Metrics</th><th>Description</th></tr></thead><tbody>';
      data.github.results.repos.forEach(r => {
        html += `<tr>
          <td><a href="${r.url}" class="external-link mono" target="_blank">${r.name}</a></td>
          <td><span class="entity-badge entity-repo"><span class="material-icons-outlined" style="font-size:12px;">star</span> ${r.stars}</span></td>
          <td class="text-muted"><small>${r.description || 'No description provided.'}</small></td>
        </tr>`;
      });
      html += '</tbody></table>';
    }

    if(html === '') return '<p class="text-muted">Target footprint null across scanned platforms.</p>';
    return html;
  },

  renderBreach(breachData, pasteData) {
    if (!breachData) return '<p class="text-muted">No Breach Datasets Matched.</p>';
    let html = `<div style="display:grid; grid-template-columns: 1fr 1fr; gap: 2rem;">`;
    
    html += `<div><h3>Dark Web / Breach Catalogs</h3>`;
    if (breachData.knownBreaches?.length) {
      html += `<table class="data-table"><thead><tr><th>Event</th><th>Disclosure</th><th>Compromised Data Classes</th></tr></thead><tbody>`;
      breachData.knownBreaches.forEach(b => {
        html += `<tr>
           <td style="color:var(--status-high); font-weight:600;">${b.title || b.name}</td>
           <td class="mono">${b.breachDate || 'Unknown'}</td>
           <td class="text-muted"><small>${(b.dataClasses || []).join(', ')}</small></td>
        </tr>`;
      });
      html += `</tbody></table>`;
    } else {
      html += `<p class="text-muted" style="padding:1rem; border:1px dashed var(--border-light);">No automated breach records flag this target.</p>`;
    }
    html += `</div>`;

    html += `<div><h3>Identity Checks</h3>`;
    if (breachData.emailRep) {
       let repColor = breachData.emailRep.suspicious ? 'var(--status-high)' : 'var(--status-low)';
       html += `<div style="background:var(--bg-surface-elevated); padding:1rem; border-left:4px solid ${repColor}; border-radius:6px; margin-bottom:1.5rem;">
         <div style="font-size:0.85rem; text-transform:uppercase; color:var(--text-muted); margin-bottom:0.5rem;">Email Reputation Score</div>
         <div style="font-size:1.5rem; font-family:var(--font-mono); color:${repColor}; margin-bottom:0.5rem;">${breachData.emailRep.reputation}</div>
         <div style="font-size:0.85rem; color:var(--text-main);">Suspicious Flag: <span style="font-weight:bold;">${breachData.emailRep.suspicious ? 'TRUE' : 'FALSE'}</span></div>
       </div>`;
    }

    if (pasteData?.pastes?.length) {
      html += `<h4>Pastebin Dumps</h4><ul style="list-style:none; padding:0;">`;
      pasteData.pastes.forEach(p => {
        html += `<li style="padding:0.5rem 0; border-bottom:1px solid var(--border-light);">
          <a href="${p.url}" class="external-link mono" target="_blank">${p.date || 'Raw Dump'}</a> <span class="text-muted" style="font-size:0.8rem;">(Tags: ${p.tags || 'none'})</span>
        </li>`;
      });
      html += `</ul>`;
    }

    html += `</div></div>`;
    return html;
  },

  renderSearch(data) {
    if (!data) return '<p class="text-muted">No OSINT Search Engine Results.</p>';
    let html = ``;

    if (data.shodan?.shodanResults?.length) {
      html += '<h3>Shodan IoT Index</h3><div style="display:flex; flex-direction:column; gap:1rem; margin-bottom:2rem;">';
      data.shodan.shodanResults.forEach(s => {
        if (!s.available) return;
        html += `<div style="background:var(--bg-surface-elevated); border:1px solid var(--accent-primary); border-radius:8px; padding:1.5rem;">
          <div style="display:flex; justify-content:space-between; margin-bottom:1rem;">
             <div style="font-size:1.2rem; color:var(--accent-primary); font-family:var(--font-mono);">${s.ip}</div>
             <div class="entity-badge entity-domain">${s.org || 'N/A'}</div>
          </div>
          <div style="display:flex; gap:2rem;">
             <div><span class="text-muted text-uppercase" style="font-size:0.75rem;">OS</span><br>${s.os || 'Unknown'}</div>
             <div><span class="text-muted text-uppercase" style="font-size:0.75rem;">Open Ports</span><br><span class="mono">${(s.ports || []).join(', ')}</span></div>
          </div>
          ${s.vulns?.length ? `<div style="margin-top:1rem; padding-top:1rem; border-top:1px solid var(--border-light);"><span class="text-muted" style="font-size:0.75rem;">Known CVEs</span><br><span style="color:var(--status-high);" class="mono">${s.vulns.join(', ')}</span></div>` : ''}
        </div>`;
      });
      html += '</div>';
    }

    if (data.google?.results?.length) {
      html += '<h3>Google Dorking Top Intel</h3><div style="display:flex; flex-direction:column; gap:1rem;">';
      data.google.results.forEach(r => {
        html += `<div style="border-bottom:1px solid var(--border-light); padding-bottom:1rem;">
          <a href="${r.link}" class="external-link" target="_blank" style="font-size:1.1rem; font-weight:500;">${r.title}</a>
          <div class="mono text-muted" style="font-size:0.75rem; color:var(--status-low); margin:4px 0;">${r.link}</div>
          <p style="font-size:0.85rem; color:var(--text-main); line-height:1.5;">${r.snippet}</p>
        </div>`;
      });
      html += '</div>';
    }

    return html || '<p class="text-muted">Search queries returned 0 high-fidelity hits.</p>';
  },

  renderWayback(data) {
    if (!data) return '<p class="text-muted">Archive system offline or returned null.</p>';
    if (data.message) return `<p class="text-muted">${data.message}</p>${data.manualUrl ? `<p><a href="${data.manualUrl}" class="btn-outline" style="display:inline-flex; margin-top:1rem;" target="_blank">Access Archive Gateway</a></p>` : ''}`;

    let html = `<div style="display:flex; justify-content:space-between; align-items:flex-end; margin-bottom:2rem;">
      <div>
        <h3>Wayback Time Machine</h3>
        <p class="text-muted">Historical snapshots isolated from CDX Index.</p>
      </div>
      <div style="text-align:right;">
        <div class="summary-value" style="color:var(--accent-primary); font-size:2.5rem;">${data.totalCount || 0}</div>
        <div class="text-muted text-uppercase" style="font-size:0.75rem;">Total Captures Found</div>
      </div>
    </div>`;

    if (data.snapshots?.length) {
      html += '<table class="data-table"><thead><tr><th style="width:120px;">Capture Date</th><th style="width:100px;">MIME</th><th style="width:80px;">Status</th><th>Original URL</th><th style="width:100px;">Action</th></tr></thead><tbody>';
      // Show up to 50 captures
      data.snapshots.slice(0, 50).forEach(s => {
        let statusColor = s.statusCode === "200" ? 'var(--status-low)' : 'var(--text-muted)';
        html += `<tr>
          <td class="mono">${s.date}</td>
          <td class="text-muted"><small>${s.type}</small></td>
          <td class="mono" style="color:${statusColor}">${s.statusCode}</td>
          <td class="text-muted mono"><small>${s.url.length > 60 ? s.url.substring(0, 57) + '...' : s.url}</small></td>
          <td><a href="${s.archiveUrl}" class="external-link" style="font-size:0.85rem;" target="_blank">RESTORE</a></td>
        </tr>`;
      });
      html += '</tbody></table>';
    }

    return html;
  },

  renderSSL(data) {
    if (!data || !data.valid) return '<p class="text-muted">No SSL/TLS data found or target does not support HTTPS.</p>';
    
    let html = `<div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom: 2rem;">
      <div>
        <h3>SSL/TLS Certificate Analysis</h3>
        <p class="text-muted">Validation of cryptographic identity and connection security.</p>
      </div>
      <div style="text-align:center;">
        <div class="grade-badge grade-${data.grade}">${data.grade}</div>
      </div>
    </div>`;

    html += `<div style="display:grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin-bottom: 2rem;">
      <div class="glass-panel" style="padding: 1.5rem;">
        <h4 style="margin-bottom: 1rem;">Certificate Details</h4>
        <table style="width:100%; text-align:left; font-size:0.9rem;">
          <tr><th style="padding-bottom:10px; color:var(--text-muted)">Subject</th><td style="padding-bottom:10px;" class="mono" style="color:var(--text-main)">${data.certificate?.subject || 'N/A'}</td></tr>
          <tr><th style="padding-bottom:10px; color:var(--text-muted)">Issuer</th><td style="padding-bottom:10px;" class="mono" style="color:var(--text-main)">${data.certificate?.issuer || 'N/A'}</td></tr>
          <tr><th style="padding-bottom:10px; color:var(--text-muted)">Valid From</th><td style="padding-bottom:10px;" class="mono">${data.certificate?.validFrom || 'N/A'}</td></tr>
          <tr><th style="padding-bottom:10px; color:var(--text-muted)">Valid To</th><td style="padding-bottom:10px;" class="mono">${data.certificate?.validTo || 'N/A'}</td></tr>
        </table>
      </div>
      <div>
        <h4 style="margin-bottom: 1rem;">Security Checks</h4>
        <div style="display:flex; flex-direction:column; gap:0.5rem;">`;
    
    if (data.checks && data.checks.length > 0) {
        data.checks.forEach(c => {
            const icon = c.pass ? 'check_circle' : 'error';
            const color = c.pass ? 'var(--status-low)' : 'var(--status-high)';
            html += `<div style="background:var(--bg-surface-elevated); padding: 0.75rem; border-radius: 6px; display:flex; gap:10px; align-items:center;">
                <span class="material-icons-outlined" style="color:${color}">${icon}</span>
                <div>
                   <div style="font-weight:600; font-size:0.9rem;">${c.name}</div>
                   <div style="font-size:0.8rem; color:var(--text-muted);">${c.detail}</div>
                </div>
            </div>`;
        });
    }

    html += `</div></div></div>`;
    return html;
  },

  renderHeaders(data) {
    if (!data || !data.checks) return '<p class="text-muted">No Security Headers data found.</p>';
    
    let html = `<div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom: 2rem;">
      <div>
        <h3>HTTP Security Headers</h3>
        <p class="text-muted">Analysis of web application defensive posture.</p>
      </div>
      <div style="text-align:center;">
         <div class="grade-badge grade-${data.grade.charAt(0)}">${data.grade}</div>
         <div style="margin-top:5px; font-size:0.8rem; font-family:var(--font-mono); color:var(--text-muted)">Score: ${data.score}/100</div>
      </div>
    </div>`;

    html += `<div style="display:grid; grid-template-columns: 1fr 1fr; gap: 1rem;">`;
    
    data.checks.forEach(c => {
        if(c.info) return; // Skip info check for main layout
        const icon = c.present ? 'check_circle' : 'warning';
        const color = c.present ? 'var(--status-low)' : 'var(--status-high)';
        html += `<div class="glass-panel" style="padding: 1rem; border-left: 4px solid ${color}">
            <div style="display:flex; gap:10px; align-items:center; margin-bottom:0.5rem;">
                <span class="material-icons-outlined" style="color:${color}; font-size:18px;">${icon}</span>
                <span style="font-weight:600; font-family:var(--font-mono); font-size:0.9rem;">${c.name}</span>
            </div>
            <div style="font-size:0.8rem; color:var(--text-muted); margin-bottom:0.8rem;">${c.description}</div>
            ${!c.present && c.remediation ? `<div style="background:rgba(255,127,80,0.1); padding:0.5rem; border-radius:4px; font-size:0.8rem; font-family:var(--font-mono); color:#ff7f50;">Fix: ${c.remediation}</div>` : ''}
            ${c.present ? `<div style="font-size:0.8rem; font-family:var(--font-mono); color:var(--accent-primary); word-break:break-all;">${c.value}</div>` : ''}
        </div>`;
    });

    html += `</div>`;
    return html;
  },

  renderTech(data) {
    if (!data || !data.detected || data.detected.length === 0) return '<p class="text-muted">No distinct technology stack fingerprints detected.</p>';
    
    let html = `<div style="margin-bottom: 2rem;">
      <h3>Technology Stack Fingerprint</h3>
      <p class="text-muted">Identified frameworks, servers, CMS, and infrastructure components.</p>
    </div>`;

    html += `<div class="tech-grid">`;
    data.detected.forEach(t => {
        let icon = 'memory';
        if (t.category.includes('CMS')) icon = 'dashboard';
        if (t.category.includes('Server')) icon = 'dns';
        if (t.category.includes('Analytics')) icon = 'insights';
        if (t.category.includes('CDN')) icon = 'cloud';
        
        html += `<div class="tech-tag">
            <div style="display:flex; align-items:center; gap:8px;">
                <span class="material-icons-outlined" style="color:var(--accent-primary); font-size:18px;">${icon}</span>
                <span class="tech-name">${t.name}</span>
            </div>
            <span class="tech-cat">${t.category}</span>
        </div>`;
    });
    html += `</div>`;

    return html;
  },

  renderDmarc(data) {
    if (!data || !data.spf && !data.dmarc) return '<p class="text-muted">No DMARC or SPF data available.</p>';

    let html = `<div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom: 2rem;">
      <div>
        <h3>Email Security Auditor</h3>
        <p class="text-muted">Analysis of SPF and DMARC configurations protecting against spoofing.</p>
      </div>
      <div style="text-align:center;">
        <div class="grade-badge grade-${data.grade}">${data.grade}</div>
      </div>
    </div>`;

    html += `<div style="display:grid; grid-template-columns: 1fr 1fr; gap: 2rem;">`;

    // SPF Card
    const spfColor = data.spf?.strict ? 'var(--status-low)' : (data.spf?.present ? 'var(--status-medium)' : 'var(--status-high)');
    html += `<div class="glass-panel" style="padding: 1.5rem; border-left: 4px solid ${spfColor}">
        <h4 style="margin-bottom: 1rem; display:flex; align-items:center; gap:8px;">
            <span class="material-icons-outlined" style="color:${spfColor}">${data.spf?.present ? 'check_circle' : 'error'}</span> SPF Record
        </h4>
        <div class="mono" style="background:var(--bg-base); padding:10px; border-radius:6px; margin-bottom:1rem; word-break:break-all; font-size:0.85rem; color:var(--text-muted);">
            ${data.spf?.record || 'N/A'}
        </div>
        <div>Strict Policy (Reject/HardFail): <span style="font-weight:bold; color:${spfColor}">${data.spf?.strict ? 'YES' : 'NO'}</span></div>
    </div>`;

    // DMARC Card
    const dmarcColor = data.dmarc?.policy === 'reject' || data.dmarc?.policy === 'quarantine' ? 'var(--status-low)' : (data.dmarc?.present ? 'var(--status-medium)' : 'var(--status-high)');
    html += `<div class="glass-panel" style="padding: 1.5rem; border-left: 4px solid ${dmarcColor}">
        <h4 style="margin-bottom: 1rem; display:flex; align-items:center; gap:8px;">
            <span class="material-icons-outlined" style="color:${dmarcColor}">${data.dmarc?.present ? 'check_circle' : 'error'}</span> DMARC Record
        </h4>
        <div class="mono" style="background:var(--bg-base); padding:10px; border-radius:6px; margin-bottom:1rem; word-break:break-all; font-size:0.85rem; color:var(--text-muted);">
            ${data.dmarc?.record || 'N/A'}
        </div>
        <div>Enforcement Policy: <span style="font-weight:bold; color:${dmarcColor}; text-transform:uppercase;">${data.dmarc?.policy || 'NONE'}</span></div>
    </div>`;

    html += `</div>`;
    
    if (data.spoofable) {
        html += `<div style="margin-top:2rem; padding:1.5rem; background:rgba(255,71,87,0.1); border:1px solid var(--status-high); border-radius:8px;">
            <h4 style="color:var(--status-high); margin-bottom:0.5rem; display:flex; align-items:center; gap:8px;">
                <span class="material-icons-outlined">gpp_bad</span> Susceptible to Spoofing
            </h4>
            <p style="font-size:0.9rem;">This domain does not enforce a strict SPF/DMARC policy. Attackers can likely send emails impersonating this domain, leading to high-impact phishing campaigns.</p>
        </div>`;
    }

    return html;
  },

  renderPorts(data) {
    if (!data || !data.openPorts) return '<p class="text-muted">Port scan data not available or failed.</p>';
    if (data.openPorts.length === 0) return `<p class="text-muted">Scanned ${data.totalScanned} critical ports. 0 exposed services discovered.</p>`;

    let html = `<div style="display:flex; justify-content:space-between; align-items:flex-end; margin-bottom:2rem;">
        <div>
            <h3>Exposed TCP Services</h3>
            <p class="text-muted">Active asynchronous TCP connect scan across ${data.totalScanned} top attack surface ports.</p>
        </div>
        <div style="text-align:right;">
            <div class="summary-value" style="color:var(--status-high); font-size:2.5rem;">${data.openPorts.length}</div>
            <div class="text-muted text-uppercase" style="font-size:0.75rem;">Open Ports</div>
        </div>
    </div>`;

    if (data.vulnerable) {
        html += `<div style="padding:1rem; background:rgba(255,71,87,0.1); border-left:4px solid var(--status-high); border-radius:6px; margin-bottom:2rem; font-size:0.9rem;">
            <span class="material-icons-outlined" style="color:var(--status-high); vertical-align:middle;">warning</span>
            <strong style="color:var(--status-high)">Critical Vulnerability:</strong> ${data.warning}
        </div>`;
    }

    html += `<table class="data-table"><thead><tr><th style="width:100px;">Port</th><th>Service Identity</th><th>Status</th></tr></thead><tbody>`;
    data.openPorts.forEach(p => {
        html += `<tr>
            <td><span class="entity-badge entity-ip" style="background:var(--bg-surface-elevated); border:1px solid var(--border-light)">${p.port}/tcp</span></td>
            <td class="mono" style="color:var(--text-main);">${p.service}</td>
            <td style="color:var(--status-low);"><span class="material-icons-outlined" style="font-size:16px; vertical-align:middle;">wifi_tethering</span> OPEN</td>
        </tr>`;
    });
    html += `</tbody></table>`;

    return html;
  },

  renderTakeover(data) {
    if (!data) return '<p class="text-muted">Takeover module did not execute successfully.</p>';
    if (data.message) return `<p class="text-muted">${data.message}</p>`;

    let html = `<div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom: 2rem;">
      <div>
        <h3>Subdomain Takeover Analysis</h3>
        <p class="text-muted">Auditing ${data.analyzedCount} subdomains for dangling CNAME records pointing to unclaimed cloud services.</p>
      </div>
      <div style="text-align:center;">
        <div class="grade-badge grade-${data.grade}">${data.grade}</div>
      </div>
    </div>`;

    if (data.vulnerableSubdomains && data.vulnerableSubdomains.length > 0) {
        html += `<div style="margin-bottom:1.5rem; padding:1rem; background:rgba(255,71,87,0.1); border:1px solid var(--status-high); border-radius:6px;">
            <h4 style="color:var(--status-high); margin-bottom:0.5rem;"><span class="material-icons-outlined" style="vertical-align:middle;">bug_report</span> High Risk: Vulnerable Subdomains Discovered</h4>
            <p style="font-size:0.85rem;">The following subdomains point to third-party services that may have been un-registered or disabled. Attackers can claim these services to hijack the subdomain.</p>
        </div>`;

        html += `<table class="data-table"><thead><tr><th>Subdomain</th><th>Dangling CNAME</th><th>Target Service Provider</th><th>Risk</th></tr></thead><tbody>`;
        data.vulnerableSubdomains.forEach(v => {
            html += `<tr>
                <td class="mono" style="color:var(--accent-primary);">${v.subdomain}</td>
                <td class="mono text-muted">${v.cname}</td>
                <td><span class="entity-badge entity-domain">${v.service}</span></td>
                <td style="color:var(--status-high); font-weight:bold;">${v.risk}</td>
            </tr>`;
        });
        html += `</tbody></table>`;
    } else {
        html += `<div style="text-align:center; padding:3rem 1rem; border:1px dashed var(--border-light); border-radius:8px;">
            <span class="material-icons-outlined" style="font-size:3rem; color:var(--status-low); margin-bottom:1rem;">security</span>
            <h4 style="color:var(--text-main);">No Takeover Vectors Found</h4>
            <p class="text-muted" style="font-size:0.9rem; max-width:400px; margin:0 auto;">All analyzed CNAME records appear to securely mapped, or do not point to known vulnerable cloud providers.</p>
        </div>`;
    }

    return html;
  },

  escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }
};
