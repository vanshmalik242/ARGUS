/**
 * Scan History Component — manages persistence and comparison of past scans
 */
const ScanHistory = {
    STORAGE_KEY: 'argus_scan_history',
    maxItems: 20,

    init() {
        this.container = document.getElementById('history-list');
        const clearBtn = document.getElementById('clear-history');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => this.clearAll());
        }
    },

    save(report) {
        let history = this.getAll();
        
        // Remove existing entry for same target to move to top
        history = history.filter(h => h.target !== report.target);
        
        const entry = {
            id: report.id,
            target: report.target,
            targetType: report.targetType,
            timestamp: new Date().toISOString(),
            riskScore: report.profile?.summary?.riskScore || 0,
            entitiesCount: report.profile?.summary?.totalEntities || 0,
            report: report // Store full report for comparison
        };

        history.unshift(entry);
        if (history.length > this.maxItems) history.pop();

        localStorage.setItem(this.STORAGE_KEY, JSON.stringify(history));
    },

    getAll() {
        try {
            return JSON.parse(localStorage.getItem(this.STORAGE_KEY)) || [];
        } catch {
            return [];
        }
    },

    clearAll() {
        if (confirm('Are you sure you want to clear all scan history?')) {
            localStorage.setItem(this.STORAGE_KEY, JSON.stringify([]));
            this.render();
        }
    },

    render() {
        if (!this.container) return;
        const history = this.getAll();

        if (history.length === 0) {
            this.container.innerHTML = `
                <div class="empty-state">
                    <span class="material-icons-outlined">history</span>
                    <h3>No history yet</h3>
                    <p>Run your first scan to see it here.</p>
                </div>
            `;
            return;
        }

        this.container.innerHTML = history.map(item => `
            <div class="history-item">
                <div class="grade-badge grade-${this.getRiskGrade(item.riskScore)}">${this.getRiskGrade(item.riskScore)}</div>
                <div class="history-content">
                    <div class="history-target">${item.target}</div>
                    <div class="history-meta">
                        <span><span class="material-icons-outlined" style="font-size:14px; vertical-align:middle">calendar_today</span> ${new Date(item.timestamp).toLocaleString()}</span>
                        <span><span class="material-icons-outlined" style="font-size:14px; vertical-align:middle">hub</span> ${item.entitiesCount} entities</span>
                    </div>
                </div>
                <div class="history-score">
                    <div class="summary-label">Risk Score</div>
                    <div class="summary-value" style="font-size: 1.2rem; color: ${this.getRiskColor(item.riskScore)}">${item.riskScore}</div>
                </div>
                <div class="history-actions">
                    <button class="btn-outline btn-sm" onclick="ScanHistory.viewReport('${item.id}')">View</button>
                    <button class="btn-outline btn-sm" onclick="ScanHistory.compare('${item.id}')">Compare</button>
                </div>
            </div>
        `).join('');
    },

    getRiskGrade(score) {
        if (score >= 60) return 'F';
        if (score >= 40) return 'D';
        if (score >= 20) return 'C';
        if (score > 0) return 'B';
        return 'A';
    },

    getRiskColor(score) {
        if (score >= 60) return 'var(--status-high)';
        if (score >= 40) return '#ff7f50';
        if (score >= 20) return '#ffa502';
        return 'var(--status-low)';
    },

    viewReport(scanId) {
        const history = this.getAll();
        const item = history.find(h => h.id === scanId);
        if (item) {
            App.saveReport(item.report);
            App.showView('results');
        }
    },

    compare(scanId) {
        const history = this.getAll();
        const currentScan = history.find(h => h.id === scanId);
        if (!currentScan) return;

        // For simplicity, we compare with the previous scan in history (if any)
        const currentIdx = history.indexOf(currentScan);
        const prevScan = history[currentIdx + 1];

        if (!prevScan) {
            alert('Need at least two scans in history to compare.');
            return;
        }

        this.renderComparison(currentScan.report, prevScan.report);
    },

    renderComparison(newReport, oldReport) {
        App.showView('results'); // Use results view as container
        const container = document.getElementById('tab-content');
        
        const newEntities = new Set(newReport.profile.entities.map(e => `${e.type}:${e.value || e.name}`));
        const oldEntities = new Set(oldReport.profile.entities.map(e => `${e.type}:${e.value || e.name}`));

        const added = [...newEntities].filter(e => !oldEntities.has(e));
        const removed = [...oldEntities].filter(e => !newEntities.has(e));

        document.getElementById('results-target-title').textContent = `Comparison: ${newReport.target} vs ${oldReport.target}`;

        container.innerHTML = `
            <div class="comparison-grid">
                <div class="comparison-col">
                    <h4><span class="material-icons-outlined" style="color:var(--status-low)">add_circle</span> Added Entities (${added.length})</h4>
                    <div class="glass-panel" style="padding:1rem; min-height:200px">
                        ${added.length ? added.map(e => `<div style="padding:5px 0; border-bottom:1px solid var(--border-light)">${e.split(':')[1]} <small class="text-muted">(${e.split(':')[0]})</small></div>`).join('') : '<p class="text-muted">No new entities</p>'}
                    </div>
                </div>
                <div class="comparison-col">
                    <h4><span class="material-icons-outlined" style="color:var(--status-high)">remove_circle</span> Removed Entities (${removed.length})</h4>
                    <div class="glass-panel" style="padding:1rem; min-height:200px">
                        ${removed.length ? removed.map(e => `<div style="padding:5px 0; border-bottom:1px solid var(--border-light)">${e.split(':')[1]} <small class="text-muted">(${e.split(':')[0]})</small></div>`).join('') : '<p class="text-muted">No entities removed</p>'}
                    </div>
                </div>
            </div>
            <div style="margin-top:2rem; text-align:center">
                <button class="btn-glow" onclick="App.showView('history')">Back to History</button>
            </div>
        `;
    }
};
