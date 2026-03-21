/**
 * App — Main application controller with localStorage persistence
 */
const App = {
    currentView: 'scan',
    currentScanId: null,
    currentReport: null,

    init() {
        // Initialize all components
        SearchForm.init();
        ReportExport.init();
        if (window.ScanHistory) ScanHistory.init();
        if (window.ParticleCanvas) ParticleCanvas.init();

        // Authentication Flow
        this.initAuth();
        this.checkAuth();

        // Navigation
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const view = btn.dataset.view;
                this.showView(view);
            });
        });

        // Settings
        this.initSettings();

        // Restore last scan from localStorage
        this.restoreLastScan();
    },

    initAuth() {
        const loginBtn = document.getElementById('login-btn');
        const loginPhrase = document.getElementById('login-phrase');
        const errorDiv = document.getElementById('login-error');

        if (!loginBtn || !loginPhrase) return;

        const attemptLogin = async () => {
            loginBtn.textContent = 'CHECKING...';
            errorDiv.textContent = '';
            try {
                const res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ phrase: loginPhrase.value })
                });
                const data = await res.json();
                
                if (data.success) {
                    document.getElementById('login-modal').classList.add('is-hidden');
                    loginPhrase.value = '';
                } else {
                    errorDiv.textContent = data.message || 'Authentication failed';
                }
            } catch (err) {
                errorDiv.textContent = 'Network error during authentication';
            } finally {
                loginBtn.textContent = 'AUTHENTICATE';
            }
        };

        loginBtn.addEventListener('click', attemptLogin);
        loginPhrase.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') attemptLogin();
        });
    },

    async checkAuth() {
        try {
            const res = await fetch('/api/auth/verify');
            if (res.status !== 200 && res.status !== 304) {
                document.getElementById('login-modal').classList.remove('is-hidden');
            } else {
                document.getElementById('login-modal').classList.add('is-hidden');
            }
        } catch (e) {
            document.getElementById('login-modal').classList.remove('is-hidden');
        }
    },

    showView(viewName) {
        this.currentView = viewName;

        // Update nav buttons
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.view === viewName);
        });

        // Update views — only one has 'active' at a time
        document.querySelectorAll('.view').forEach(v => {
            v.classList.toggle('active', v.id === `view-${viewName}`);
        });

        // If switching to results and we have a report, render it
        if (viewName === 'results' && this.currentReport) {
            Dashboard.render(this.currentReport);
        }

        // If switching to timeline, re-render
        if (viewName === 'timeline' && this.currentReport) {
            Timeline.render(this.currentReport);
        }

        if (viewName === 'history' && window.ScanHistory) {
            ScanHistory.render();
        }
    },

    /** Save the last scan report to localStorage */
    saveReport(report) {
        this.currentReport = report;
        try {
            localStorage.setItem('argus_last_report', JSON.stringify(report));
            if (window.ScanHistory) ScanHistory.save(report);
        } catch (e) {
            console.warn('Could not save scan to localStorage:', e);
        }
    },

    /** Restore scan from localStorage on page load */
    restoreLastScan() {
        try {
            const saved = localStorage.getItem('argus_last_report');
            if (saved) {
                const report = JSON.parse(saved);
                this.currentReport = report;
                // Pre-render the intelligence hub & timeline so they aren't blank
                Dashboard.render(report);
                Timeline.render(report);
            }
        } catch (e) {
            console.warn('Could not restore last scan:', e);
        }
    },

    async initSettings() {
        const settingsGrid = document.getElementById('settings-grid');
        const settingsConfig = [
            { key: 'SHODAN_API_KEY', label: 'Shodan API Key', icon: 'search', hint: 'Get a free key at shodan.io' },
            { key: 'GOOGLE_CSE_API_KEY', label: 'Google Custom Search API Key', icon: 'search', hint: 'From programmablesearchengine.google.com' },
            { key: 'GOOGLE_CSE_CX', label: 'Google CSE Engine ID', icon: 'travel_explore', hint: 'Custom Search Engine ID (cx)' },
            { key: 'GITHUB_TOKEN', label: 'GitHub Personal Access Token', icon: 'code', hint: 'Increases rate limit from 60 to 5000 req/hr' },
        ];

        // Load current settings
        let currentSettings = {};
        try {
            const res = await api.get('/settings');
            currentSettings = res.settings || {};
        } catch {
            // Server not running yet
        }

        settingsGrid.innerHTML = settingsConfig.map(s => `
      <div class="setting-field">
        <label class="setting-label">
          <span class="material-icons-outlined">${s.icon}</span>
          ${s.label}
        </label>
        <div class="setting-hint">${s.hint}</div>
        <input type="password" class="setting-input" data-key="${s.key}" 
          value="${currentSettings[s.key] || ''}" placeholder="Enter key...">
      </div>
    `).join('');

        // Toggle password visibility on focus
        settingsGrid.querySelectorAll('.setting-input').forEach(input => {
            input.addEventListener('focus', () => { input.type = 'text'; });
            input.addEventListener('blur', () => { input.type = 'password'; });
        });

        // Save button
        document.getElementById('save-settings')?.addEventListener('click', async () => {
            const keys = {};
            settingsGrid.querySelectorAll('.setting-input').forEach(input => {
                const key = input.dataset.key;
                const value = input.value.trim();
                if (value && !value.includes('****')) {
                    keys[key] = value;
                }
            });

            try {
                await api.post('/settings', { keys });
                const btn = document.getElementById('save-settings');
                btn.innerHTML = '<span class="material-icons-outlined">check</span> Saved!';
                btn.style.borderColor = 'var(--status-low)';
                btn.style.color = 'var(--status-low)';
                setTimeout(() => {
                    btn.innerHTML = '<span class="material-icons-outlined">save</span> COMMIT SETTINGS';
                    btn.style.borderColor = '';
                    btn.style.color = '';
                }, 2000);
            } catch (err) {
                console.error('Failed to save settings:', err);
            }
        });
    },
};

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    App.init();
});
