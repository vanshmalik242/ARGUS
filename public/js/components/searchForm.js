/**
 * Search Form Component — target input with auto-detection, module selection, and AUP Modal
 */
const SearchForm = {
    init() {
        this.input = document.getElementById('target-input');
        this.badge = document.getElementById('target-type-badge');
        this.scanBtn = document.getElementById('scan-button');
        
        // Progress Overlay
        this.progressSection = document.getElementById('progress-section');
        this.progressBar = document.getElementById('progress-bar');
        this.progressTarget = document.getElementById('progress-target');
        this.progressDetails = document.getElementById('progress-details');
        this.progressModules = document.getElementById('progress-modules');

        // AUP Modal Elements
        this.aupModal = document.getElementById('aup-modal');
        this.aupAcceptBtn = document.getElementById('aup-accept');
        this.aupDeclineBtn = document.getElementById('aup-decline');
        this.aupAccepted = false;

        this.input.addEventListener('input', () => this.detectType());
        this.scanBtn.addEventListener('click', () => this.handleScanClick());

        // Enter key triggers scan
        this.input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') this.handleScanClick();
        });

        // AUP Modal Listeners
        if (this.aupAcceptBtn) {
            this.aupAcceptBtn.addEventListener('click', () => this.acceptAUP());
        }
        if (this.aupDeclineBtn) {
            this.aupDeclineBtn.addEventListener('click', () => this.declineAUP());
        }
    },

    detectType() {
        const val = this.input.value.trim();
        if (!val) {
            this.badge.textContent = 'auto-detect';
            this.badge.style.background = '';
            return;
        }

        let type = 'username';
        if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)) type = 'email';
        else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val)) type = 'ip';
        else if (/^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$/.test(val)) type = 'domain';

        this.badge.textContent = type;

        const colors = {
            domain: 'rgba(124, 77, 255, 0.25)',
            email: 'rgba(0, 229, 255, 0.25)',
            ip: 'rgba(255, 110, 64, 0.25)',
            username: 'rgba(63, 185, 80, 0.25)',
        };
        this.badge.style.background = colors[type] || '';
    },

    getSelectedModules() {
        const chips = document.querySelectorAll('.module-card input:checked');
        return Array.from(chips).map(cb => cb.dataset.module);
    },

    handleScanClick() {
        if (!this.input.value.trim()) {
            this.input.focus();
            return;
        }
        
        const modules = this.getSelectedModules();
        if (modules.length === 0) return;

        if (!this.aupAccepted && this.aupModal) {
            // Show the modal
            this.aupModal.classList.remove('is-hidden');
        } else {
            this.startScan();
        }
    },

    acceptAUP() {
        this.aupAccepted = true;
        this.aupModal.classList.add('is-hidden');
        this.startScan();
    },

    declineAUP() {
        this.aupModal.classList.add('is-hidden');
    },

    async startScan() {
        const target = this.input.value.trim();
        const modules = this.getSelectedModules();

        // Disable button
        this.scanBtn.disabled = true;
        this.scanBtn.innerHTML = '<span class="material-icons-outlined" style="animation: spin 2s linear infinite;">sync</span> SCANNING...';

        try {
            const result = await api.post('/scan', { target, modules });

            if (!result.scanId) {
                throw new Error('Failed to start scan');
            }

            App.currentScanId = result.scanId;

            // Show progress
            this.showProgress(target, modules);

            // Stream progress
            api.streamScan(result.scanId,
                (data) => this.updateProgress(data, modules),
                (data) => this.scanComplete(result.scanId)
            );
        } catch (err) {
            this.scanBtn.disabled = false;
            this.scanBtn.innerHTML = '<span class="material-icons-outlined">play_arrow</span> INIT SCAN';
            console.error('Scan error:', err);
        }
    },

    showProgress(target, modules) {
        this.progressSection.classList.remove('is-hidden');
        this.progressTarget.textContent = target;
        this.progressBar.style.width = '0%';
        this.progressDetails.textContent = 'Allocating scan threads...';

        this.progressModules.innerHTML = modules.map(m =>
            `<span class="module-badge chip-running" data-module="${m}">${m.toUpperCase()}</span>`
        ).join('');
    },

    updateProgress(data, allModules) {
        this.progressBar.style.width = `${data.progress}%`;
        this.progressDetails.textContent = `Processing: ${data.progress}% [${data.completedModules.length}/${allModules.length} Modules]`;

        allModules.forEach(m => {
            const badge = this.progressModules.querySelector(`[data-module="${m}"]`);
            if (!badge) return;
            if (data.completedModules.includes(m)) {
                badge.className = 'module-badge chip-done';
            } else if (data.errorModules.includes(m)) {
                badge.className = 'module-badge chip-running';
                badge.style.color = 'var(--status-high)';
                badge.style.borderColor = 'var(--status-high)';
            }
        });
    },

    async scanComplete(scanId) {
        this.progressBar.style.width = '100%';
        this.progressDetails.textContent = 'Analysis complete. Aggregating intelligence...';

        // Fetch full report
        const report = await api.get(`/scan/${scanId}/report`);
        
        // Save to App state AND localStorage
        App.saveReport(report);

        // Reset button
        this.scanBtn.disabled = false;
        this.scanBtn.innerHTML = '<span class="material-icons-outlined">play_arrow</span> INIT SCAN';

        // Navigate to results
        setTimeout(() => {
            this.progressSection.classList.add('is-hidden');
            App.showView('results');
            Dashboard.render(report);
            Timeline.render(report);
        }, 800);
    },
};
