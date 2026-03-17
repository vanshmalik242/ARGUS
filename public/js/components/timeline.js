/**
 * Timeline Component — renders event timeline from scan results
 * Uses CSS classes: .timeline-item, .timeline-dot, .timeline-body, .timeline-date, .timeline-event-text, .timeline-source
 */
const Timeline = {
    report: null,

    render(report) {
        this.report = report;
        const events = report.profile?.timeline || [];
        this.renderChart(events);
        this.renderList(events);
    },

    renderChart(events) {
        const container = document.getElementById('timeline-chart');
        if (events.length === 0) {
            container.innerHTML = '<div class="empty-state" style="height:100%"><span class="material-icons-outlined">timeline</span><p>No timeline events</p></div>';
            return;
        }

        // Group by category
        const categoryColors = {
            infrastructure: '#58A6FF',
            breach: '#F85149',
            archive: '#00E5FF',
            social: '#3FB950',
        };

        // Create a simple bar visualization
        const dates = events.filter(e => e.date).map(e => new Date(e.date)).filter(d => !isNaN(d));
        if (dates.length === 0) {
            container.innerHTML = '<div class="empty-state" style="height:100%"><span class="material-icons-outlined">timeline</span><p>No datable events</p></div>';
            return;
        }

        const minDate = new Date(Math.min(...dates));
        const maxDate = new Date(Math.max(...dates));
        const range = maxDate - minDate || 1;

        container.innerHTML = `
      <div style="position:relative;height:100%;padding:16px">
        <div style="position:absolute;bottom:30px;left:16px;right:16px;height:2px;background:var(--border-light)"></div>
        ${events.filter(e => e.date && !isNaN(new Date(e.date))).map((evt, i) => {
            const d = new Date(evt.date);
            const pos = ((d - minDate) / range) * 90 + 5;
            const color = categoryColors[evt.category] || '#7C4DFF';
            return `
            <div style="position:absolute;left:${pos}%;bottom:32px;transform:translateX(-50%)" title="${evt.date}: ${evt.event}">
              <div style="width:8px;height:${20 + (i % 3) * 15}px;background:${color};border-radius:4px 4px 0 0;margin:0 auto"></div>
              <div style="width:12px;height:12px;background:${color};border-radius:50%;border:2px solid var(--bg-surface);margin-top:-1px"></div>
            </div>
          `;
        }).join('')}
        <div style="position:absolute;bottom:8px;left:16px;font-size:11px;color:var(--text-muted);font-family:var(--font-mono)">${minDate.toISOString().split('T')[0]}</div>
        <div style="position:absolute;bottom:8px;right:16px;font-size:11px;color:var(--text-muted);font-family:var(--font-mono)">${maxDate.toISOString().split('T')[0]}</div>
      </div>
    `;
    },

    renderList(events) {
        const container = document.getElementById('timeline-list');

        if (events.length === 0) {
            container.innerHTML = '<div class="empty-state"><span class="material-icons-outlined">timeline</span><h3>No Events</h3><p>Run a scan to discover timeline events.</p></div>';
            return;
        }

        // Sort by date
        const sorted = [...events].sort((a, b) => {
            const da = new Date(a.date);
            const db = new Date(b.date);
            return da - db;
        });

        container.innerHTML = sorted.map(evt => `
      <div class="timeline-item ${evt.category || ''}">
        <div class="timeline-dot"></div>
        <div class="timeline-body">
          <div class="timeline-date">${evt.date || 'Unknown date'}</div>
          <div class="timeline-event-text">${evt.event}</div>
          <div class="timeline-source">${evt.source || ''}</div>
        </div>
      </div>
    `).join('');
    },
};
