/**
 * API utility — fetch wrapper and SSE handler
 */
const API_BASE = '/api';

const api = {
    async post(endpoint, data) {
        const res = await fetch(`${API_BASE}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });
        if (res.status === 401) {
            document.getElementById('login-modal').classList.remove('is-hidden');
            throw new Error('Authentication required');
        }
        return res.json();
    },

    async get(endpoint) {
        const res = await fetch(`${API_BASE}${endpoint}`);
        if (res.status === 401) {
            document.getElementById('login-modal').classList.remove('is-hidden');
            throw new Error('Authentication required');
        }
        return res.json();
    },

    /**
     * Subscribe to SSE stream for scan progress
     */
    streamScan(scanId, onUpdate, onComplete) {
        const evtSource = new EventSource(`${API_BASE}/scan/${scanId}/stream`);

        evtSource.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.done) {
                evtSource.close();
                if (onComplete) onComplete(data);
            } else {
                if (onUpdate) onUpdate(data);
            }
        };

        evtSource.onerror = () => {
            evtSource.close();
            if (onComplete) onComplete({ status: 'error' });
        };

        return evtSource;
    },

    getExportUrl(scanId, format) {
        return `${API_BASE}/scan/${scanId}/export?format=${format}`;
    },
};
