/**
 * Network Map Component — SVG-based entity/relationship visualization
 * Demonstrates: SVG manipulation, basic graph layout logic, interactive UI
 */
const NetworkMap = {
    containerId: 'view-results', // Default container to find width/height
    svg: null,
    nodes: [],
    links: [],
    padding: 60,

    render(report) {
        const tabContent = document.getElementById('tab-content');
        if (!tabContent) return;

        // Clear and setup container
        tabContent.innerHTML = `
            <div class="network-map-container" id="net-map">
                <svg id="net-svg" width="100%" height="100%" style="background: var(--bg-base)"></svg>
                <div id="net-tooltip" class="glass-panel" style="position:absolute; padding:10px; pointer-events:none; display:none; z-index:100; font-size:12px; border-color:var(--accent-primary)"></div>
            </div>
        `;

        const svg = document.getElementById('net-svg');
        const container = document.getElementById('net-map');
        const width = container.clientWidth;
        const height = container.clientHeight;

        const profile = report.profile || {};
        const rawEntities = profile.entities || [];
        const rawRelations = profile.relationships || [];

        // 1. Prepare Nodes (Entity uniqueness)
        const nodeMap = new Map();
        
        // Add target as central node
        nodeMap.set(report.target, { 
            id: report.target, 
            label: report.target, 
            type: 'target', 
            color: 'var(--accent-primary)',
            size: 15
        });

        const entityColors = {
            ip: 'var(--accent-primary)',
            domain: '#8A2BE2',
            person: '#2ed573',
            repository: '#ffa502',
            email: '#ff4757',
            technology: '#00E5FF',
            nameserver: '#7C4DFF',
            subdomain: '#BA68C8'
        };

        rawEntities.forEach(e => {
            const id = e.value || e.name;
            if (id && !nodeMap.has(id)) {
                nodeMap.set(id, {
                    id: id,
                    label: id.length > 20 ? id.substring(0, 17) + '...' : id,
                    type: e.type,
                    color: entityColors[e.type] || 'var(--text-muted)',
                    size: 8
                });
            }
        });

        this.nodes = Array.from(nodeMap.values());

        // 2. Prepare Links
        this.links = rawRelations
            .filter(r => nodeMap.has(r.from) && nodeMap.has(r.to))
            .map(r => ({
                source: r.from,
                target: r.to,
                type: r.type
            }));

        // 3. Simple Radial/Random Layout (since we don't have d3)
        this.nodes.forEach((node, i) => {
            if (node.type === 'target') {
                node.x = width / 2;
                node.y = height / 2;
            } else {
                const angle = (i / this.nodes.length) * 2 * Math.PI;
                const radius = Math.min(width, height) * 0.35 * (0.8 + Math.random() * 0.4);
                node.x = width / 2 + Math.cos(angle) * radius;
                node.y = height / 2 + Math.sin(angle) * radius;
            }
        });

        // 4. Draw
        this.draw(svg);
    },

    draw(svg) {
        let html = '';

        // Draw Links
        this.links.forEach(link => {
            const s = this.nodes.find(n => n.id === link.source);
            const t = this.nodes.find(n => n.id === link.target);
            if (s && t) {
                html += `<line x1="${s.x}" y1="${s.y}" x2="${t.x}" y2="${t.y}" class="link" stroke-width="1" />`;
            }
        });

        // Draw Nodes
        this.nodes.forEach(node => {
            html += `
                <g class="node" data-id="${node.id}" data-type="${node.type}">
                    <circle cx="${node.x}" cy="${node.y}" r="${node.size}" fill="${node.color}" />
                    <text x="${node.x}" y="${node.y + node.size + 15}" text-anchor="middle" class="node-label">${node.label}</text>
                </g>
            `;
        });

        svg.innerHTML = html;

        // Add interactivity
        const tooltip = document.getElementById('net-tooltip');
        svg.querySelectorAll('.node').forEach(nodeEl => {
            nodeEl.addEventListener('mouseenter', (e) => {
                const id = nodeEl.dataset.id;
                const type = nodeEl.dataset.type;
                tooltip.style.display = 'block';
                tooltip.innerHTML = `<strong>${id}</strong><br><span style="color:var(--text-muted)">Type: ${type}</span>`;
            });
            nodeEl.addEventListener('mousemove', (e) => {
                tooltip.style.left = (e.pageX + 15) + 'px';
                tooltip.style.top = (e.pageY + 15) + 'px';
            });
            nodeEl.addEventListener('mouseleave', () => {
                tooltip.style.display = 'none';
            });
        });
    }
};
