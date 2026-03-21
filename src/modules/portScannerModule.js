/**
 * Asynchronous TCP Port Scanner
 * Scans top 50 critical ports concurrently for a given IP/Domain.
 */
const net = require('net');

const TOP_PORTS = [
    { port: 20, service: 'FTP-DATA' }, { port: 21, service: 'FTP' }, { port: 22, service: 'SSH' },
    { port: 23, service: 'Telnet' }, { port: 25, service: 'SMTP' }, { port: 53, service: 'DNS' },
    { port: 80, service: 'HTTP' }, { port: 110, service: 'POP3' }, { port: 111, service: 'RPCBind' },
    { port: 135, service: 'MSRPC' }, { port: 139, service: 'NetBIOS' }, { port: 143, service: 'IMAP' },
    { port: 443, service: 'HTTPS' }, { port: 445, service: 'SMB' }, { port: 993, service: 'IMAPS' },
    { port: 995, service: 'POP3S' }, { port: 1723, service: 'PPTP' }, { port: 3306, service: 'MySQL' },
    { port: 3389, service: 'RDP' }, { port: 5432, service: 'PostgreSQL' }, { port: 5900, service: 'VNC' },
    { port: 6379, service: 'Redis' }, { port: 8080, service: 'HTTP-Proxy' }, { port: 8443, service: 'HTTPS-Alt' },
    { port: 27017, service: 'MongoDB' }
];

function checkPort(host, port, timeout = 1500) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        let status = 'closed';

        socket.on('connect', () => {
            status = 'open';
            socket.destroy();
        });

        socket.setTimeout(timeout);
        socket.on('timeout', () => {
            socket.destroy();
        });

        socket.on('error', () => {
            // Refused or host unreachable
        });

        socket.on('close', () => {
            resolve({ port, status });
        });

        socket.connect(port, host);
    });
}

async function scanPorts(target) {
    const result = {
        target: target,
        openPorts: [],
        totalScanned: TOP_PORTS.length,
        vulnerable: false
    };

    try {
        // Quick async connect scan
        const checks = TOP_PORTS.map(p => checkPort(target, p.port).then(res => ({ ...p, status: res.status })));
        
        const results = await Promise.all(checks);
        
        result.openPorts = results.filter(r => r.status === 'open').map(r => ({
            port: r.port,
            service: r.service
        }));

        const criticalPorts = [21, 23, 25, 3306, 5432, 27017, 6379, 5900, 3389];
        const exposedCritical = result.openPorts.find(p => criticalPorts.includes(p.port));
        
        if (exposedCritical) {
            result.vulnerable = true;
            result.warning = `Exposed critical infrastructure port detected: ${exposedCritical.port} (${exposedCritical.service})`;
        }
    } catch (err) {
        result.error = err.message;
    }

    return result;
}

module.exports = { scanPorts };
