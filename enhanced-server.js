const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const rateLimit = require('express-rate-limit');
const fs = require('fs');

const app = express();
const PORT = 3000;

// Rate limiting middleware
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs
    message: 'Too many login attempts, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

// IP blocking storage
const blockedIPs = new Set();
const suspiciousIPs = new Map(); // IP -> count

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// IP blocking middleware
app.use((req, res, next) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    if (blockedIPs.has(clientIP)) {
        return res.status(403).send('Access denied');
    }
    next();
});

// Enhanced database setup
const db = new sqlite3.Database('./honeypot.db', (err) => {
    if (err) {
        console.error('DB connection error:', err.message);
    } else {
        console.log('Connected to SQLite DB.');
        
        // Enhanced logs table
        db.run(`CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            user_agent TEXT,
            payload TEXT,
            attack_type TEXT,
            severity INTEGER,
            geolocation TEXT,
            session_id TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Attack statistics table
        db.run(`CREATE TABLE IF NOT EXISTS attack_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT,
            total_attempts INTEGER,
            unique_ips INTEGER,
            blocked_ips INTEGER,
            attack_types TEXT
        )`);
    }
});

// Enhanced suspicious pattern detection
function analyzeAttack(input, userAgent = '') {
    const patterns = {
        'SQL Injection': [
            /(\bor\b|\band\b).*=.*--/i,
            /('|;|--|\/\*|\*\/|union|select|drop|insert|update|delete)/i,
            /(\bor\b|\band\b).*(\b1=1\b|\btrue\b)/i
        ],
        'XSS': [
            /<script.*?>.*?<\/script>/i,
            /javascript:/i,
            /<.*?on\w+=.*?>/i,
            /alert\(|confirm\(|prompt\(/i
        ],
        'Command Injection': [
            /[;&|`$(){}]/,
            /\b(cat|ls|pwd|whoami|id|uname|wget|curl)\b/i
        ],
        'Path Traversal': [
            /\.\.[\/\\]/,
            /\/etc\/passwd|\/etc\/shadow/i
        ],
        'Bot/Scanner': [
            /bot|crawler|spider|scan/i
        ]
    };

    let detectedAttacks = [];
    let maxSeverity = 0;

    for (const [attackType, patternList] of Object.entries(patterns)) {
        for (const pattern of patternList) {
            if (pattern.test(input) || pattern.test(userAgent)) {
                detectedAttacks.push(attackType);
                maxSeverity = Math.max(maxSeverity, getSeverity(attackType));
                break;
            }
        }
    }

    return {
        isAttack: detectedAttacks.length > 0,
        attackTypes: detectedAttacks,
        severity: maxSeverity
    };
}

function getSeverity(attackType) {
    const severityMap = {
        'SQL Injection': 5,
        'Command Injection': 5,
        'XSS': 4,
        'Path Traversal': 4,
        'Bot/Scanner': 2
    };
    return severityMap[attackType] || 1;
}

// Session tracking
function generateSessionId() {
    return Math.random().toString(36).substring(2, 15);
}

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Enhanced login handler
app.post('/login', loginLimiter, (req, res) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('User-Agent') || '';
    const username = req.body.username || '';
    const password = req.body.password || '';
    const sessionId = req.session?.id || generateSessionId();

    const combinedInput = `${username} ${password}`;
    const analysis = analyzeAttack(combinedInput, userAgent);

    // Track suspicious IPs
    if (analysis.isAttack) {
        const count = suspiciousIPs.get(clientIP) || 0;
        suspiciousIPs.set(clientIP, count + 1);
        
        // Block IP after 3 suspicious attempts
        if (count >= 2) {
            blockedIPs.add(clientIP);
            console.log(`🚫 Blocked IP: ${clientIP}`);
        }
    }

    // Enhanced logging
    const stmt = db.prepare(`INSERT INTO logs 
        (ip, user_agent, payload, attack_type, severity, session_id) 
        VALUES (?, ?, ?, ?, ?, ?)`);
    
    stmt.run(
        clientIP,
        userAgent,
        `username=${username} password=${password}`,
        analysis.attackTypes.join(', ') || 'Normal',
        analysis.severity,
        sessionId
    );
    stmt.finalize();

    // Response based on attack detection
    let response = 'Login failed. Please try again.';
    if (analysis.isAttack) {
        response = `🚨 Suspicious activity detected! ${response}`;
        console.log(`🚨 Attack detected from ${clientIP}: ${analysis.attackTypes.join(', ')}`);
    }

    res.send(response);
});

// Decoy endpoints to attract attackers
app.get('/admin.php', (req, res) => logDecoyAccess(req, res, 'admin.php'));
app.get('/wp-admin', (req, res) => logDecoyAccess(req, res, 'wp-admin'));
app.get('/phpmyadmin', (req, res) => logDecoyAccess(req, res, 'phpmyadmin'));
app.get('/.env', (req, res) => logDecoyAccess(req, res, '.env'));
app.get('/config.php', (req, res) => logDecoyAccess(req, res, 'config.php'));

function logDecoyAccess(req, res, endpoint) {
    const clientIP = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('User-Agent') || '';
    
    const stmt = db.prepare(`INSERT INTO logs 
        (ip, user_agent, payload, attack_type, severity) 
        VALUES (?, ?, ?, ?, ?)`);
    
    stmt.run(clientIP, userAgent, `Accessed decoy endpoint: ${endpoint}`, 'Reconnaissance', 3);
    stmt.finalize();
    
    console.log(`🎯 Decoy accessed: ${endpoint} from ${clientIP}`);
    res.status(404).send('Not Found');
}

// Enhanced admin dashboard
app.get('/admin', (req, res) => {
    db.all(`SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100`, [], (err, rows) => {
        if (err) {
            return res.status(500).send('Database error');
        }

        // Get statistics
        db.get(`SELECT 
            COUNT(*) as total,
            COUNT(DISTINCT ip) as unique_ips,
            AVG(severity) as avg_severity
            FROM logs WHERE date(timestamp) = date('now')`, [], (err, stats) => {
            
            let html = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>Enhanced Honeypot Dashboard</title>
                <link rel="stylesheet" href="/style.css">
                <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
                <style>
                    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
                    .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); text-align: center; }
                    .stat-number { font-size: 2em; font-weight: bold; color: #3498db; }
                    .severity-high { background-color: #ffebee; }
                    .severity-medium { background-color: #fff3e0; }
                    .severity-low { background-color: #e8f5e8; }
                    .export-btn { background: #27ae60; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 10px; }
                </style>
            </head>
            <body>
                <div class="admin-container">
                    <h2>🍯 Enhanced Honeypot Dashboard</h2>
                    
                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-number">${stats?.total || 0}</div>
                            <div>Total Attempts Today</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">${stats?.unique_ips || 0}</div>
                            <div>Unique IPs</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">${blockedIPs.size}</div>
                            <div>Blocked IPs</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">${(stats?.avg_severity || 0).toFixed(1)}</div>
                            <div>Avg Threat Level</div>
                        </div>
                    </div>

                    <div style="margin: 20px 0;">
                        <a href="/export/csv" class="export-btn">📊 Export CSV</a>
                        <a href="/export/json" class="export-btn">📋 Export JSON</a>
                        <a href="/blocked-ips" class="export-btn">🚫 View Blocked IPs</a>
                    </div>
                    
                    <table>
                        <tr>
                            <th>ID</th><th>IP</th><th>Attack Type</th><th>Severity</th>
                            <th>Payload</th><th>User Agent</th><th>Timestamp</th>
                        </tr>`;

            rows.forEach((row) => {
                const severityClass = row.severity >= 4 ? 'severity-high' : 
                                    row.severity >= 2 ? 'severity-medium' : 'severity-low';
                html += `
                <tr class="${severityClass}">
                    <td>${row.id}</td>
                    <td>${row.ip}</td>
                    <td>${row.attack_type}</td>
                    <td>${row.severity}</td>
                    <td>${row.payload.substring(0, 50)}...</td>
                    <td>${(row.user_agent || '').substring(0, 30)}...</td>
                    <td>${row.timestamp}</td>
                </tr>`;
            });

            html += `</table></div></body></html>`;
            res.send(html);
        });
    });
});

// Export endpoints
app.get('/export/csv', (req, res) => {
    db.all('SELECT * FROM logs ORDER BY timestamp DESC', [], (err, rows) => {
        if (err) return res.status(500).send('Database error');
        
        let csv = 'ID,IP,Attack Type,Severity,Payload,User Agent,Timestamp\n';
        rows.forEach(row => {
            csv += `${row.id},"${row.ip}","${row.attack_type}",${row.severity},"${row.payload}","${row.user_agent}","${row.timestamp}"\n`;
        });
        
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=honeypot-logs.csv');
        res.send(csv);
    });
});

app.get('/export/json', (req, res) => {
    db.all('SELECT * FROM logs ORDER BY timestamp DESC', [], (err, rows) => {
        if (err) return res.status(500).send('Database error');
        
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', 'attachment; filename=honeypot-logs.json');
        res.json(rows);
    });
});

app.get('/blocked-ips', (req, res) => {
    const blockedList = Array.from(blockedIPs);
    res.json({ 
        blocked_ips: blockedList,
        count: blockedList.length,
        suspicious_ips: Object.fromEntries(suspiciousIPs)
    });
});

app.listen(PORT, () => {
    console.log(`🍯 Enhanced Honeypot running at http://localhost:${PORT}`);
    console.log(`📊 Admin dashboard: http://localhost:${PORT}/admin`);
});