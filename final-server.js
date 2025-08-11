const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const geoip = require('geoip-lite');
const config = require('./config');
const alertSystem = require('./alerts');

const app = express();
const PORT = config.server.port;

// Session configuration
app.use(session({
    secret: 'honeypot-secret-key-change-in-production',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Rate limiting
const loginLimiter = rateLimit(config.rateLimit);

// IP blocking and tracking
const blockedIPs = new Set();
const suspiciousIPs = new Map();
const ipAttempts = new Map();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Enhanced IP tracking middleware
app.use((req, res, next) => {
    const clientIP = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'];
    req.clientIP = clientIP;
    
    // Check if IP is blocked
    if (blockedIPs.has(clientIP)) {
        console.log(`🚫 Blocked IP attempted access: ${clientIP}`);
        return res.status(403).json({ error: 'Access denied' });
    }
    
    // Track IP attempts
    const attempts = ipAttempts.get(clientIP) || 0;
    ipAttempts.set(clientIP, attempts + 1);
    
    next();
});

// Enhanced database setup
const db = new sqlite3.Database(config.database.path, (err) => {
    if (err) {
        console.error('DB connection error:', err.message);
    } else {
        console.log('Connected to SQLite DB.');
        
        // Create enhanced tables
        db.run(`CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            user_agent TEXT,
            payload TEXT,
            attack_type TEXT,
            severity INTEGER,
            geolocation TEXT,
            country_code TEXT,
            session_id TEXT,
            endpoint TEXT,
            method TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            reason TEXT,
            blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            attempts INTEGER DEFAULT 1
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS daily_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT UNIQUE,
            total_attempts INTEGER,
            unique_ips INTEGER,
            blocked_ips INTEGER,
            top_attack_types TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
    }
});

// Enhanced attack detection
function analyzeAttack(input, userAgent = '', endpoint = '') {
    const patterns = {
        'SQL Injection': [
            /(\bor\b|\band\b).*=.*--/i,
            /('|;|--|\/\*|\*\/|union|select|drop|insert|update|delete)/i,
            /(\bor\b|\band\b).*(\b1=1\b|\btrue\b)/i,
            /\bwaitfor\b.*\bdelay\b/i,
            /\bsleep\s*\(/i
        ],
        'XSS': [
            /<script.*?>.*?<\/script>/i,
            /javascript:/i,
            /<.*?on\w+=.*?>/i,
            /alert\(|confirm\(|prompt\(/i,
            /<iframe|<object|<embed/i
        ],
        'Command Injection': [
            /[;&|`$(){}]/,
            /\b(cat|ls|pwd|whoami|id|uname|wget|curl|nc|netcat)\b/i,
            /\|\s*(cat|ls|pwd|whoami)/i
        ],
        'Path Traversal': [
            /\.\.[\/\\]/,
            /\/etc\/passwd|\/etc\/shadow|\/proc\/|\/sys\//i,
            /\.\.\\|\.\.\/|%2e%2e/i
        ],
        'Bot/Scanner': [
            /bot|crawler|spider|scan|nmap|sqlmap|nikto|dirb|gobuster/i,
            /python-requests|curl\/|wget\//i
        ],
        'Reconnaissance': [
            /\/admin|\/wp-admin|\/phpmyadmin|\/config|\/backup/i,
            /\.env|\.git|\.svn|web\.config/i
        ]
    };

    let detectedAttacks = [];
    let maxSeverity = 0;
    const combinedInput = `${input} ${userAgent} ${endpoint}`;

    for (const [attackType, patternList] of Object.entries(patterns)) {
        for (const pattern of patternList) {
            if (pattern.test(combinedInput)) {
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
        'Reconnaissance': 3,
        'Bot/Scanner': 2
    };
    return severityMap[attackType] || 1;
}

// Enhanced logging function
function logAttack(req, payload, analysis, endpoint = '/login') {
    const clientIP = req.clientIP;
    const userAgent = req.get('User-Agent') || '';
    const sessionId = req.session.id;
    const geo = geoip.lookup(clientIP);
    const geolocation = geo ? `${geo.city}, ${geo.country}` : 'Unknown';
    const countryCode = geo ? geo.country : 'Unknown';

    const stmt = db.prepare(`INSERT INTO logs 
        (ip, user_agent, payload, attack_type, severity, geolocation, country_code, session_id, endpoint, method) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    
    stmt.run(
        clientIP,
        userAgent,
        payload,
        analysis.attackTypes.join(', ') || 'Normal',
        analysis.severity,
        geolocation,
        countryCode,
        sessionId,
        endpoint,
        req.method
    );
    stmt.finalize();

    // Send alerts for high-severity attacks
    if (analysis.isAttack && analysis.severity >= 3) {
        alertSystem.sendAttackAlert({
            ip: clientIP,
            attackTypes: analysis.attackTypes,
            severity: analysis.severity,
            payload: payload,
            userAgent: userAgent,
            geolocation: geolocation,
            timestamp: new Date().toISOString()
        });
    }
}

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/analytics.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'analytics.html'));
});

// Enhanced login handler
app.post('/login', loginLimiter, (req, res) => {
    const username = req.body.username || '';
    const password = req.body.password || '';
    const combinedInput = `username=${username} password=${password}`;
    
    const analysis = analyzeAttack(combinedInput, req.get('User-Agent'), '/login');
    logAttack(req, combinedInput, analysis);

    // Track suspicious activity
    if (analysis.isAttack) {
        const clientIP = req.clientIP;
        const count = suspiciousIPs.get(clientIP) || 0;
        suspiciousIPs.set(clientIP, count + 1);
        
        // Block IP after threshold
        if (count >= config.ipBlocking.maxSuspiciousAttempts - 1) {
            blockedIPs.add(clientIP);
            
            // Add to blocked IPs table
            const stmt = db.prepare('INSERT OR REPLACE INTO blocked_ips (ip, reason, attempts) VALUES (?, ?, ?)');
            stmt.run(clientIP, `Exceeded ${config.ipBlocking.maxSuspiciousAttempts} suspicious attempts`, count + 1);
            stmt.finalize();
            
            console.log(`🚫 Blocked IP: ${clientIP} after ${count + 1} suspicious attempts`);
        }
    }

    // Response
    let response = 'Login failed. Please try again.';
    if (analysis.isAttack) {
        response = `🚨 Suspicious activity detected! ${response}`;
        console.log(`🚨 Attack detected from ${req.clientIP}: ${analysis.attackTypes.join(', ')}`);
    }

    res.send(response);
});

// Decoy endpoints
const decoyEndpoints = config.decoyServices.endpoints;
decoyEndpoints.forEach(endpoint => {
    app.get(endpoint, (req, res) => {
        const analysis = analyzeAttack('', req.get('User-Agent'), endpoint);
        analysis.attackTypes.push('Reconnaissance');
        analysis.severity = Math.max(analysis.severity, 3);
        
        logAttack(req, `Accessed decoy endpoint: ${endpoint}`, analysis, endpoint);
        console.log(`🎯 Decoy accessed: ${endpoint} from ${req.clientIP}`);
        
        res.status(404).send('Not Found');
    });
});

// API endpoints
app.get('/api/stats', (req, res) => {
    const queries = [
        'SELECT COUNT(*) as total FROM logs WHERE date(timestamp) = date("now")',
        'SELECT COUNT(DISTINCT ip) as unique_ips FROM logs WHERE date(timestamp) = date("now")',
        'SELECT COUNT(*) as blocked FROM blocked_ips',
        'SELECT attack_type, COUNT(*) as count FROM logs WHERE date(timestamp) = date("now") AND attack_type != "Normal" GROUP BY attack_type ORDER BY count DESC LIMIT 5'
    ];

    Promise.all(queries.map(query => 
        new Promise((resolve, reject) => {
            db.all(query, [], (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        })
    )).then(results => {
        res.json({
            totalAttacks: results[0][0].total,
            uniqueIPs: results[1][0].unique_ips,
            blockedIPs: results[2][0].blocked,
            topAttackTypes: results[3]
        });
    }).catch(err => {
        res.status(500).json({ error: 'Database error' });
    });
});

// Enhanced admin dashboard
app.get('/admin', (req, res) => {
    db.all(`SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100`, [], (err, rows) => {
        if (err) {
            return res.status(500).send('Database error');
        }

        let html = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>🍯 Enhanced Honeypot Dashboard</title>
            <link rel="stylesheet" href="/style.css">
            <meta http-equiv="refresh" content="30">
            <style>
                .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
                .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); text-align: center; }
                .stat-number { font-size: 2em; font-weight: bold; color: #3498db; }
                .severity-5 { background-color: #ffebee; border-left: 4px solid #e74c3c; }
                .severity-4 { background-color: #fff3e0; border-left: 4px solid #f39c12; }
                .severity-3 { background-color: #fff8e1; border-left: 4px solid #f1c40f; }
                .severity-2, .severity-1 { background-color: #e8f5e8; border-left: 4px solid #27ae60; }
                .export-btn { background: #27ae60; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 5px; display: inline-block; }
                .blocked-ip { color: #e74c3c; font-weight: bold; }
            </style>
        </head>
        <body>
            <div class="admin-container">
                <h2>🍯 Enhanced Honeypot Dashboard</h2>
                <p><strong>Status:</strong> Active | <strong>Blocked IPs:</strong> ${blockedIPs.size} | <strong>Last Updated:</strong> ${new Date().toLocaleString()}</p>
                
                <div style="margin: 20px 0;">
                    <a href="/export/csv" class="export-btn">📊 Export CSV</a>
                    <a href="/export/json" class="export-btn">📋 Export JSON</a>
                    <a href="/blocked-ips" class="export-btn">🚫 Blocked IPs</a>
                    <a href="/analytics.html" class="export-btn">📈 Analytics</a>
                </div>
                
                <table>
                    <tr>
                        <th>ID</th><th>IP</th><th>Location</th><th>Attack Type</th><th>Severity</th>
                        <th>Payload</th><th>Endpoint</th><th>Timestamp</th>
                    </tr>`;

        rows.forEach((row) => {
            const severityClass = `severity-${row.severity}`;
            const ipClass = blockedIPs.has(row.ip) ? 'blocked-ip' : '';
            html += `
            <tr class="${severityClass}">
                <td>${row.id}</td>
                <td class="${ipClass}">${row.ip}</td>
                <td>${row.geolocation || 'Unknown'}</td>
                <td>${row.attack_type}</td>
                <td>${row.severity}</td>
                <td title="${row.payload}">${row.payload.substring(0, 50)}...</td>
                <td>${row.endpoint}</td>
                <td>${new Date(row.timestamp).toLocaleString()}</td>
            </tr>`;
        });

        html += `
                </table>
                <div style="margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 8px;">
                    <h4>🛡️ Security Status</h4>
                    <p><strong>Active Sessions:</strong> ${ipAttempts.size}</p>
                    <p><strong>Suspicious IPs:</strong> ${suspiciousIPs.size}</p>
                    <p><strong>Total Blocked:</strong> ${blockedIPs.size}</p>
                </div>
            </div>
        </body>
        </html>`;
        
        res.send(html);
    });
});

// Export and utility endpoints
app.get('/export/csv', (req, res) => {
    db.all('SELECT * FROM logs ORDER BY timestamp DESC', [], (err, rows) => {
        if (err) return res.status(500).send('Database error');
        
        let csv = 'ID,IP,Location,Attack Type,Severity,Payload,User Agent,Endpoint,Timestamp\n';
        rows.forEach(row => {
            csv += `${row.id},"${row.ip}","${row.geolocation}","${row.attack_type}",${row.severity},"${row.payload}","${row.user_agent}","${row.endpoint}","${row.timestamp}"\n`;
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
        res.json({
            export_date: new Date().toISOString(),
            total_records: rows.length,
            logs: rows
        });
    });
});

app.get('/blocked-ips', (req, res) => {
    db.all('SELECT * FROM blocked_ips ORDER BY blocked_at DESC', [], (err, rows) => {
        if (err) return res.status(500).send('Database error');
        
        res.json({
            blocked_ips: rows,
            count: rows.length,
            suspicious_ips: Object.fromEntries(suspiciousIPs),
            active_sessions: ipAttempts.size
        });
    });
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        blocked_ips: blockedIPs.size,
        suspicious_ips: suspiciousIPs.size
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`🍯 Enhanced Honeypot Server running at http://localhost:${PORT}`);
    console.log(`📊 Admin Dashboard: http://localhost:${PORT}/admin`);
    console.log(`📈 Analytics: http://localhost:${PORT}/analytics.html`);
    console.log(`🔍 Health Check: http://localhost:${PORT}/health`);
    console.log(`\n🛡️ Security Features Active:`);
    console.log(`   ✅ Rate Limiting: ${config.rateLimit.max} attempts per ${config.rateLimit.windowMs/1000/60} minutes`);
    console.log(`   ✅ IP Blocking: After ${config.ipBlocking.maxSuspiciousAttempts} suspicious attempts`);
    console.log(`   ✅ Attack Detection: ${Object.keys(analyzeAttack('test').attackTypes || {}).length} pattern types`);
    console.log(`   ✅ Geolocation: ${config.geolocation.enabled ? 'Enabled' : 'Disabled'}`);
    console.log(`   ✅ Email Alerts: ${config.emailAlerts.enabled ? 'Enabled' : 'Disabled'}`);
    console.log(`\n🎯 Decoy Endpoints: ${decoyEndpoints.length} active`);
    console.log(`\n🚨 Ready to catch attackers!`);
});