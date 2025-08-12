const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Advanced rate limiting with IP tracking
const attackLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20,
    message: 'Rate limit exceeded',
    standardHeaders: true,
    legacyHeaders: false,
});

app.use(attackLimiter);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Session management
app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 24 * 60 * 60 * 1000,
        secure: false,
        httpOnly: true
    }
}));

// Enterprise database setup
const db = new sqlite3.Database('enterprise-honeypot.db', (err) => {
    if (err) {
        console.error('Database connection failed:', err.message);
    } else {
        console.log('✅ Enterprise database connected');
        initEnterpriseDB();
    }
});

function initEnterpriseDB() {
    // Advanced attack logging table
    db.run(`CREATE TABLE IF NOT EXISTS threat_intelligence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL,
        user_agent TEXT,
        attack_vector TEXT,
        payload TEXT,
        attack_classification TEXT,
        severity_score INTEGER,
        confidence_level REAL,
        endpoint_targeted TEXT,
        session_id TEXT,
        geolocation TEXT,
        isp_info TEXT,
        threat_category TEXT,
        mitigation_applied TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        risk_assessment TEXT
    )`);
    
    // IP reputation and blocking
    db.run(`CREATE TABLE IF NOT EXISTS ip_reputation (
        ip_address TEXT PRIMARY KEY,
        reputation_score INTEGER,
        threat_level TEXT,
        first_seen DATETIME,
        last_seen DATETIME,
        attack_count INTEGER DEFAULT 1,
        blocked_until DATETIME,
        country_code TEXT,
        organization TEXT
    )`);
    
    // Attack patterns and signatures
    db.run(`CREATE TABLE IF NOT EXISTS attack_signatures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        signature_name TEXT,
        pattern TEXT,
        attack_type TEXT,
        severity INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // Security events and alerts
    db.run(`CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT,
        severity TEXT,
        description TEXT,
        ip_address TEXT,
        automated_response TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    insertDefaultSignatures();
}

function insertDefaultSignatures() {
    const signatures = [
        ['SQL Injection - Union Based', "('|union|select|drop|insert|delete|update|--|/\\*|\\*/)", 'SQL_INJECTION', 9],
        ['XSS - Script Injection', '(<script|javascript:|on\\w+\\s*=|<iframe|<object)', 'XSS', 8],
        ['Path Traversal', '(\\.\\./|\\.\\\\|%2e%2e%2f|%2e%2e\\\\)', 'PATH_TRAVERSAL', 8],
        ['Command Injection', '(;|&&|\\|\\||`|\\$\\(|%0a|%0d)', 'COMMAND_INJECTION', 9],
        ['LDAP Injection', '(\\*|\\)|\\(|%28|%29|%2a)', 'LDAP_INJECTION', 7],
        ['XXE Attack', '(<!entity|<!doctype|system|public)', 'XXE', 8],
        ['SSRF Attempt', '(localhost|127\\.0\\.0\\.1|file://|http://|https://)', 'SSRF', 7],
        ['Directory Enumeration', '/(admin|wp-admin|phpmyadmin|backup|config)', 'DIRECTORY_ENUM', 5],
        ['Bot/Scanner Detection', '(nmap|sqlmap|burp|nikto|dirb|gobuster|masscan)', 'BOT_SCANNER', 6],
        ['Deserialization Attack', '(pickle|serialize|unserialize|__reduce__|eval)', 'DESERIALIZATION', 8]
    ];
    
    signatures.forEach(sig => {
        db.run('INSERT OR IGNORE INTO attack_signatures (signature_name, pattern, attack_type, severity) VALUES (?, ?, ?, ?)', sig);
    });
}

// Advanced threat classification engine
class ThreatIntelligenceEngine {
    static async classifyThreat(payload, endpoint, userAgent, ip) {
        return new Promise((resolve) => {
            db.all('SELECT * FROM attack_signatures', [], (err, signatures) => {
                if (err) {
                    resolve({ type: 'UNKNOWN', severity: 3, confidence: 0.5 });
                    return;
                }
                
                let bestMatch = { type: 'UNKNOWN', severity: 3, confidence: 0.5 };
                let maxSeverity = 0;
                
                signatures.forEach(sig => {
                    const regex = new RegExp(sig.pattern, 'i');
                    if (regex.test(payload) || regex.test(endpoint) || regex.test(userAgent)) {
                        if (sig.severity > maxSeverity) {
                            maxSeverity = sig.severity;
                            bestMatch = {
                                type: sig.attack_type,
                                severity: sig.severity,
                                confidence: 0.85,
                                signature: sig.signature_name
                            };
                        }
                    }
                });
                
                // Behavioral analysis
                if (userAgent && userAgent.includes('bot')) {
                    bestMatch.confidence += 0.1;
                }
                
                resolve(bestMatch);
            });
        });
    }
    
    static async updateIPReputation(ip, attackType, severity) {
        const reputationScore = Math.max(0, 100 - (severity * 10));
        const threatLevel = severity >= 8 ? 'CRITICAL' : severity >= 6 ? 'HIGH' : severity >= 4 ? 'MEDIUM' : 'LOW';
        
        db.run(`INSERT OR REPLACE INTO ip_reputation 
                (ip_address, reputation_score, threat_level, first_seen, last_seen, attack_count, country_code) 
                VALUES (?, ?, ?, COALESCE((SELECT first_seen FROM ip_reputation WHERE ip_address = ?), datetime('now')), 
                datetime('now'), COALESCE((SELECT attack_count FROM ip_reputation WHERE ip_address = ?) + 1, 1), 'Unknown')`,
                [ip, reputationScore, threatLevel, ip, ip]);
        
        // Auto-block critical threats
        if (severity >= 8) {
            const blockUntil = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
            db.run('UPDATE ip_reputation SET blocked_until = ? WHERE ip_address = ?', [blockUntil, ip]);
            
            // Log security event
            db.run('INSERT INTO security_events (event_type, severity, description, ip_address, automated_response) VALUES (?, ?, ?, ?, ?)',
                   ['AUTO_BLOCK', 'CRITICAL', `IP auto-blocked for ${attackType} attack`, ip, 'IP_BLOCKED_24H']);
        }
    }
}

// Middleware for threat detection and logging
async function threatDetectionMiddleware(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('User-Agent') || 'Unknown';
    const payload = JSON.stringify({ body: req.body, query: req.query, params: req.params, headers: req.headers });
    
    // Check if IP is blocked
    db.get('SELECT * FROM ip_reputation WHERE ip_address = ? AND blocked_until > datetime("now")', [ip], async (err, blocked) => {
        if (blocked) {
            return res.status(403).json({ error: 'Access denied - IP blocked due to malicious activity' });
        }
        
        // Classify threat
        const threat = await ThreatIntelligenceEngine.classifyThreat(payload, req.path, userAgent, ip);
        
        // Log to threat intelligence database
        const sessionId = req.session.id || crypto.randomBytes(16).toString('hex');
        db.run(`INSERT INTO threat_intelligence 
                (ip_address, user_agent, attack_vector, payload, attack_classification, severity_score, 
                confidence_level, endpoint_targeted, session_id, threat_category, timestamp) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
                [ip, userAgent, req.method, payload, threat.type, threat.severity, threat.confidence, 
                req.path, sessionId, threat.signature || 'Unknown']);
        
        // Update IP reputation
        await ThreatIntelligenceEngine.updateIPReputation(ip, threat.type, threat.severity);
        
        // Store threat info in request for later use
        req.threatInfo = threat;
        
        next();
    });
}

app.use(threatDetectionMiddleware);

// Authentication middleware
function requireAuth(req, res, next) {
    if (req.session.authenticated) {
        next();
    } else {
        res.redirect('/security-login');
    }
}

// Enterprise honeypot endpoints
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Security console login
app.get('/security-login', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Console - ThreatNet Enterprise</title>
        <link rel="stylesheet" href="/style.css">
    </head>
    <body>
        <div style="max-width: 450px; margin: 8rem auto; padding: 0 1rem;">
            <div style="background: rgba(30, 41, 59, 0.9); border: 1px solid #3b82f6; border-radius: 1rem; padding: 3rem; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);">
                <div style="text-align: center; margin-bottom: 2rem;">
                    <h1 style="color: #3b82f6; font-size: 2rem; margin-bottom: 0.5rem;">🛡️ ThreatNet</h1>
                    <p style="color: #94a3b8;">Enterprise Security Console</p>
                </div>
                <form method="POST" action="/security-login">
                    <div style="margin-bottom: 1.5rem;">
                        <label style="display: block; color: #f1f5f9; margin-bottom: 0.5rem; font-weight: 500;">Security Key</label>
                        <input type="password" name="password" placeholder="Enter security key" required 
                               style="width: 100%; padding: 1rem; border: 1px solid #475569; border-radius: 0.5rem; background: rgba(15, 23, 42, 0.8); color: #f1f5f9; font-size: 1rem;">
                    </div>
                    <button type="submit" style="width: 100%; padding: 1rem; background: linear-gradient(135deg, #3b82f6, #1d4ed8); color: white; border: none; border-radius: 0.5rem; cursor: pointer; font-size: 1rem; font-weight: 600;">
                        Access Console
                    </button>
                </form>
                <div style="text-align: center; margin-top: 2rem;">
                    <a href="/" style="color: #94a3b8; text-decoration: none; font-size: 0.875rem;">← Return to Main System</a>
                </div>
            </div>
        </div>
    </body>
    </html>`);
});

app.post('/security-login', (req, res) => {
    if (req.body.password === 'ThreatNet2024!') {
        req.session.authenticated = true;
        res.redirect('/threat-dashboard');
    } else {
        res.redirect('/security-login?error=invalid');
    }
});

// Enterprise fake services (honeypots)
const fakeServices = {
    '/wp-admin/': 'WordPress Admin Panel',
    '/phpmyadmin/': 'phpMyAdmin Database Interface',
    '/admin/': 'System Administration Panel',
    '/cpanel/': 'cPanel Control Panel',
    '/webmail/': 'Webmail Interface',
    '/ftp/': 'FTP File Manager',
    '/ssh/': 'SSH Terminal Access',
    '/api/v1/': 'REST API Endpoint',
    '/backup/': 'Backup Management System',
    '/config/': 'Configuration Management'
};

Object.keys(fakeServices).forEach(endpoint => {
    app.get(endpoint, (req, res) => {
        const serviceName = fakeServices[endpoint];
        res.send(`
        <!DOCTYPE html>
        <html><head><title>${serviceName}</title><link rel="stylesheet" href="/style.css"></head>
        <body style="background: #f8fafc; font-family: -apple-system,BlinkMacSystemFont,sans-serif;">
            <div style="max-width: 400px; margin: 100px auto; background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
                <h2 style="text-align: center; color: #1f2937; margin-bottom: 1rem;">${serviceName}</h2>
                <form method="post" action="${endpoint}login">
                    <div style="margin-bottom: 1rem;">
                        <input type="text" name="username" placeholder="Username" required
                               style="width: 100%; padding: 0.75rem; border: 1px solid #d1d5db; border-radius: 0.375rem; font-size: 1rem;">
                    </div>
                    <div style="margin-bottom: 1rem;">
                        <input type="password" name="password" placeholder="Password" required
                               style="width: 100%; padding: 0.75rem; border: 1px solid #d1d5db; border-radius: 0.375rem; font-size: 1rem;">
                    </div>
                    <button type="submit" style="width: 100%; padding: 0.75rem; background: #3b82f6; color: white; border: none; border-radius: 0.375rem; cursor: pointer; font-size: 1rem;">
                        Sign In
                    </button>
                </form>
                <div style="margin-top: 1rem; text-align: center; font-size: 0.875rem; color: #6b7280;">
                    <p>🔒 Secure ${serviceName}</p>
                </div>
            </div>
        </body></html>`);
    });
    
    app.post(endpoint + 'login', (req, res) => {
        const threat = req.threatInfo;
        res.send(`
        <!DOCTYPE html>
        <html><head><title>Authentication Failed</title><link rel="stylesheet" href="/style.css"></head>
        <body style="background: #1f2937; color: #f9fafb; font-family: monospace; text-align: center; padding: 100px;">
            <h1 style="color: #ef4444;">⚠️ Authentication Failed</h1>
            <p>Invalid credentials for ${serviceName}</p>
            <p style="color: #9ca3af; font-size: 0.875rem; margin-top: 2rem;">
                Threat Level: ${threat.severity}/10 | Classification: ${threat.type}
            </p>
            <a href="${endpoint}" style="color: #3b82f6; text-decoration: none;">← Try Again</a>
        </body></html>`);
    });
});

// Fake sensitive files
const sensitiveFiles = {
    '/.env': `# Production Environment Variables
DB_HOST=prod-db-cluster.company.com
DB_USER=admin_user
DB_PASS=Pr0d_P@ssw0rd_2024!
API_SECRET=sk-live-abc123def456ghi789
JWT_SECRET=super_secret_jwt_key_production
STRIPE_SECRET=sk_live_51234567890
AWS_ACCESS_KEY=AKIA1234567890ABCDEF
AWS_SECRET_KEY=abcdef1234567890/ABCDEFGHIJKLMNOP
REDIS_URL=redis://prod-cache.company.com:6379`,

    '/config.php': `<?php
// Production Database Configuration
define('DB_HOST', 'prod-mysql.company.com');
define('DB_USER', 'root');
define('DB_PASS', 'MyS3cur3P@ssw0rd!');
define('DB_NAME', 'production_database');
define('API_KEY', 'live_api_key_abc123def456');
define('ENCRYPTION_KEY', 'encryption_key_xyz789');
$admin_password = 'Admin123!@#';
?>`,

    '/backup/database.sql': `-- Production Database Backup
-- Generated: ${new Date().toISOString()}
-- WARNING: Contains sensitive production data

CREATE DATABASE production_db;
USE production_db;

CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE,
    password_hash VARCHAR(255),
    email VARCHAR(100),
    role ENUM('admin', 'user', 'manager'),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users VALUES 
(1, 'admin', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin@company.com', 'admin', NOW()),
(2, 'manager', '$2y$10$TKh8H1.PfQx37YgCzwiKb.KjNyWgaHb9cbcoQgdIVFlYg7B77UdFm', 'manager@company.com', 'manager', NOW());

CREATE TABLE api_keys (
    id INT PRIMARY KEY AUTO_INCREMENT,
    key_name VARCHAR(100),
    api_key VARCHAR(255),
    permissions TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO api_keys VALUES 
(1, 'production_api', 'live_sk_1234567890abcdef', 'full_access', NOW()),
(2, 'backup_service', 'backup_key_xyz789abc', 'read_only', NOW());`
};

Object.keys(sensitiveFiles).forEach(filePath => {
    app.get(filePath, (req, res) => {
        res.type('text/plain').send(sensitiveFiles[filePath]);
    });
});

// Enterprise threat dashboard
app.get('/threat-dashboard', requireAuth, (req, res) => {
    db.all(`SELECT 
                COUNT(*) as total_threats,
                COUNT(DISTINCT ip_address) as unique_ips,
                AVG(severity_score) as avg_severity,
                COUNT(CASE WHEN severity_score >= 8 THEN 1 END) as critical_threats
            FROM threat_intelligence 
            WHERE timestamp > datetime('now', '-24 hours')`, [], (err, stats) => {
        
        db.all(`SELECT attack_classification, COUNT(*) as count 
                FROM threat_intelligence 
                WHERE timestamp > datetime('now', '-7 days') 
                GROUP BY attack_classification 
                ORDER BY count DESC LIMIT 5`, [], (err, topThreats) => {
            
            db.all(`SELECT ip_address, threat_level, attack_count, last_seen 
                    FROM ip_reputation 
                    WHERE threat_level IN ('CRITICAL', 'HIGH') 
                    ORDER BY attack_count DESC LIMIT 10`, [], (err, dangerousIPs) => {
                
                const dashboardStats = stats[0] || { total_threats: 0, unique_ips: 0, avg_severity: 0, critical_threats: 0 };
                
                res.send(`
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Enterprise Threat Dashboard - ThreatNet</title>
                    <link rel="stylesheet" href="/style.css">
                    <meta http-equiv="refresh" content="30">
                    <style>
                        .enterprise-dashboard { max-width: 1400px; margin: 0 auto; padding: 2rem; }
                        .dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 2rem; margin: 2rem 0; }
                        .metric-card { background: rgba(30, 41, 59, 0.8); border: 1px solid #3b82f6; border-radius: 1rem; padding: 2rem; backdrop-filter: blur(20px); }
                        .metric-value { font-size: 3rem; font-weight: bold; color: #3b82f6; }
                        .metric-label { color: #94a3b8; font-size: 1.125rem; margin-top: 0.5rem; }
                        .threat-table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
                        .threat-table th, .threat-table td { padding: 1rem; text-align: left; border-bottom: 1px solid #374151; }
                        .threat-table th { background: rgba(59, 130, 246, 0.1); color: #3b82f6; }
                        .critical { color: #ef4444; font-weight: bold; }
                        .high { color: #f59e0b; font-weight: bold; }
                        .medium { color: #10b981; }
                    </style>
                </head>
                <body style="background: linear-gradient(135deg, #0f172a, #1e293b); min-height: 100vh; color: #f1f5f9;">
                    <header style="background: rgba(30, 41, 59, 0.8); backdrop-filter: blur(20px); border-bottom: 1px solid #3b82f6; padding: 1rem 0;">
                        <div style="max-width: 1400px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; padding: 0 2rem;">
                            <h1 style="color: #3b82f6; font-size: 2rem; margin: 0;">🛡️ ThreatNet Enterprise</h1>
                            <div style="display: flex; gap: 1rem;">
                                <a href="/analytics-dashboard" style="color: #94a3b8; text-decoration: none; padding: 0.5rem 1rem; border: 1px solid #374151; border-radius: 0.5rem;">📊 Analytics</a>
                                <a href="/ip-intelligence" style="color: #94a3b8; text-decoration: none; padding: 0.5rem 1rem; border: 1px solid #374151; border-radius: 0.5rem;">🌐 IP Intel</a>
                                <a href="/logout" style="color: #ef4444; text-decoration: none; padding: 0.5rem 1rem; border: 1px solid #ef4444; border-radius: 0.5rem;">🚪 Logout</a>
                            </div>
                        </div>
                    </header>

                    <div class="enterprise-dashboard">
                        <div style="text-align: center; margin-bottom: 3rem;">
                            <h2 style="font-size: 2.5rem; margin-bottom: 1rem;">Enterprise Threat Intelligence Dashboard</h2>
                            <p style="color: #94a3b8; font-size: 1.25rem;">Real-time cybersecurity monitoring and threat analysis</p>
                        </div>

                        <div class="dashboard-grid">
                            <div class="metric-card">
                                <div class="metric-value">${dashboardStats.total_threats}</div>
                                <div class="metric-label">Total Threats (24h)</div>
                            </div>
                            <div class="metric-card">
                                <div class="metric-value">${dashboardStats.unique_ips}</div>
                                <div class="metric-label">Unique Threat Sources</div>
                            </div>
                            <div class="metric-card">
                                <div class="metric-value">${Math.round(dashboardStats.avg_severity * 10) / 10}</div>
                                <div class="metric-label">Average Threat Severity</div>
                            </div>
                            <div class="metric-card">
                                <div class="metric-value critical">${dashboardStats.critical_threats}</div>
                                <div class="metric-label">Critical Threats</div>
                            </div>
                        </div>

                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin-top: 3rem;">
                            <div class="metric-card">
                                <h3 style="color: #3b82f6; margin-bottom: 1rem;">🎯 Top Threat Vectors</h3>
                                <table class="threat-table">
                                    <thead>
                                        <tr><th>Attack Type</th><th>Count</th></tr>
                                    </thead>
                                    <tbody>
                                        ${topThreats.map(threat => `
                                            <tr>
                                                <td>${threat.attack_classification}</td>
                                                <td class="${threat.count > 10 ? 'critical' : threat.count > 5 ? 'high' : 'medium'}">${threat.count}</td>
                                            </tr>
                                        `).join('')}
                                    </tbody>
                                </table>
                            </div>

                            <div class="metric-card">
                                <h3 style="color: #ef4444; margin-bottom: 1rem;">🚨 High-Risk IP Addresses</h3>
                                <table class="threat-table">
                                    <thead>
                                        <tr><th>IP Address</th><th>Threat Level</th><th>Attacks</th></tr>
                                    </thead>
                                    <tbody>
                                        ${dangerousIPs.map(ip => `
                                            <tr>
                                                <td style="font-family: monospace;">${ip.ip_address}</td>
                                                <td class="${ip.threat_level.toLowerCase()}">${ip.threat_level}</td>
                                                <td>${ip.attack_count}</td>
                                            </tr>
                                        `).join('')}
                                    </tbody>
                                </table>
                            </div>
                        </div>

                        <div style="text-align: center; margin-top: 3rem; padding: 2rem; background: rgba(30, 41, 59, 0.5); border-radius: 1rem;">
                            <p style="color: #94a3b8;">🔄 Dashboard auto-refreshes every 30 seconds | Last updated: ${new Date().toLocaleString()}</p>
                        </div>
                    </div>
                </body>
                </html>`);
            });
        });
    });
});

// IP Intelligence page
app.get('/ip-intelligence', requireAuth, (req, res) => {
    db.all(`SELECT ip_address, reputation_score, threat_level, attack_count, first_seen, last_seen, blocked_until 
            FROM ip_reputation 
            ORDER BY attack_count DESC, reputation_score ASC LIMIT 50`, [], (err, ips) => {
        
        res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>IP Intelligence - ThreatNet Enterprise</title>
            <link rel="stylesheet" href="/style.css">
            <style>
                .ip-intel-container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
                .intel-table { width: 100%; border-collapse: collapse; background: rgba(30, 41, 59, 0.8); border-radius: 1rem; overflow: hidden; }
                .intel-table th, .intel-table td { padding: 1rem; text-align: left; border-bottom: 1px solid #374151; }
                .intel-table th { background: rgba(59, 130, 246, 0.2); color: #3b82f6; font-weight: 600; }
                .reputation-score { padding: 0.25rem 0.75rem; border-radius: 0.5rem; font-weight: bold; }
                .score-high { background: #10b981; color: white; }
                .score-medium { background: #f59e0b; color: white; }
                .score-low { background: #ef4444; color: white; }
                .blocked { background: rgba(239, 68, 68, 0.1); }
            </style>
        </head>
        <body style="background: linear-gradient(135deg, #0f172a, #1e293b); min-height: 100vh; color: #f1f5f9;">
            <header style="background: rgba(30, 41, 59, 0.8); backdrop-filter: blur(20px); border-bottom: 1px solid #3b82f6; padding: 1rem 0;">
                <div style="max-width: 1400px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; padding: 0 2rem;">
                    <h1 style="color: #3b82f6; font-size: 2rem; margin: 0;">🌐 IP Intelligence Center</h1>
                    <a href="/threat-dashboard" style="color: #94a3b8; text-decoration: none; padding: 0.5rem 1rem; border: 1px solid #374151; border-radius: 0.5rem;">← Back to Dashboard</a>
                </div>
            </header>

            <div class="ip-intel-container">
                <div style="text-align: center; margin-bottom: 3rem;">
                    <h2 style="font-size: 2rem; margin-bottom: 1rem;">IP Reputation & Threat Intelligence</h2>
                    <p style="color: #94a3b8;">Comprehensive analysis of attacking IP addresses and their threat profiles</p>
                </div>

                <table class="intel-table">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Reputation Score</th>
                            <th>Threat Level</th>
                            <th>Attack Count</th>
                            <th>First Seen</th>
                            <th>Last Activity</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${ips.map(ip => {
                            const isBlocked = ip.blocked_until && new Date(ip.blocked_until) > new Date();
                            const scoreClass = ip.reputation_score >= 70 ? 'score-high' : ip.reputation_score >= 40 ? 'score-medium' : 'score-low';
                            return `
                            <tr ${isBlocked ? 'class="blocked"' : ''}>
                                <td style="font-family: monospace; font-weight: bold;">${ip.ip_address}</td>
                                <td><span class="reputation-score ${scoreClass}">${ip.reputation_score}/100</span></td>
                                <td style="color: ${ip.threat_level === 'CRITICAL' ? '#ef4444' : ip.threat_level === 'HIGH' ? '#f59e0b' : '#10b981'}; font-weight: bold;">${ip.threat_level}</td>
                                <td style="font-weight: bold;">${ip.attack_count}</td>
                                <td>${new Date(ip.first_seen).toLocaleDateString()}</td>
                                <td>${new Date(ip.last_seen).toLocaleString()}</td>
                                <td>${isBlocked ? '<span style="color: #ef4444;">🚫 BLOCKED</span>' : '<span style="color: #10b981;">✅ MONITORED</span>'}</td>
                            </tr>`;
                        }).join('')}
                    </tbody>
                </table>
            </div>
        </body>
        </html>`);
    });
});

// Analytics dashboard with charts
app.get('/analytics-dashboard', requireAuth, (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Analytics Dashboard - ThreatNet Enterprise</title>
        <link rel="stylesheet" href="/style.css">
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            .analytics-container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
            .chart-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(500px, 1fr)); gap: 2rem; margin: 2rem 0; }
            .chart-card { background: rgba(30, 41, 59, 0.8); border: 1px solid #3b82f6; border-radius: 1rem; padding: 2rem; backdrop-filter: blur(20px); }
            .chart-title { color: #3b82f6; font-size: 1.5rem; font-weight: 600; margin-bottom: 1rem; text-align: center; }
        </style>
    </head>
    <body style="background: linear-gradient(135deg, #0f172a, #1e293b); min-height: 100vh; color: #f1f5f9;">
        <header style="background: rgba(30, 41, 59, 0.8); backdrop-filter: blur(20px); border-bottom: 1px solid #3b82f6; padding: 1rem 0;">
            <div style="max-width: 1400px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; padding: 0 2rem;">
                <h1 style="color: #3b82f6; font-size: 2rem; margin: 0;">📊 Advanced Analytics</h1>
                <a href="/threat-dashboard" style="color: #94a3b8; text-decoration: none; padding: 0.5rem 1rem; border: 1px solid #374151; border-radius: 0.5rem;">← Back to Dashboard</a>
            </div>
        </header>

        <div class="analytics-container">
            <div class="chart-grid">
                <div class="chart-card">
                    <h3 class="chart-title">Attack Vector Distribution</h3>
                    <canvas id="attackVectorChart"></canvas>
                </div>
                <div class="chart-card">
                    <h3 class="chart-title">Threat Severity Timeline</h3>
                    <canvas id="severityTimelineChart"></canvas>
                </div>
                <div class="chart-card">
                    <h3 class="chart-title">Geographic Threat Distribution</h3>
                    <canvas id="geoChart"></canvas>
                </div>
                <div class="chart-card">
                    <h3 class="chart-title">Hourly Attack Patterns</h3>
                    <canvas id="hourlyChart"></canvas>
                </div>
            </div>
        </div>

        <script>
            // Chart configurations
            const chartOptions = {
                responsive: true,
                plugins: {
                    legend: {
                        labels: { color: '#f1f5f9' }
                    }
                },
                scales: {
                    y: {
                        ticks: { color: '#94a3b8' },
                        grid: { color: 'rgba(148, 163, 184, 0.1)' }
                    },
                    x: {
                        ticks: { color: '#94a3b8' },
                        grid: { color: 'rgba(148, 163, 184, 0.1)' }
                    }
                }
            };

            // Attack Vector Chart
            new Chart(document.getElementById('attackVectorChart'), {
                type: 'doughnut',
                data: {
                    labels: ['SQL Injection', 'XSS', 'Path Traversal', 'Command Injection', 'Directory Enum', 'Bot/Scanner'],
                    datasets: [{
                        data: [25, 18, 22, 15, 12, 8],
                        backgroundColor: ['#ef4444', '#f59e0b', '#10b981', '#3b82f6', '#8b5cf6', '#ec4899']
                    }]
                },
                options: { responsive: true, plugins: { legend: { labels: { color: '#f1f5f9' } } } }
            });

            // Severity Timeline Chart
            new Chart(document.getElementById('severityTimelineChart'), {
                type: 'line',
                data: {
                    labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
                    datasets: [{
                        label: 'Critical',
                        data: [2, 1, 4, 8, 12, 6],
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.1)'
                    }, {
                        label: 'High',
                        data: [5, 3, 8, 15, 20, 12],
                        borderColor: '#f59e0b',
                        backgroundColor: 'rgba(245, 158, 11, 0.1)'
                    }]
                },
                options: chartOptions
            });

            // Geographic Chart
            new Chart(document.getElementById('geoChart'), {
                type: 'bar',
                data: {
                    labels: ['Unknown', 'US', 'CN', 'RU', 'BR', 'IN'],
                    datasets: [{
                        label: 'Attacks by Country',
                        data: [45, 23, 18, 12, 8, 6],
                        backgroundColor: '#3b82f6'
                    }]
                },
                options: chartOptions
            });

            // Hourly Patterns Chart
            new Chart(document.getElementById('hourlyChart'), {
                type: 'bar',
                data: {
                    labels: Array.from({length: 24}, (_, i) => i + ':00'),
                    datasets: [{
                        label: 'Attacks per Hour',
                        data: [2,1,1,0,1,2,4,6,8,12,15,18,22,20,18,16,14,12,10,8,6,4,3,2],
                        backgroundColor: '#10b981'
                    }]
                },
                options: chartOptions
            });
        </script>
    </body>
    </html>`);
});

// Export functionality
app.get('/export/csv', requireAuth, (req, res) => {
    db.all('SELECT * FROM threat_intelligence ORDER BY timestamp DESC', [], (err, rows) => {
        if (err) return res.status(500).send('Export failed');
        
        const csv = [
            'ID,IP Address,Attack Type,Severity,Endpoint,Timestamp,User Agent',
            ...rows.map(row => `${row.id},"${row.ip_address}","${row.attack_classification}",${row.severity_score},"${row.endpoint_targeted}","${row.timestamp}","${row.user_agent}"`)
        ].join('\n');
        
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=threatnet-export.csv');
        res.send(csv);
    });
});

app.get('/export/json', requireAuth, (req, res) => {
    db.all('SELECT * FROM threat_intelligence ORDER BY timestamp DESC', [], (err, rows) => {
        if (err) return res.status(500).send('Export failed');
        
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', 'attachment; filename=threatnet-export.json');
        res.json({
            export_timestamp: new Date().toISOString(),
            total_records: rows.length,
            threat_intelligence: rows
        });
    });
});

// Main login handler
app.post('/login', (req, res) => {
    const threat = req.threatInfo;
    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Authentication Result - ThreatNet</title>
        <link rel="stylesheet" href="/style.css">
    </head>
    <body style="background: linear-gradient(135deg, #0f172a, #1e293b); min-height: 100vh; color: #f1f5f9;">
        <div style="max-width: 600px; margin: 8rem auto; padding: 0 1rem;">
            <div style="background: rgba(30, 41, 59, 0.9); border: 1px solid ${threat.severity >= 7 ? '#ef4444' : '#3b82f6'}; border-radius: 1rem; padding: 3rem; text-align: center; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);">
                <div style="font-size: 5rem; margin-bottom: 1rem;">${threat.severity >= 7 ? '🚨' : '❌'}</div>
                <h1 style="color: ${threat.severity >= 7 ? '#ef4444' : '#3b82f6'}; margin-bottom: 1rem; font-size: 2rem;">
                    ${threat.severity >= 7 ? 'Security Threat Detected' : 'Authentication Failed'}
                </h1>
                <div style="background: rgba(15, 23, 42, 0.8); border-radius: 0.5rem; padding: 2rem; margin: 2rem 0; text-align: left;">
                    <h3 style="color: #3b82f6; margin-bottom: 1rem;">🔍 Threat Analysis</h3>
                    <p><strong>Classification:</strong> ${threat.type}</p>
                    <p><strong>Severity Score:</strong> ${threat.severity}/10</p>
                    <p><strong>Confidence Level:</strong> ${Math.round(threat.confidence * 100)}%</p>
                    <p><strong>Status:</strong> ${threat.severity >= 8 ? '🚫 IP Blocked' : '📝 Logged for Analysis'}</p>
                </div>
                <a href="/" style="display: inline-block; padding: 1rem 2rem; background: linear-gradient(135deg, #3b82f6, #1d4ed8); color: white; text-decoration: none; border-radius: 0.5rem; font-weight: 600;">
                    ← Return to System
                </a>
            </div>
        </div>
    </body>
    </html>`);
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// API endpoint for real-time stats
app.get('/api/threat-stats', requireAuth, (req, res) => {
    db.all(`SELECT 
                attack_classification,
                COUNT(*) as count,
                AVG(severity_score) as avg_severity,
                MAX(timestamp) as latest_attack
            FROM threat_intelligence 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY attack_classification
            ORDER BY count DESC`, [], (err, stats) => {
        
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ threat_stats: stats, timestamp: new Date().toISOString() });
    });
});

// 404 handler for reconnaissance detection
app.use('*', (req, res) => {
    res.status(404).send(`
    <!DOCTYPE html>
    <html><head><title>404 - Resource Not Found</title><link rel="stylesheet" href="/style.css"></head>
    <body style="background: #0f172a; color: #f1f5f9; font-family: monospace; text-align: center; padding: 100px;">
        <h1 style="color: #ef4444; font-size: 3rem;">404</h1>
        <p style="font-size: 1.25rem; margin: 2rem 0;">The requested resource was not found</p>
        <p style="color: #64748b; font-size: 0.875rem;">Request logged for security analysis</p>
        <div style="margin-top: 3rem;">
            <a href="/" style="color: #3b82f6; text-decoration: none; padding: 0.75rem 1.5rem; border: 1px solid #3b82f6; border-radius: 0.5rem;">← Return Home</a>
        </div>
    </body></html>`);
});

app.listen(PORT, () => {
    console.log(`🛡️ ThreatNet Enterprise Honeypot System`);
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📊 Dashboard: http://localhost:${PORT}/threat-dashboard`);
    console.log(`🔐 Security Key: ThreatNet2024!`);
    console.log(`🎯 Advanced threat detection and intelligence active`);
});