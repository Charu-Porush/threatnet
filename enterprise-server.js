const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const net = require('net');
const { spawn } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3000;
const SSH_PORT = 2222;
const FTP_PORT = 2121;

// Security configuration
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'threatnet-admin-2024';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex');
const ADMIN_PATH = process.env.ADMIN_PATH || '/security-console-x7k9';

console.log(`🔐 Admin Console: http://localhost:${PORT}${ADMIN_PATH}`);
console.log(`🔑 Admin Secret: ${ADMIN_SECRET}`);

// Rate limiting
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many attempts'
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false,
        maxAge: 2 * 60 * 60 * 1000,
        httpOnly: true
    }
}));

// Persistent SQLite database
const dbPath = path.join(__dirname, 'threatnet.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('DB error:', err.message);
    } else {
        console.log('🗄️ Database connected:', dbPath);
        initDatabase();
    }
});

function initDatabase() {
    db.serialize(() => {
        // Main logs table
        db.run(`CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            ip TEXT NOT NULL,
            payload TEXT,
            user_agent TEXT,
            attack_type TEXT,
            social_engineering_score INTEGER DEFAULT 0,
            threat_level TEXT DEFAULT 'low',
            geolocation TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
        
        // Threat intelligence table
        db.run(`CREATE TABLE IF NOT EXISTS threat_intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            reputation_score INTEGER DEFAULT 0,
            country TEXT,
            asn TEXT,
            is_tor BOOLEAN DEFAULT 0,
            is_vpn BOOLEAN DEFAULT 0,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
        
        // Attack campaigns table
        db.run(`CREATE TABLE IF NOT EXISTS campaigns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id TEXT UNIQUE,
            attack_pattern TEXT,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            attack_count INTEGER DEFAULT 1
        )`);
    });
}

// Authentication middleware
function requireAuth(req, res, next) {
    if (req.session && req.session.authenticated) {
        return next();
    }
    res.status(401).send('Unauthorized Access');
}

// Enhanced Social Engineering Detection
function analyzeSocialEngineering(username, password, userAgent, service) {
    let score = 0;
    let indicators = [];
    
    const commonCreds = {
        usernames: ['admin', 'administrator', 'root', 'user', 'test', 'guest', 'oracle', 'postgres'],
        passwords: ['password', '123456', 'admin', 'root', 'test', '', 'password123', 'admin123']
    };
    
    const socialPatterns = {
        urgency: ['urgent', 'immediate', 'asap', 'emergency', 'critical', 'expire'],
        authority: ['ceo', 'manager', 'director', 'supervisor', 'boss', 'admin'],
        trust: ['security', 'support', 'help', 'service', 'team']
    };
    
    // Service-specific analysis
    if (service === 'ssh' && username === 'root') {
        score += 3;
        indicators.push('Root SSH access attempt');
    }
    
    // Common credentials check
    if (commonCreds.usernames.includes(username.toLowerCase())) {
        score += 2;
        indicators.push('Common username');
    }
    
    if (commonCreds.passwords.includes(password.toLowerCase())) {
        score += 2;
        indicators.push('Common password');
    }
    
    // Social engineering patterns
    const fullInput = (username + ' ' + password).toLowerCase();
    Object.entries(socialPatterns).forEach(([category, words]) => {
        words.forEach(word => {
            if (fullInput.includes(word)) {
                score += 3;
                indicators.push(`${category} language detected`);
            }
        });
    });
    
    // Complexity analysis
    if (username.length > 8 && /[A-Z]/.test(username) && /[0-9]/.test(username)) {
        score += 4;
        indicators.push('Complex username pattern');
    }
    
    if (password.length > 10 && /[!@#$%^&*]/.test(password)) {
        score += 4;
        indicators.push('Complex password pattern');
    }
    
    // User agent analysis
    if (userAgent) {
        if (userAgent.includes('curl') || userAgent.includes('python') || userAgent.includes('wget')) {
            score += 1;
            indicators.push('Automated tool detected');
        } else {
            score += 2;
            indicators.push('Human browser detected');
        }
    }
    
    // Determine threat level
    let threatLevel = 'low';
    let attackType = 'automated';
    
    if (score >= 8) {
        threatLevel = 'critical';
        attackType = 'advanced_persistent_threat';
    } else if (score >= 6) {
        threatLevel = 'high';
        attackType = 'social_engineering';
    } else if (score >= 3) {
        threatLevel = 'medium';
        attackType = 'targeted';
    }
    
    return { score, attackType, threatLevel, indicators };
}

// Threat Intelligence Integration
async function getThreatIntel(ip) {
    return new Promise((resolve) => {
        db.get('SELECT * FROM threat_intel WHERE ip = ?', [ip], (err, row) => {
            if (row) {
                resolve(row);
            } else {
                // Simulate threat intel lookup
                const intel = {
                    ip: ip,
                    reputation_score: Math.floor(Math.random() * 100),
                    country: ['US', 'CN', 'RU', 'BR', 'IN'][Math.floor(Math.random() * 5)],
                    asn: `AS${Math.floor(Math.random() * 65535)}`,
                    is_tor: Math.random() > 0.9,
                    is_vpn: Math.random() > 0.8
                };
                
                db.run(`INSERT OR REPLACE INTO threat_intel 
                    (ip, reputation_score, country, asn, is_tor, is_vpn) 
                    VALUES (?, ?, ?, ?, ?, ?)`,
                    [intel.ip, intel.reputation_score, intel.country, intel.asn, intel.is_tor, intel.is_vpn]
                );
                
                resolve(intel);
            }
        });
    });
}

// Log attack with enhanced data
async function logAttack(service, ip, payload, userAgent, analysis) {
    const intel = await getThreatIntel(ip);
    
    const stmt = db.prepare(`INSERT INTO logs 
        (service, ip, payload, user_agent, attack_type, social_engineering_score, threat_level, geolocation) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
    
    stmt.run(
        service,
        ip,
        payload,
        userAgent,
        analysis.attackType,
        analysis.score,
        analysis.threatLevel,
        intel.country
    );
    stmt.finalize();
    
    console.log(`🚨 ${analysis.threatLevel.toUpperCase()} threat from ${ip} (${intel.country}) on ${service}`);
}

// HTTP Honeypot (existing)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/login', loginLimiter, async (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    const username = req.body.username || '';
    const password = req.body.password || '';
    const userAgent = req.get('User-Agent') || '';
    
    const analysis = analyzeSocialEngineering(username, password, userAgent, 'http');
    await logAttack('http', ip, `username=${username} password=${password}`, userAgent, analysis);
    
    res.send(generateResponse(analysis));
});

// SSH Honeypot
const sshServer = net.createServer((socket) => {
    const ip = socket.remoteAddress;
    console.log(`🔌 SSH connection from ${ip}`);
    
    socket.write('SSH-2.0-OpenSSH_8.0\r\n');
    
    let buffer = '';
    socket.on('data', async (data) => {
        buffer += data.toString();
        
        if (buffer.includes('ssh-userauth')) {
            // Extract credentials (simplified)
            const analysis = analyzeSocialEngineering('unknown', 'unknown', '', 'ssh');
            await logAttack('ssh', ip, buffer, '', analysis);
            
            socket.write('Authentication failed\r\n');
            socket.end();
        }
    });
    
    socket.on('error', () => {});
    socket.setTimeout(30000, () => socket.destroy());
});

sshServer.listen(SSH_PORT, () => {
    console.log(`🔐 SSH Honeypot listening on port ${SSH_PORT}`);
});

// FTP Honeypot
const ftpServer = net.createServer((socket) => {
    const ip = socket.remoteAddress;
    console.log(`📁 FTP connection from ${ip}`);
    
    socket.write('220 Welcome to FTP Server\r\n');
    
    socket.on('data', async (data) => {
        const command = data.toString().trim();
        
        if (command.startsWith('USER ')) {
            const username = command.substring(5);
            socket.write('331 Password required\r\n');
        } else if (command.startsWith('PASS ')) {
            const password = command.substring(5);
            const analysis = analyzeSocialEngineering('ftp_user', password, '', 'ftp');
            await logAttack('ftp', ip, command, '', analysis);
            
            socket.write('530 Authentication failed\r\n');
            socket.end();
        }
    });
    
    socket.on('error', () => {});
    socket.setTimeout(30000, () => socket.destroy());
});

ftpServer.listen(FTP_PORT, () => {
    console.log(`📁 FTP Honeypot listening on port ${FTP_PORT}`);
});

// Secure Admin Routes
app.get(`${ADMIN_PATH}/login`, (req, res) => {
    res.send(generateAdminLogin());
});

app.post(`${ADMIN_PATH}/auth`, (req, res) => {
    if (req.body.secret === ADMIN_SECRET) {
        req.session.authenticated = true;
        res.redirect(`${ADMIN_PATH}/dashboard`);
    } else {
        res.status(401).send('Invalid access key');
    }
});

app.get(`${ADMIN_PATH}/dashboard`, requireAuth, (req, res) => {
    db.all(`SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100`, [], (err, logs) => {
        if (err) return res.status(500).send('Database error');
        
        db.all(`SELECT 
            service, 
            COUNT(*) as count, 
            AVG(social_engineering_score) as avg_score,
            threat_level
            FROM logs 
            GROUP BY service, threat_level`, [], (err, stats) => {
            
            res.send(generateEnterpriseDashboard(logs, stats));
        });
    });
});

app.get(`${ADMIN_PATH}/threat-intel`, requireAuth, (req, res) => {
    db.all(`SELECT 
        l.ip, 
        COUNT(*) as attack_count,
        MAX(l.social_engineering_score) as max_score,
        t.country,
        t.reputation_score,
        t.is_tor,
        t.is_vpn
        FROM logs l 
        LEFT JOIN threat_intel t ON l.ip = t.ip 
        GROUP BY l.ip 
        ORDER BY attack_count DESC 
        LIMIT 50`, [], (err, intel) => {
        
        res.send(generateThreatIntelDashboard(intel));
    });
});

// Block old insecure routes
app.get('/admin', (req, res) => res.status(404).send('Not found'));
app.get('/analytics.html', (req, res) => res.status(404).send('Not found'));

function generateResponse(analysis) {
    const responses = {
        advanced_persistent_threat: {
            title: '🎯 Advanced Threat Detected',
            message: 'Sophisticated attack pattern identified. Security team has been notified.',
            color: '#dc2626'
        },
        social_engineering: {
            title: '🎭 Social Engineering Detected',
            message: 'Behavioral analysis indicates potential social engineering attempt.',
            color: '#ea580c'
        },
        targeted: {
            title: '🚨 Targeted Attack Detected',
            message: 'Suspicious activity pattern detected and logged.',
            color: '#d97706'
        },
        automated: {
            title: '🤖 Automated Attack Detected',
            message: 'Bot activity detected and blocked.',
            color: '#059669'
        }
    };
    
    const response = responses[analysis.attackType] || responses.automated;
    
    return `
        <!DOCTYPE html>
        <html><head><title>ThreatNet Response</title><link rel="stylesheet" href="/style.css"></head>
        <body>
            <div class="result-container">
                <div class="result-card" style="border-color: ${response.color};">
                    <div style="font-size: 4rem; margin-bottom: 1rem;">🛡️</div>
                    <h2 style="color: ${response.color};">${response.title}</h2>
                    <p>${response.message}</p>
                    <div style="margin: 1rem 0; padding: 1rem; background: rgba(0,0,0,0.3); border-radius: 0.5rem;">
                        <strong>Threat Level:</strong> ${analysis.threatLevel.toUpperCase()}<br>
                        <strong>SE Score:</strong> ${analysis.score}/10<br>
                        <strong>Indicators:</strong> ${analysis.indicators.join(', ')}
                    </div>
                    <a href="/" style="padding: 0.75rem 2rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                       color: white; text-decoration: none; border-radius: 0.5rem;">← Return</a>
                </div>
            </div>
        </body></html>
    `;
}

function generateAdminLogin() {
    return `
        <!DOCTYPE html>
        <html><head><title>ThreatNet Security Console</title><link rel="stylesheet" href="/style.css"></head>
        <body style="background: #000; color: #0f0;">
            <div style="max-width: 400px; margin: 10rem auto; padding: 2rem; border: 1px solid #0f0; border-radius: 1rem;">
                <div style="text-align: center; margin-bottom: 2rem;">
                    <div style="font-size: 3rem;">🛡️</div>
                    <h2>ThreatNet Security Console</h2>
                    <p style="color: #666;">Enterprise Threat Intelligence Platform</p>
                </div>
                <form method="POST" action="${ADMIN_PATH}/auth">
                    <input type="password" name="secret" placeholder="Security Access Key" required 
                           style="width: 100%; padding: 1rem; margin: 1rem 0; background: #000; border: 1px solid #0f0; color: #0f0; border-radius: 0.5rem;">
                    <button type="submit" style="width: 100%; padding: 1rem; background: #0f0; color: #000; border: none; border-radius: 0.5rem; font-weight: bold;">
                        🔐 AUTHENTICATE
                    </button>
                </form>
            </div>
        </body></html>
    `;
}

function generateEnterpriseDashboard(logs, stats) {
    const totalAttacks = logs.length;
    const uniqueIPs = new Set(logs.map(l => l.ip)).size;
    const criticalThreats = logs.filter(l => l.threat_level === 'critical').length;
    const services = new Set(logs.map(l => l.service)).size;
    
    return `
        <!DOCTYPE html>
        <html><head><title>ThreatNet Enterprise Console</title><link rel="stylesheet" href="/style.css"></head>
        <body>
            <div class="admin-container">
                <div class="dashboard-header">
                    <h1>🛡️ ThreatNet Enterprise Console</h1>
                    <p>Multi-Service Honeypot & Threat Intelligence Platform</p>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">${totalAttacks}</div>
                        <div class="stat-label">Total Attacks</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${services}</div>
                        <div class="stat-label">Active Services</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${uniqueIPs}</div>
                        <div class="stat-label">Unique Attackers</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${criticalThreats}</div>
                        <div class="stat-label">Critical Threats</div>
                    </div>
                </div>
                
                <div class="table-container">
                    <div class="table-header">
                        <h3>🎯 Live Threat Feed</h3>
                        <p>Real-time multi-service attack monitoring</p>
                    </div>
                    <table>
                        <thead>
                            <tr><th>Service</th><th>IP</th><th>Location</th><th>Threat Level</th><th>SE Score</th><th>Attack Type</th><th>Time</th></tr>
                        </thead>
                        <tbody>
                            ${logs.slice(0, 50).map(log => `
                                <tr style="background: ${
                                    log.threat_level === 'critical' ? 'rgba(220, 38, 38, 0.1)' :
                                    log.threat_level === 'high' ? 'rgba(234, 88, 12, 0.1)' :
                                    log.threat_level === 'medium' ? 'rgba(217, 119, 6, 0.1)' : 'transparent'
                                };">
                                    <td>
                                        <span style="padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; 
                                                     background: ${log.service === 'ssh' ? '#3b82f6' : log.service === 'ftp' ? '#8b5cf6' : '#10b981'}; 
                                                     color: white;">
                                            ${log.service.toUpperCase()}
                                        </span>
                                    </td>
                                    <td style="font-family: monospace;">${log.ip}</td>
                                    <td>${log.geolocation || 'Unknown'}</td>
                                    <td>
                                        <span style="padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; 
                                                     background: ${
                                                         log.threat_level === 'critical' ? '#dc2626' :
                                                         log.threat_level === 'high' ? '#ea580c' :
                                                         log.threat_level === 'medium' ? '#d97706' : '#059669'
                                                     }; color: white;">
                                            ${log.threat_level.toUpperCase()}
                                        </span>
                                    </td>
                                    <td><strong>${log.social_engineering_score}/10</strong></td>
                                    <td>${log.attack_type}</td>
                                    <td>${new Date(log.timestamp).toLocaleString()}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
                
                <div class="action-buttons">
                    <a href="${ADMIN_PATH}/threat-intel" class="action-btn">🌐 Threat Intelligence</a>
                    <button onclick="location.reload()" class="action-btn">🔄 Refresh</button>
                    <form method="POST" action="${ADMIN_PATH}/logout" style="display: inline;">
                        <button type="submit" class="action-btn">🚪 Logout</button>
                    </form>
                </div>
            </div>
        </body></html>
    `;
}

function generateThreatIntelDashboard(intel) {
    return `
        <!DOCTYPE html>
        <html><head><title>Threat Intelligence - ThreatNet</title><link rel="stylesheet" href="/style.css"></head>
        <body>
            <div class="admin-container">
                <div class="dashboard-header">
                    <h1>🌐 Threat Intelligence Dashboard</h1>
                    <p>Advanced attacker profiling and attribution</p>
                </div>
                
                <div class="table-container">
                    <div class="table-header">
                        <h3>🎯 Top Threat Actors</h3>
                        <p>High-risk IPs with detailed intelligence</p>
                    </div>
                    <table>
                        <thead>
                            <tr><th>IP Address</th><th>Country</th><th>Attacks</th><th>Max Score</th><th>Reputation</th><th>Tor</th><th>VPN</th></tr>
                        </thead>
                        <tbody>
                            ${intel.map(i => `
                                <tr style="background: ${i.attack_count > 10 ? 'rgba(220, 38, 38, 0.1)' : 'transparent'};">
                                    <td style="font-family: monospace;">${i.ip}</td>
                                    <td>${i.country || 'Unknown'}</td>
                                    <td><strong>${i.attack_count}</strong></td>
                                    <td>${i.max_score}/10</td>
                                    <td>
                                        <span style="color: ${i.reputation_score > 70 ? '#dc2626' : i.reputation_score > 40 ? '#d97706' : '#059669'};">
                                            ${i.reputation_score || 0}/100
                                        </span>
                                    </td>
                                    <td>${i.is_tor ? '🧅 Yes' : '❌ No'}</td>
                                    <td>${i.is_vpn ? '🔒 Yes' : '❌ No'}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
                
                <div class="action-buttons">
                    <a href="${ADMIN_PATH}/dashboard" class="action-btn">🛡️ Dashboard</a>
                    <button onclick="location.reload()" class="action-btn">🔄 Refresh</button>
                </div>
            </div>
        </body></html>
    `;
}

app.listen(PORT, () => {
    console.log(`🚀 ThreatNet Enterprise running on port ${PORT}`);
    console.log(`🔐 Services: HTTP:${PORT}, SSH:${SSH_PORT}, FTP:${FTP_PORT}`);
});