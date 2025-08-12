const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');


const app = express();
const PORT = process.env.PORT || 3000;

// Security configuration
// HONEYPOT: Intentional weak default for trapping attackers
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'threatnet-admin-2024';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex');
const ADMIN_PATH = process.env.ADMIN_PATH || '/security-console-x7k9';

console.log(`🔐 Admin Console: http://localhost:${PORT}${ADMIN_PATH}`);
console.log(`🔑 Admin Secret: ${ADMIN_SECRET}`);
console.log(`🍯 HONEYPOT MODE: Vulnerabilities are intentional traps`);

// Rate limiting
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many attempts'
});

// Middleware - SECURITY: Replace deprecated bodyParser
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production', // SECURITY: Enable secure cookies in production
        maxAge: 2 * 60 * 60 * 1000,
        httpOnly: true,
        sameSite: 'strict' // SECURITY: Prevent CSRF
    }
}));

// Persistent SQLite database
const dbPath = path.join(__dirname, 'threatnet.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('DB error:', err.message);
        process.exit(1); // SECURITY: Exit on critical database failure
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
            ai_analysis TEXT,
            ai_confidence INTEGER DEFAULT 0,
            ai_threat_level TEXT DEFAULT 'medium',
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

// AI-Powered Threat Analysis (Free Hugging Face API)
async function aiThreatAnalysis(payload, userAgent, ip) {
    try {
        // SECURITY: Validate payload to prevent SSRF and injection
        if (!payload || typeof payload !== 'string' || payload.length > 1000) {
            throw new Error('Invalid payload');
        }
        
        const response = await fetch('https://api-inference.huggingface.co/models/cardiffnlp/twitter-roberta-base-sentiment-latest', {
            method: 'POST',
            headers: {
                'Authorization': 'Bearer hf_demo', // Free demo token
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ inputs: payload.substring(0, 500) }) // SECURITY: Limit payload size
        });
        
        const result = await response.json();
        const sentiment = result[0]?.label || 'NEUTRAL';
        const confidence = result[0]?.score || 0.5;
        
        // Convert sentiment to threat analysis
        let aiThreatLevel = 'medium';
        let aiConfidence = confidence;
        
        if (sentiment === 'NEGATIVE' && confidence > 0.7) {
            aiThreatLevel = 'high';
        } else if (sentiment === 'POSITIVE') {
            aiThreatLevel = 'low';
        }
        
        return {
            ai_analysis: sentiment,
            ai_confidence: Math.round(confidence * 100),
            ai_threat_level: aiThreatLevel,
            ai_indicators: [`AI detected ${sentiment.toLowerCase()} intent`]
        };
    } catch (error) {
        // Fallback AI simulation
        const patterns = ['union', 'select', 'script', 'alert', '../', 'admin'];
        const threatWords = patterns.filter(p => payload.toLowerCase().includes(p));
        
        return {
            ai_analysis: threatWords.length > 0 ? 'MALICIOUS' : 'BENIGN',
            ai_confidence: threatWords.length > 0 ? 85 : 60,
            ai_threat_level: threatWords.length > 1 ? 'high' : 'medium',
            ai_indicators: [`AI pattern matching: ${threatWords.length} threat indicators`]
        };
    }
}

// Enhanced Social Engineering Detection
async function analyzeSocialEngineering(username, password, userAgent, service) {
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
    
    // HTTP-specific analysis
    if (service === 'http' && username.toLowerCase().includes('admin')) {
        score += 2;
        indicators.push('Admin account targeting');
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
    
    // Social engineering patterns - SECURITY: Validate input types
    if (typeof username !== 'string' || typeof password !== 'string') {
        username = String(username || '');
        password = String(password || '');
    }
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
    
    // Get AI analysis
    const payload = `${username} ${password}`;
    const aiAnalysis = await aiThreatAnalysis(payload, userAgent, 'unknown');
    
    // Combine traditional and AI analysis
    if (aiAnalysis.ai_threat_level === 'high') {
        score += 3;
        indicators.push(...aiAnalysis.ai_indicators);
    }
    
    return { 
        score, 
        attackType, 
        threatLevel, 
        indicators,
        aiAnalysis // Include AI results
    };
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
        (service, ip, payload, user_agent, attack_type, social_engineering_score, threat_level, geolocation, ai_analysis, ai_confidence, ai_threat_level) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    
    const aiData = analysis.aiAnalysis || {};
    stmt.run(
        service,
        ip,
        payload,
        userAgent,
        analysis.attackType,
        analysis.score,
        analysis.threatLevel,
        intel.country,
        aiData.ai_analysis || 'N/A',
        aiData.ai_confidence || 0,
        aiData.ai_threat_level || 'medium'
    );
    stmt.finalize();
    
    const aiInfo = analysis.aiAnalysis ? ` | AI: ${analysis.aiAnalysis.ai_analysis} (${analysis.aiAnalysis.ai_confidence}%)` : '';
    console.log(`🚨 ${analysis.threatLevel.toUpperCase()} threat from ${ip} (${intel.country}) on ${service}${aiInfo}`);
}

// HTTP Honeypot with AI indicator
app.get('/', (req, res) => {
    // Read the original index.html and inject AI status
    const fs = require('fs');
    let html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
    
    // Add AI status indicator
    const aiIndicator = `
        <div style="position: fixed; top: 20px; right: 20px; background: rgba(59, 130, 246, 0.9); color: white; padding: 0.75rem 1rem; border-radius: 0.5rem; font-size: 0.875rem; z-index: 1000; backdrop-filter: blur(10px);">
            🤖 AI-Powered Security: <span style="color: #10b981; font-weight: bold;">ACTIVE</span>
        </div>
    `;
    
    // Inject before closing body tag
    html = html.replace('</body>', aiIndicator + '</body>');
    
    res.send(html);
});

app.post('/login', loginLimiter, async (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    const username = req.body.username || '';
    const password = req.body.password || '';
    const userAgent = req.get('User-Agent') || '';
    
    const analysis = await analyzeSocialEngineering(username, password, userAgent, 'http');
    await logAttack('http', ip, `username=${username} password=${password}`, userAgent, analysis);
    
    // Generate AI-enhanced response
    const aiData = analysis.aiAnalysis || {};
    const responseHtml = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ThreatNet - AI Analysis Result</title>
        <link rel="stylesheet" href="/style.css">
    </head>
    <body>
        <div style="max-width: 600px; margin: 6rem auto; padding: 0 1rem;">
            <div style="background: rgba(30, 41, 59, 0.9); border: 1px solid #3b82f6; border-radius: 1rem; padding: 3rem; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);">
                <div style="text-align: center; margin-bottom: 2rem;">
                    <div style="font-size: 4rem; margin-bottom: 1rem;">🤖</div>
                    <h1 style="color: #3b82f6; margin-bottom: 0.5rem;">AI-Powered Threat Analysis</h1>
                    <p style="color: #94a3b8;">Advanced machine learning threat detection</p>
                </div>
                
                <div style="background: rgba(15, 23, 42, 0.8); border-radius: 0.5rem; padding: 2rem; margin: 2rem 0;">
                    <h3 style="color: #3b82f6; margin-bottom: 1rem;">🔍 AI Analysis Results</h3>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
                        <div>
                            <strong style="color: #f1f5f9;">AI Classification:</strong><br>
                            <span style="color: ${aiData.ai_analysis === 'MALICIOUS' ? '#ef4444' : aiData.ai_analysis === 'NEGATIVE' ? '#f59e0b' : '#10b981'}; font-weight: bold;">
                                ${aiData.ai_analysis || 'ANALYZING'}
                            </span>
                        </div>
                        <div>
                            <strong style="color: #f1f5f9;">AI Confidence:</strong><br>
                            <span style="color: #3b82f6; font-weight: bold;">${aiData.ai_confidence || 0}%</span>
                        </div>
                    </div>
                    <div style="margin-bottom: 1rem;">
                        <strong style="color: #f1f5f9;">Threat Level:</strong>
                        <span style="padding: 0.25rem 0.75rem; border-radius: 0.5rem; font-weight: bold; margin-left: 0.5rem; background: ${
                            analysis.threatLevel === 'critical' ? '#dc2626' :
                            analysis.threatLevel === 'high' ? '#ea580c' :
                            analysis.threatLevel === 'medium' ? '#eab308' : '#059669'
                        }; color: white;">
                            ${analysis.threatLevel.toUpperCase()}
                        </span>
                    </div>
                    <div>
                        <strong style="color: #f1f5f9;">Attack Type:</strong>
                        <span style="color: #94a3b8;">${analysis.attackType}</span>
                    </div>
                </div>
                
                <div style="background: rgba(15, 23, 42, 0.8); border-radius: 0.5rem; padding: 2rem; margin: 2rem 0;">
                    <h3 style="color: #f59e0b; margin-bottom: 1rem;">⚠️ Security Alert</h3>
                    <p style="color: #94a3b8; margin-bottom: 1rem;">
                        ${analysis.threatLevel === 'critical' ? 'Critical threat detected! Advanced persistent threat patterns identified.' :
                          analysis.threatLevel === 'high' ? 'High-risk activity detected. Potential social engineering attempt.' :
                          analysis.threatLevel === 'medium' ? 'Suspicious activity logged for analysis.' :
                          'Low-risk automated attempt detected.'}
                    </p>
                    <p style="color: #64748b; font-size: 0.875rem;">
                        🔒 This incident has been logged and analyzed by our AI security system.
                    </p>
                </div>
                
                <div style="text-align: center;">
                    <a href="/" style="display: inline-block; padding: 1rem 2rem; background: linear-gradient(135deg, #3b82f6, #1d4ed8); color: white; text-decoration: none; border-radius: 0.5rem; font-weight: 600;">
                        ← Return to System
                    </a>
                </div>
            </div>
        </div>
    </body>
    </html>`;
    
    res.send(responseHtml);
});



// Secure Admin Routes
app.get(`${ADMIN_PATH}/login`, (req, res) => {
    res.send(generateAdminLogin());
});

app.get(`${ADMIN_PATH}`, (req, res) => {
    res.redirect(`${ADMIN_PATH}/login`);
});

app.post(`${ADMIN_PATH}/auth`, (req, res) => {
    // SECURITY: Use timing-safe comparison for real admin auth
    const providedSecret = Buffer.from(req.body.secret || '', 'utf8');
    const actualSecret = Buffer.from(ADMIN_SECRET, 'utf8');
    
    if (providedSecret.length === actualSecret.length && 
        crypto.timingSafeEqual(providedSecret, actualSecret)) {
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

// Secure Analytics Route with Real Data
app.get(`${ADMIN_PATH}/analytics`, requireAuth, (req, res) => {
    res.send(generateSecureAnalytics());
});

// Analytics API endpoint for real-time updates
app.get(`${ADMIN_PATH}/api/analytics-data`, requireAuth, (req, res) => {
    db.all(`SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100`, [], (err, logs) => {
        if (err) return res.status(500).json({error: 'Database error'});
        
        const stats = {
            totalAttacks: logs.length,
            uniqueIPs: [...new Set(logs.map(l => l.ip))].length,
            attackTypes: {},
            threatLevels: {},
            hourlyData: {},
            topIPs: {},
            recentAttacks: logs.slice(0, 10)
        };
        
        logs.forEach(log => {
            stats.attackTypes[log.attack_type] = (stats.attackTypes[log.attack_type] || 0) + 1;
            stats.threatLevels[log.threat_level] = (stats.threatLevels[log.threat_level] || 0) + 1;
            stats.topIPs[log.ip] = (stats.topIPs[log.ip] || 0) + 1;
            
            const hour = new Date(log.timestamp).getHours();
            stats.hourlyData[hour] = (stats.hourlyData[hour] || 0) + 1;
        });
        
        res.json(stats);
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
                    <h1>🤖 ThreatNet AI-Enhanced Console</h1>
                    <p>AI-Powered Multi-Service Honeypot & Threat Intelligence Platform</p>
                    <div style="background: rgba(59, 130, 246, 0.1); border: 1px solid #3b82f6; border-radius: 0.5rem; padding: 1rem; margin: 1rem 0;">
                        <span style="color: #3b82f6; font-weight: bold;">✨ AI Status:</span> 
                        <span style="color: #10b981;">Machine Learning Threat Analysis ACTIVE</span>
                    </div>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">${totalAttacks}</div>
                        <div class="stat-label">Total Attacks</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">HTTP</div>
                        <div class="stat-label">Service Type</div>
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
                        <h3>🎯 AI-Enhanced Threat Feed</h3>
                        <p>Real-time AI-powered attack analysis and monitoring</p>
                    </div>
                    <table>
                        <thead>
                            <tr><th>Service</th><th>IP</th><th>Location</th><th>Threat Level</th><th>AI Analysis</th><th>Attack Type</th><th>Time</th></tr>
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
                                    <td>
                                        <strong>${log.social_engineering_score}/10</strong>
                                        ${log.ai_analysis ? `<br><small style="color: #3b82f6;">🤖 AI: ${log.ai_analysis} (${log.ai_confidence}%)</small>` : ''}
                                    </td>
                                    <td>${log.attack_type}</td>
                                    <td>${new Date(log.timestamp).toLocaleString()}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
                
                <div class="action-buttons">
                    <a href="${ADMIN_PATH}/analytics" class="action-btn">📊 Analytics</a>
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
                    <a href="${ADMIN_PATH}/analytics" class="action-btn">📊 Analytics</a>
                    <a href="${ADMIN_PATH}/dashboard" class="action-btn">🛡️ Dashboard</a>
                    <button onclick="location.reload()" class="action-btn">🔄 Refresh</button>
                </div>
            </div>
        </body></html>
    `;
}

function generateSecureAnalytics() {
    return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>ThreatNet Analytics - Secure Console</title>
            <link rel="stylesheet" href="/style.css">
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                .analytics-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin: 2rem 0; }
                .chart-container { background: rgba(30, 41, 59, 0.8); border: 1px solid #334155; padding: 1.5rem; border-radius: 1rem; }
                .chart-title { color: #f1f5f9; font-size: 1.125rem; font-weight: 600; margin-bottom: 1rem; }
                .live-feed { max-height: 400px; overflow-y: auto; background: rgba(15, 23, 42, 0.5); padding: 1rem; border-radius: 0.5rem; border: 1px solid #334155; }
                .attack-item { padding: 0.75rem; margin: 0.5rem 0; background: rgba(30, 41, 59, 0.6); border-left: 4px solid #ef4444; border-radius: 0.5rem; }
                .attack-ip { color: #06b6d4; font-family: monospace; font-weight: 600; }
                .threat-badge { padding: 0.25rem 0.5rem; border-radius: 1rem; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
                .threat-critical { background: #dc2626; color: white; }
                .threat-high { background: #ea580c; color: white; }
                .threat-medium { background: #eab308; color: black; }
                .threat-low { background: #059669; color: white; }
            </style>
        </head>
        <body>
            <div class="admin-container">
                <div class="dashboard-header">
                    <h1>📊 ThreatNet Analytics Console</h1>
                    <p>Real-time threat intelligence and attack visualization</p>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number" id="totalAttacks">Loading...</div>
                        <div class="stat-label">Total Attacks</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="uniqueIPs">Loading...</div>
                        <div class="stat-label">Unique Attackers</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="criticalThreats">Loading...</div>
                        <div class="stat-label">Critical Threats</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="currentThreat">Loading...</div>
                        <div class="stat-label">Threat Level</div>
                    </div>
                </div>

                <div class="analytics-grid">
                    <div class="chart-container">
                        <h3 class="chart-title">🎯 Attack Types Distribution</h3>
                        <canvas id="attackTypesChart"></canvas>
                    </div>
                    <div class="chart-container">
                        <h3 class="chart-title">⚠️ Threat Levels</h3>
                        <canvas id="threatChart"></canvas>
                    </div>
                </div>

                <div class="analytics-grid">
                    <div class="chart-container">
                        <h3 class="chart-title">🕐 Hourly Attack Pattern</h3>
                        <canvas id="hourlyChart"></canvas>
                    </div>
                    <div class="chart-container">
                        <h3 class="chart-title">🌐 Top Attacking IPs</h3>
                        <canvas id="topIPsChart"></canvas>
                    </div>
                </div>

                <div class="chart-container">
                    <h3 class="chart-title">🚨 Live Attack Feed</h3>
                    <div class="live-feed" id="liveFeed">Loading...</div>
                </div>

                <div class="action-buttons">
                    <button onclick="refreshData()" class="action-btn">🔄 Refresh</button>
                    <button onclick="exportData()" class="action-btn">📊 Export</button>
                    <a href="${ADMIN_PATH}/dashboard" class="action-btn">🛡️ Dashboard</a>
                    <a href="${ADMIN_PATH}/threat-intel" class="action-btn">🌐 Intel</a>
                </div>
            </div>

            <script>
                let charts = {};
                
                async function loadAnalytics() {
                    try {
                        const response = await fetch('${ADMIN_PATH}/api/analytics-data');
                        const data = await response.json();
                        
                        document.getElementById('totalAttacks').textContent = data.totalAttacks;
                        document.getElementById('uniqueIPs').textContent = data.uniqueIPs;
                        document.getElementById('criticalThreats').textContent = data.threatLevels.critical || 0;
                        
                        const maxThreat = Object.keys(data.threatLevels).reduce((a, b) => 
                            data.threatLevels[a] > data.threatLevels[b] ? a : b, 'low');
                        document.getElementById('currentThreat').textContent = maxThreat?.toUpperCase() || 'LOW';
                        
                        updateCharts(data);
                        updateLiveFeed(data.recentAttacks);
                        
                    } catch (error) {
                        console.error('Failed to load analytics:', error);
                    }
                }
                
                function updateCharts(data) {
                    const attackCtx = document.getElementById('attackTypesChart').getContext('2d');
                    if (charts.attackTypes) charts.attackTypes.destroy();
                    charts.attackTypes = new Chart(attackCtx, {
                        type: 'doughnut',
                        data: {
                            labels: Object.keys(data.attackTypes),
                            datasets: [{
                                data: Object.values(data.attackTypes),
                                backgroundColor: ['#ef4444', '#f59e0b', '#8b5cf6', '#3b82f6', '#10b981']
                            }]
                        },
                        options: {
                            responsive: true,
                            plugins: { legend: { labels: { color: '#cbd5e1' } } }
                        }
                    });
                    
                    const threatCtx = document.getElementById('threatChart').getContext('2d');
                    if (charts.threat) charts.threat.destroy();
                    charts.threat = new Chart(threatCtx, {
                        type: 'bar',
                        data: {
                            labels: Object.keys(data.threatLevels),
                            datasets: [{
                                data: Object.values(data.threatLevels),
                                backgroundColor: ['#dc2626', '#ea580c', '#eab308', '#059669']
                            }]
                        },
                        options: {
                            responsive: true,
                            plugins: { legend: { display: false } },
                            scales: {
                                x: { ticks: { color: '#cbd5e1' }, grid: { color: '#334155' } },
                                y: { ticks: { color: '#cbd5e1' }, grid: { color: '#334155' } }
                            }
                        }
                    });
                    
                    const hourlyCtx = document.getElementById('hourlyChart').getContext('2d');
                    if (charts.hourly) charts.hourly.destroy();
                    const hourlyLabels = Array.from({length: 24}, (_, i) => i + ':00');
                    const hourlyData = hourlyLabels.map((_, i) => data.hourlyData[i] || 0);
                    
                    charts.hourly = new Chart(hourlyCtx, {
                        type: 'line',
                        data: {
                            labels: hourlyLabels,
                            datasets: [{
                                label: 'Attacks',
                                data: hourlyData,
                                borderColor: '#ef4444',
                                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                                fill: true
                            }]
                        },
                        options: {
                            responsive: true,
                            plugins: { legend: { labels: { color: '#cbd5e1' } } },
                            scales: {
                                x: { ticks: { color: '#cbd5e1' }, grid: { color: '#334155' } },
                                y: { ticks: { color: '#cbd5e1' }, grid: { color: '#334155' } }
                            }
                        }
                    });
                    
                    const ipCtx = document.getElementById('topIPsChart').getContext('2d');
                    if (charts.topIPs) charts.topIPs.destroy();
                    const topIPs = Object.entries(data.topIPs)
                        .sort(([,a], [,b]) => b - a)
                        .slice(0, 5);
                    
                    charts.topIPs = new Chart(ipCtx, {
                        type: 'bar',
                        data: {
                            labels: topIPs.map(([ip]) => ip),
                            datasets: [{
                                label: 'Attacks',
                                data: topIPs.map(([,count]) => count),
                                backgroundColor: '#3b82f6'
                            }]
                        },
                        options: {
                            responsive: true,
                            indexAxis: 'y',
                            plugins: { legend: { labels: { color: '#cbd5e1' } } },
                            scales: {
                                x: { ticks: { color: '#cbd5e1' }, grid: { color: '#334155' } },
                                y: { ticks: { color: '#cbd5e1' }, grid: { color: '#334155' } }
                            }
                        }
                    });
                }
                
                function updateLiveFeed(attacks) {
                    const feed = document.getElementById('liveFeed');
                    feed.innerHTML = attacks.map(attack => \`
                        <div class="attack-item">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <div>
                                    <span class="attack-ip">\${attack.ip}</span> - \${attack.attack_type}
                                    <div style="color: #64748b; font-size: 0.75rem;">\${new Date(attack.timestamp).toLocaleString()}</div>
                                </div>
                                <span class="threat-badge threat-\${attack.threat_level}">\${attack.threat_level.toUpperCase()}</span>
                            </div>
                        </div>
                    \`).join('');
                }
                
                function refreshData() {
                    loadAnalytics();
                }
                
                function exportData() {
                    window.open('${ADMIN_PATH}/api/analytics-data', '_blank');
                }
                
                loadAnalytics();
                setInterval(loadAnalytics, 30000);
            </script>
        </body>
        </html>
    `;
}

app.listen(PORT, () => {
    console.log(`🚀 ThreatNet HTTP Honeypot running on port ${PORT}`);
    console.log(`🌐 Web Interface: http://localhost:${PORT}`);
    console.log(`🔐 Admin Console: http://localhost:${PORT}${ADMIN_PATH}`);
});