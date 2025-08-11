const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Security configuration
const ADMIN_SECRET = process.env.ADMIN_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex');
const ADMIN_PATH = `/security-console-${crypto.randomBytes(4).toString('hex')}`;

console.log(`🔐 Admin Console: http://localhost:${PORT}${ADMIN_PATH}`);

// Rate limiting
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5,
    message: 'Too many login attempts, try again later.'
});

const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 3,
    message: 'Admin access limited. Contact administrator.'
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// Session configuration
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false,
        maxAge: 2 * 60 * 60 * 1000, // 2 hours
        httpOnly: true
    }
}));

// Database setup
const db = new sqlite3.Database(':memory:', (err) => {
    if (err) {
        console.error('DB error:', err.message);
    } else {
        console.log('🗄️ Database connected');
        db.run(`CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            payload TEXT,
            user_agent TEXT,
            attack_type TEXT,
            social_engineering_score INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
    }
});

// Authentication middleware
function requireAuth(req, res, next) {
    if (req.session && req.session.authenticated) {
        return next();
    }
    res.status(401).send('Unauthorized Access');
}

// Social Engineering Detection
function analyzeSocialEngineering(username, password, userAgent) {
    let score = 0;
    let indicators = [];
    
    // Common social engineering patterns
    const commonNames = ['admin', 'administrator', 'root', 'user', 'test', 'guest'];
    const commonPasswords = ['password', '123456', 'admin', 'root', 'test'];
    const urgentWords = ['urgent', 'immediate', 'asap', 'emergency', 'critical'];
    const authorityWords = ['ceo', 'manager', 'director', 'supervisor', 'boss'];
    
    // Check for common credentials (automated attacks)
    if (commonNames.includes(username.toLowerCase())) {
        score += 2;
        indicators.push('Common username');
    }
    
    if (commonPasswords.includes(password.toLowerCase())) {
        score += 2;
        indicators.push('Common password');
    }
    
    // Check for social engineering keywords
    const fullInput = (username + ' ' + password).toLowerCase();
    urgentWords.forEach(word => {
        if (fullInput.includes(word)) {
            score += 3;
            indicators.push('Urgency language');
        }
    });
    
    authorityWords.forEach(word => {
        if (fullInput.includes(word)) {
            score += 3;
            indicators.push('Authority impersonation');
        }
    });
    
    // Check for human-like patterns
    if (username.length > 8 && /[A-Z]/.test(username) && /[0-9]/.test(username)) {
        score += 4;
        indicators.push('Complex username pattern');
    }
    
    if (password.length > 10 && /[!@#$%^&*]/.test(password)) {
        score += 4;
        indicators.push('Complex password pattern');
    }
    
    // User agent analysis
    if (userAgent && !userAgent.includes('curl') && !userAgent.includes('python')) {
        score += 2;
        indicators.push('Human browser');
    }
    
    // Determine attack type
    let attackType = 'automated';
    if (score >= 6) {
        attackType = 'social_engineering';
    } else if (score >= 3) {
        attackType = 'targeted';
    }
    
    return { score, attackType, indicators };
}

// Attack detection patterns
function detectAttackType(input) {
    const patterns = {
        sql_injection: [/(union|select|insert|delete|drop|exec|script)/i, /('|;|--)/],
        xss: [/<script/i, /javascript:/i, /onerror=/i],
        command_injection: [/(;|\||&|`)/i, /(cat|ls|pwd|whoami|id)/i],
        path_traversal: [/\.\.\//, /(etc\/passwd|windows\/system32)/i]
    };
    
    for (const [type, regexes] of Object.entries(patterns)) {
        if (regexes.some(regex => regex.test(input))) {
            return type;
        }
    }
    return 'unknown';
}

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Block old insecure admin routes
app.get('/admin', (req, res) => {
    res.status(404).send('Page not found');
});

app.get('/analytics.html', (req, res) => {
    res.status(404).send('Page not found');
});

app.get('/reset-logs', (req, res) => {
    res.status(404).send('Page not found');
});

app.post('/login', loginLimiter, (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    const username = req.body.username || '';
    const password = req.body.password || '';
    const userAgent = req.get('User-Agent') || '';
    
    // Analyze social engineering
    const socialAnalysis = analyzeSocialEngineering(username, password, userAgent);
    
    // Detect attack type
    const attackType = detectAttackType(username + ' ' + password);
    
    // Log the attempt
    const stmt = db.prepare(`INSERT INTO logs 
        (ip, payload, user_agent, attack_type, social_engineering_score) 
        VALUES (?, ?, ?, ?, ?)`);
    
    stmt.run(
        ip, 
        `username=${username} password=${password}`,
        userAgent,
        socialAnalysis.attackType,
        socialAnalysis.score
    );
    stmt.finalize();
    
    // Response based on analysis
    const isSuspicious = socialAnalysis.score > 0 || attackType !== 'unknown';
    const responseType = socialAnalysis.attackType === 'social_engineering' ? 'social' : 'technical';
    
    res.send(generateResponse(isSuspicious, responseType, socialAnalysis.indicators));
});

// Secure admin login
app.get(`${ADMIN_PATH}/login`, (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html><head><title>Secure Access</title><link rel="stylesheet" href="/style.css"></head>
        <body style="background: #000; color: #0f0;">
            <div style="max-width: 400px; margin: 10rem auto; padding: 2rem; border: 1px solid #0f0;">
                <h2>🔐 Secure Console Access</h2>
                <form method="POST" action="${ADMIN_PATH}/auth">
                    <input type="password" name="secret" placeholder="Access Key" required 
                           style="width: 100%; padding: 1rem; margin: 1rem 0; background: #000; border: 1px solid #0f0; color: #0f0;">
                    <button type="submit" style="width: 100%; padding: 1rem; background: #0f0; color: #000; border: none;">
                        AUTHENTICATE
                    </button>
                </form>
            </div>
        </body></html>
    `);
});

app.post(`${ADMIN_PATH}/auth`, adminLimiter, (req, res) => {
    if (req.body.secret === ADMIN_SECRET) {
        req.session.authenticated = true;
        res.redirect(`${ADMIN_PATH}/dashboard`);
    } else {
        res.status(401).send('Invalid access key');
    }
});

// Secure admin dashboard
app.get(`${ADMIN_PATH}/dashboard`, requireAuth, (req, res) => {
    db.all(`SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100`, [], (err, rows) => {
        if (err) return res.status(500).send('Database error');
        
        const stats = {
            total: rows.length,
            uniqueIPs: new Set(rows.map(r => r.ip)).size,
            socialEngineering: rows.filter(r => r.social_engineering_score >= 6).length,
            automated: rows.filter(r => r.attack_type === 'automated').length,
            targeted: rows.filter(r => r.attack_type === 'targeted').length
        };
        
        res.send(generateSecureDashboard(rows, stats));
    });
});

// Logout
app.post(`${ADMIN_PATH}/logout`, requireAuth, (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

function generateResponse(isSuspicious, type, indicators) {
    const responses = {
        social: {
            title: '🎯 Social Engineering Detected',
            message: 'Advanced behavioral analysis has flagged this attempt as potential social engineering.',
            details: `Indicators: ${indicators.join(', ')}`
        },
        technical: {
            title: '🚨 Technical Attack Detected', 
            message: 'Malicious payload detected in login attempt.',
            details: 'This incident has been logged for security analysis.'
        },
        normal: {
            title: '❌ Authentication Failed',
            message: 'Invalid credentials provided.',
            details: 'Please verify your username and password.'
        }
    };
    
    const response = responses[isSuspicious ? type : 'normal'];
    
    return `
        <!DOCTYPE html>
        <html><head><title>ThreatNet Response</title><link rel="stylesheet" href="/style.css"></head>
        <body>
            <div class="result-container">
                <div class="result-card" style="border-color: ${isSuspicious ? '#ef4444' : '#334155'};">
                    <div style="font-size: 4rem; margin-bottom: 1rem;">${isSuspicious ? '🚨' : '❌'}</div>
                    <h2 style="color: ${isSuspicious ? '#ef4444' : '#f8fafc'};">${response.title}</h2>
                    <p>${response.message}</p>
                    <small style="color: #64748b;">${response.details}</small>
                    <br><br>
                    <a href="/" style="padding: 0.75rem 2rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                       color: white; text-decoration: none; border-radius: 0.5rem;">← Try Again</a>
                    <br><br>
                    <small style="color: #64748b;">🔒 All activities are monitored and logged</small>
                </div>
            </div>
        </body></html>
    `;
}

function generateSecureDashboard(logs, stats) {
    return `
        <!DOCTYPE html>
        <html><head><title>ThreatNet Security Console</title><link rel="stylesheet" href="/style.css"></head>
        <body>
            <div class="admin-container">
                <div class="dashboard-header">
                    <h1>🛡️ ThreatNet Security Console</h1>
                    <p>Advanced Threat Detection & Social Engineering Analysis</p>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">${stats.total}</div>
                        <div class="stat-label">Total Attempts</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${stats.socialEngineering}</div>
                        <div class="stat-label">Social Engineering</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${stats.targeted}</div>
                        <div class="stat-label">Targeted Attacks</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${stats.automated}</div>
                        <div class="stat-label">Automated Bots</div>
                    </div>
                </div>
                
                <div class="table-container">
                    <div class="table-header">
                        <h3>🎯 Social Engineering Analysis</h3>
                        <p>Advanced behavioral detection and threat classification</p>
                    </div>
                    <table>
                        <thead>
                            <tr><th>IP</th><th>Attack Type</th><th>SE Score</th><th>Payload</th><th>Time</th></tr>
                        </thead>
                        <tbody>
                            ${logs.map(log => `
                                <tr style="background: ${log.social_engineering_score >= 6 ? 'rgba(239, 68, 68, 0.1)' : 
                                                        log.social_engineering_score >= 3 ? 'rgba(245, 158, 11, 0.1)' : 
                                                        'transparent'};">
                                    <td style="font-family: monospace;">${log.ip}</td>
                                    <td>
                                        <span style="padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; 
                                                     background: ${log.attack_type === 'social_engineering' ? '#ef4444' : 
                                                                  log.attack_type === 'targeted' ? '#f59e0b' : '#6b7280'}; 
                                                     color: white;">
                                            ${log.attack_type.toUpperCase()}
                                        </span>
                                    </td>
                                    <td><strong>${log.social_engineering_score}/10</strong></td>
                                    <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis;">${log.payload}</td>
                                    <td>${new Date(log.timestamp).toLocaleString()}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
                
                <div class="action-buttons">
                    <button onclick="location.reload()" class="action-btn">🔄 Refresh</button>
                    <form method="POST" action="${ADMIN_PATH}/logout" style="display: inline;">
                        <button type="submit" class="action-btn">🚪 Logout</button>
                    </form>
                </div>
            </div>
        </body></html>
    `;
}

app.listen(PORT, () => {
    console.log(`🚀 ThreatNet running on port ${PORT}`);
    console.log(`🔑 Admin Secret: ${ADMIN_SECRET}`);
});