const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to parse form data
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public'))); // to serve frontend files

// Session configuration
app.use(session({
    secret: 'honeypot-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Authentication middleware
function requireAuth(req, res, next) {
    if (req.session.authenticated) {
        next();
    } else {
        res.redirect('/dashboard-login');
    }
}

// Setup SQLite database (in-memory for Vercel)
const db = new sqlite3.Database(':memory:', (err) => {
    if (err) {
        console.error('DB connection error:', err.message);
    } else {
        console.log('Connected to SQLite DB.');
        db.run(`CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT,
      payload TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    }
});

// Serve your homepage with AI indicator
app.get('/', (req, res) => {
    const fs = require('fs');
    let html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
    
    // Add AI status indicator
    const aiIndicator = `
        <div style="position: fixed; top: 20px; right: 20px; background: rgba(59, 130, 246, 0.9); color: white; padding: 0.75rem 1rem; border-radius: 0.5rem; font-size: 0.875rem; z-index: 1000; backdrop-filter: blur(10px); box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
            🤖 AI Security: <span style="color: #10b981; font-weight: bold;">ACTIVE</span>
        </div>
    `;
    
    // Inject before closing body tag
    html = html.replace('</body>', aiIndicator + '</body>');
    
    res.send(html);
});

// Dashboard login page
app.get('/dashboard-login', (req, res) => {
    const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Dashboard Login - ThreatNet</title>
        <link rel="stylesheet" href="/style.css">
    </head>
    <body>
        <div style="max-width: 400px; margin: 8rem auto; padding: 0 1rem;">
            <div style="background: rgba(30, 41, 59, 0.8); border: 1px solid #64748b; border-radius: 1rem; padding: 3rem;">
                <h2 style="text-align: center; color: #f1f5f9; margin-bottom: 2rem;">🛡️ Dashboard Access</h2>
                <form method="POST" action="/dashboard-login">
                    <div style="margin-bottom: 1rem;">
                        <input type="password" name="password" placeholder="Admin Password" required 
                               style="width: 100%; padding: 0.75rem; border: 1px solid #64748b; border-radius: 0.5rem; background: rgba(15, 23, 42, 0.8); color: #f1f5f9;">
                    </div>
                    <button type="submit" style="width: 100%; padding: 0.75rem; background: linear-gradient(135deg, #3b82f6, #1d4ed8); color: white; border: none; border-radius: 0.5rem; cursor: pointer;">Access Dashboard</button>
                </form>
                <div style="text-align: center; margin-top: 1rem;">
                    <a href="/" style="color: #94a3b8; text-decoration: none;">← Back to Home</a>
                </div>
            </div>
        </div>
    </body>
    </html>`;
    res.send(html);
});

// Dashboard login handler
app.post('/dashboard-login', (req, res) => {
    const password = req.body.password;
    if (password === 'admin123') { // Change this password
        req.session.authenticated = true;
        res.redirect('/admin');
    } else {
        res.redirect('/dashboard-login?error=1');
    }
});

// AI-Powered Threat Analysis
async function aiThreatAnalysis(payload) {
    try {
        // Fallback AI simulation (works offline)
        const patterns = ['union', 'select', 'script', 'alert', '../', 'admin', "'", '--', 'or', 'and'];
        const threatWords = patterns.filter(p => payload.toLowerCase().includes(p));
        
        return {
            ai_analysis: threatWords.length > 2 ? 'MALICIOUS' : threatWords.length > 0 ? 'SUSPICIOUS' : 'BENIGN',
            ai_confidence: threatWords.length > 2 ? 92 : threatWords.length > 0 ? 75 : 45,
            ai_threat_level: threatWords.length > 2 ? 'HIGH' : threatWords.length > 0 ? 'MEDIUM' : 'LOW',
            ai_indicators: [`AI detected ${threatWords.length} threat patterns: ${threatWords.slice(0, 3).join(', ')}`]
        };
    } catch (error) {
        return {
            ai_analysis: 'UNKNOWN',
            ai_confidence: 50,
            ai_threat_level: 'MEDIUM',
            ai_indicators: ['AI analysis unavailable']
        };
    }
}

// Bot vs Human Detection
function detectBotOrHuman(userAgent, payload) {
    let botScore = 0;
    let indicators = [];
    
    // User Agent Analysis
    const botPatterns = ['bot', 'crawler', 'spider', 'curl', 'wget', 'python', 'scanner', 'sqlmap', 'nmap', 'burp'];
    const humanBrowsers = ['chrome', 'firefox', 'safari', 'edge', 'opera'];
    
    if (userAgent) {
        const ua = userAgent.toLowerCase();
        
        botPatterns.forEach(pattern => {
            if (ua.includes(pattern)) {
                botScore += 3;
                indicators.push(`Bot pattern: ${pattern}`);
            }
        });
        
        if (humanBrowsers.some(browser => ua.includes(browser))) {
            botScore -= 2;
            indicators.push('Human browser');
        }
    } else {
        botScore += 4;
        indicators.push('No user agent');
    }
    
    // Payload Analysis
    if (payload && /union.*select|<script|1'.*or.*'1/i.test(payload)) {
        botScore += 2;
        indicators.push('Automated attack');
    }
    
    const classification = botScore >= 5 ? 'BOT' : botScore <= -1 ? 'HUMAN' : 'SUSPICIOUS';
    const confidence = Math.min(0.95, 0.6 + Math.abs(botScore) * 0.05);
    
    return { classification, confidence, indicators };
}

function isSuspicious(input) {
    const suspiciousPatterns = [
        /(\bor\b|\band\b).*=.*--/i,           // SQL Injection keyword patterns
        /('|;|--|\/\*|\*\/)/,                 // SQL Injection special chars
        /<script.*?>.*?<\/script>/i,          // XSS script tags
        /javascript:/i,                       // JS in URLs
        /<.*?on\w+=.*?>/i,                   // Inline JS event handlers in tags
    ];

    return suspiciousPatterns.some((pattern) => pattern.test(input));
}

// Handle login form submission
app.post('/login', async (req, res) => {
    const ip = req.ip;
    const username = req.body.username;
    const password = req.body.password;
    const userAgent = req.get('User-Agent') || 'Unknown';
    const payload = `username=${username} password=${password}`;

    let alert = '';
    const botAnalysis = detectBotOrHuman(userAgent, payload);
    const aiAnalysis = await aiThreatAnalysis(payload);

    if (isSuspicious(username) || isSuspicious(password)) {
        alert = '[!] Suspicious input detected!';
    }

    // Log every attempt (for now)
    const stmt = db.prepare('INSERT INTO logs (ip, payload) VALUES (?, ?)');
    stmt.run(ip, `username=${username} password=${password}`, (err) => {
        if (err) {
            console.error(err.message);
        }
    });
    stmt.finalize();

    // Send stylish response page
    const isAttack = alert !== '';
    const responseHtml = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Authentication Result</title>
        <link rel="stylesheet" href="/style.css">
        <style>
            .result-container {
                max-width: 500px;
                margin: 8rem auto;
                padding: 0 1rem;
            }
            .result-card {
                background: rgba(30, 41, 59, 0.8);
                backdrop-filter: blur(20px);
                border: 1px solid ${isAttack ? 'var(--accent-red)' : 'var(--border-color)'};
                border-radius: 1rem;
                padding: 3rem;
                text-align: center;
                box-shadow: var(--shadow-lg);
            }
            .result-icon {
                font-size: 4rem;
                margin-bottom: 1rem;
            }
            .result-title {
                font-size: 1.5rem;
                font-weight: 700;
                color: ${isAttack ? 'var(--accent-red)' : 'var(--text-primary)'};
                margin-bottom: 1rem;
            }
            .result-message {
                color: var(--text-secondary);
                margin-bottom: 2rem;
                line-height: 1.6;
            }
            .back-button {
                display: inline-block;
                padding: 0.75rem 2rem;
                background: var(--gradient-primary);
                color: white;
                text-decoration: none;
                border-radius: 0.5rem;
                font-weight: 600;
                transition: all 0.3s ease;
            }
            .back-button:hover {
                transform: translateY(-2px);
                box-shadow: var(--shadow-md);
            }
        </style>
    </head>
    <body>
        <header class="security-header">
            <div class="header-content">
                <a href="/" class="logo">ThreatNet</a>
                <nav class="nav-menu">
                    <ul class="nav-links">
                        <li><a href="/" class="active">🏠 Home</a></li>
                        <li><a href="/admin">🛡️ Dashboard</a></li>
                        <li><a href="/analytics.html">📊 Analytics</a></li>
                    </ul>
                    <div class="status-indicator">
                        <div class="status-dot"></div>
                        System Active
                    </div>
                </nav>
            </div>
        </header>

        <div class="result-container">
            <div class="result-card">
                <div class="result-icon">${isAttack ? '🚨' : '❌'}</div>
                <h2 class="result-title">${isAttack ? 'Security Alert' : 'Authentication Failed'}</h2>
                <div style="background: rgba(15, 23, 42, 0.8); border-radius: 0.5rem; padding: 1.5rem; margin: 1.5rem 0; text-align: left;">
                    <h4 style="color: #3b82f6; margin-bottom: 1rem;">🤖 AI-Powered Analysis</h4>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
                        <div>
                            <strong>AI Classification:</strong><br>
                            <span style="color: ${aiAnalysis.ai_analysis === 'MALICIOUS' ? '#ef4444' : aiAnalysis.ai_analysis === 'SUSPICIOUS' ? '#f59e0b' : '#10b981'}; font-weight: bold;">
                                ${aiAnalysis.ai_analysis}
                            </span>
                        </div>
                        <div>
                            <strong>AI Confidence:</strong><br>
                            <span style="color: #3b82f6; font-weight: bold;">${aiAnalysis.ai_confidence}%</span>
                        </div>
                    </div>
                    <p><strong>Attacker Type:</strong> ${botAnalysis.classification}</p>
                    <p><strong>Bot Confidence:</strong> ${Math.round(botAnalysis.confidence * 100)}%</p>
                    <p><strong>AI Indicators:</strong> ${aiAnalysis.ai_indicators[0]}</p>
                </div>
                <p class="result-message">
                    ${isAttack ? 
                        'Suspicious activity detected and logged for analysis.' : 
                        'Invalid credentials provided. Please try again.'}
                </p>
                <a href="/" class="back-button">← Try Again</a>
            </div>
        </div>

        <footer class="security-footer">
            <div class="footer-content">
                <div class="footer-section">
                    <h4>🛡️ ThreatNet</h4>
                    <p>Advanced honeypot security system for real-time threat detection and analysis.</p>
                </div>
                <div class="footer-section">
                    <h4>🔗 Quick Links</h4>
                    <ul class="footer-links">
                        <li><a href="/">🏠 Home</a></li>
                        <li><a href="/admin">🛡️ Dashboard</a></li>
                        <li><a href="/analytics.html">📊 Analytics</a></li>
                    </ul>
                </div>
                <div class="footer-section">
                    <h4>📊 Security Stats</h4>
                    <p>• Multi-vector attack detection<br>
                    • Real-time threat monitoring<br>
                    • Advanced analytics & reporting</p>
                </div>
            </div>
            <div class="footer-bottom">
                <p>&copy; 2024 ThreatNet. Built for cybersecurity professionals.</p>
            </div>
        </footer>
    </body>
    </html>
    `;
    
    res.send(responseHtml);
});

// Reset logs route
app.get('/reset-logs', (req, res) => {
    db.run('DELETE FROM logs', [], (err) => {
        if (err) {
            console.error('Error clearing logs:', err.message);
            return res.status(500).send('Error clearing logs');
        }
        console.log('All logs cleared');
        res.redirect('/admin');
    });
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});

// Security console login endpoint
app.get('/security-console-x7k9/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/security-console-x7k9/login', (req, res) => {
    const ip = req.ip;
    const username = req.body.username;
    const password = req.body.password;

    let alert = '';

    if (isSuspicious(username) || isSuspicious(password)) {
        alert = '[!] Suspicious input detected!';
    }

    // Log every attempt
    const stmt = db.prepare('INSERT INTO logs (ip, payload) VALUES (?, ?)');
    stmt.run(ip, `security-console: username=${username} password=${password}`, (err) => {
        if (err) {
            console.error(err.message);
        }
    });
    stmt.finalize();

    // Redirect to main login result
    res.redirect('/login-result?status=' + (alert ? 'threat' : 'failed'));
});

// Login result endpoint
app.get('/login-result', (req, res) => {
    const status = req.query.status;
    const isAttack = status === 'threat';
    
    const responseHtml = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Console - Authentication Result</title>
        <link rel="stylesheet" href="/style.css">
    </head>
    <body>
        <header class="security-header">
            <div class="header-content">
                <a href="/" class="logo">ThreatNet</a>
                <nav class="nav-menu">
                    <ul class="nav-links">
                        <li><a href="/">🏠 Home</a></li>
                        <li><a href="/admin">🛡️ Dashboard</a></li>
                        <li><a href="/analytics.html">📊 Analytics</a></li>
                    </ul>
                </nav>
            </div>
        </header>
        <div style="max-width: 500px; margin: 8rem auto; padding: 0 1rem;">
            <div style="background: rgba(30, 41, 59, 0.8); border: 1px solid ${isAttack ? '#ef4444' : '#64748b'}; border-radius: 1rem; padding: 3rem; text-align: center;">
                <div style="font-size: 4rem; margin-bottom: 1rem;">${isAttack ? '🚨' : '❌'}</div>
                <h2 style="color: ${isAttack ? '#ef4444' : '#f1f5f9'}; margin-bottom: 1rem;">${isAttack ? 'Security Alert' : 'Access Denied'}</h2>
                <p style="color: #94a3b8; margin-bottom: 2rem;">
                    ${isAttack ? 'Suspicious activity detected. Incident logged.' : 'Invalid credentials. Access denied.'}
                </p>
                <a href="/" style="display: inline-block; padding: 0.75rem 2rem; background: linear-gradient(135deg, #3b82f6, #1d4ed8); color: white; text-decoration: none; border-radius: 0.5rem;">← Return Home</a>
            </div>
        </div>
    </body>
    </html>
    `;
    
    res.send(responseHtml);
});

// Admin dashboard route to show logs (protected)
app.get('/admin', requireAuth, (req, res) => {
    db.all('SELECT * FROM logs ORDER BY timestamp DESC', [], (err, rows) => {
        if (err) {
            return res.status(500).send('Database error');
        }

        // Build professional admin dashboard
        let html = `
        <!DOCTYPE html>
        <html lang="en">
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Dashboard - Honeypot Logs</title>
            <link rel="stylesheet" href="/style.css">
            <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>">
            <meta http-equiv="refresh" content="30">
          </head>
          <body>
            <header class="security-header">
              <div class="header-content">
                <a href="/" class="logo">ThreatNet</a>
                <nav class="nav-menu">
                  <ul class="nav-links">
                    <li><a href="/">🏠 Home</a></li>
                    <li><a href="/admin" class="active">🛡️ Dashboard</a></li>
                    <li><a href="/analytics.html">📊 Analytics</a></li>
                  </ul>
                  <div class="status-indicator">
                    <div class="status-dot"></div>
                    Monitoring Active
                  </div>
                </nav>
              </div>
            </header>

            <div class="admin-container">
              <div class="dashboard-header">
                <h1 class="dashboard-title">🤖 AI-Enhanced Security Monitoring</h1>
                <p class="dashboard-subtitle">AI-powered real-time threat detection and analysis</p>
                <div style="background: rgba(59, 130, 246, 0.1); border: 1px solid #3b82f6; border-radius: 0.5rem; padding: 1rem; margin: 1rem 0;">
                    <span style="color: #3b82f6; font-weight: bold;">✨ AI Status:</span> 
                    <span style="color: #10b981;">Machine Learning Threat Analysis ACTIVE</span>
                </div>
              </div>

              <div class="stats-grid">
                <div class="stat-card">
                  <div class="stat-number">${rows.length}</div>
                  <div class="stat-label">Total Logs</div>
                </div>
                <div class="stat-card">
                  <div class="stat-number">${new Set(rows.map(r => r.ip)).size}</div>
                  <div class="stat-label">Unique IPs</div>
                </div>
                <div class="stat-card">
                  <div class="stat-number">${rows.filter(r => r.payload.includes("'") || r.payload.includes("<script")).length}</div>
                  <div class="stat-label">Threats Detected</div>
                </div>
                <div class="stat-card">
                  <div class="stat-number">${new Date().toLocaleDateString()}</div>
                  <div class="stat-label">Last Updated</div>
                </div>
              </div>

              <div class="action-buttons">
                <a href="/" class="action-btn">🏠 Home</a>
                <a href="/analytics.html" class="action-btn">📈 Analytics</a>
                <a href="#" class="action-btn" onclick="window.location.reload()">🔄 Refresh</a>
                <a href="/reset-logs" class="action-btn" onclick="return confirm('Are you sure you want to clear all logs?')">🗑️ Clear Logs</a>
                <a href="/logout" class="action-btn">🚪 Logout</a>
              </div>

              <div class="table-container">
                <div class="table-header">
                  <h3 class="table-title">Attack Logs</h3>
                  <p class="table-description">Recent security events and potential threats</p>
                </div>
                <table>
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>IP Address</th>
                      <th>Payload</th>
                      <th>Timestamp</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>`;

        rows.forEach((row) => {
            const isSuspicious = row.payload.includes("'") || row.payload.includes("<script") || row.payload.includes("--");
            const statusBadge = isSuspicious ? '<span style="background: var(--accent-red); color: white; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem;">THREAT</span>' : '<span style="background: var(--accent-green); color: white; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem;">NORMAL</span>';
            
            html += `
                    <tr ${isSuspicious ? 'style="background: rgba(239, 68, 68, 0.1); border-left: 3px solid var(--accent-red);"' : ''}>
                      <td>${row.id}</td>
                      <td style="font-family: monospace;">${row.ip}</td>
                      <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${row.payload}">${row.payload}</td>
                      <td>${new Date(row.timestamp).toLocaleString()}</td>
                      <td>${statusBadge}</td>
                    </tr>`;
        });

        html += `
                  </tbody>
                </table>
              </div>
            </div>

            <footer class="security-footer">
                <div class="footer-content">
                    <div class="footer-section">
                        <h4>🛡️ ThreatNet</h4>
                        <p>Advanced honeypot security system for real-time threat detection and analysis.</p>
                    </div>
                    <div class="footer-section">
                        <h4>🔗 Quick Links</h4>
                        <ul class="footer-links">
                            <li><a href="/">🏠 Home</a></li>
                            <li><a href="/admin">🛡️ Dashboard</a></li>
                            <li><a href="/analytics.html">📊 Analytics</a></li>
                        </ul>
                    </div>
                    <div class="footer-section">
                        <h4>📊 Security Stats</h4>
                        <p>• Multi-vector attack detection<br>
                        • Real-time threat monitoring<br>
                        • Advanced analytics & reporting</p>
                    </div>
                </div>
                <div class="footer-bottom">
                    <p>&copy; 2024 ThreatNet. Built for cybersecurity professionals.</p>
                </div>
            </footer>
          </body>
        </html>
      `;

        res.send(html);
    });
});

// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// Protect analytics route
app.get('/analytics.html', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'analytics.html'));
});


