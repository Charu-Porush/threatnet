const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to parse form data
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public'))); // to serve frontend files

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

// Serve your homepage (we will create this later)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

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
app.post('/login', (req, res) => {
    const ip = req.ip;
    const username = req.body.username;
    const password = req.body.password;

    let alert = '';

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
                <p class="result-message">
                    ${isAttack ? 
                        'Suspicious activity detected in your login attempt. This incident has been logged for security analysis.' : 
                        'Invalid credentials provided. Please verify your username and password and try again.'}
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

// Admin dashboard route to show logs
app.get('/admin', (req, res) => {
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
                <h1 class="dashboard-title">🔍 Security Monitoring</h1>
                <p class="dashboard-subtitle">Real-time threat detection and analysis</p>
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




