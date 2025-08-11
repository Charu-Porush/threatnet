const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = 4000;

app.use(express.static('public'));

// Connect to database
const db = new sqlite3.Database('./threatnet.db', (err) => {
    if (err) {
        console.log('No database found, creating sample data...');
        createSampleData();
    }
});

function createSampleData() {
    const sampleDb = new sqlite3.Database(':memory:');
    sampleDb.serialize(() => {
        sampleDb.run(`CREATE TABLE logs (
            id INTEGER PRIMARY KEY,
            service TEXT,
            ip TEXT,
            attack_type TEXT,
            threat_level TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
        
        const attacks = [
            ['http', '192.168.1.100', 'sql_injection', 'high'],
            ['http', '10.0.0.50', 'xss', 'medium'],
            ['ssh', '203.0.113.10', 'brute_force', 'critical'],
            ['ftp', '172.16.0.25', 'directory_traversal', 'medium'],
            ['http', '192.168.1.100', 'command_injection', 'high']
        ];
        
        attacks.forEach(attack => {
            sampleDb.run('INSERT INTO logs (service, ip, attack_type, threat_level) VALUES (?, ?, ?, ?)', attack);
        });
    });
    return sampleDb;
}

// Analytics page
app.get('/analytics', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>ThreatNet Analytics</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body { background: #0f172a; color: #f1f5f9; font-family: Arial; margin: 0; padding: 20px; }
                .container { max-width: 1200px; margin: 0 auto; }
                .header { text-align: center; margin-bottom: 30px; }
                .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }
                .stat-card { background: #1e293b; padding: 20px; border-radius: 10px; text-align: center; }
                .stat-number { font-size: 2rem; font-weight: bold; color: #3b82f6; }
                .charts { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
                .chart-container { background: #1e293b; padding: 20px; border-radius: 10px; }
                canvas { max-height: 300px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ ThreatNet Analytics</h1>
                    <p>Real-time threat intelligence dashboard</p>
                </div>
                
                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-number" id="totalAttacks">0</div>
                        <div>Total Attacks</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="uniqueIPs">0</div>
                        <div>Unique IPs</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="criticalThreats">0</div>
                        <div>Critical Threats</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="services">3</div>
                        <div>Services</div>
                    </div>
                </div>
                
                <div class="charts">
                    <div class="chart-container">
                        <h3>Attack Types</h3>
                        <canvas id="attackChart"></canvas>
                    </div>
                    <div class="chart-container">
                        <h3>Threat Levels</h3>
                        <canvas id="threatChart"></canvas>
                    </div>
                </div>
            </div>
            
            <script>
                async function loadData() {
                    const response = await fetch('/api/stats');
                    const data = await response.json();
                    
                    document.getElementById('totalAttacks').textContent = data.total;
                    document.getElementById('uniqueIPs').textContent = data.uniqueIPs;
                    document.getElementById('criticalThreats').textContent = data.critical;
                    
                    // Attack Types Chart
                    new Chart(document.getElementById('attackChart'), {
                        type: 'doughnut',
                        data: {
                            labels: Object.keys(data.attackTypes),
                            datasets: [{
                                data: Object.values(data.attackTypes),
                                backgroundColor: ['#ef4444', '#f59e0b', '#8b5cf6', '#3b82f6', '#10b981']
                            }]
                        },
                        options: { responsive: true, plugins: { legend: { labels: { color: '#f1f5f9' } } } }
                    });
                    
                    // Threat Levels Chart
                    new Chart(document.getElementById('threatChart'), {
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
                                x: { ticks: { color: '#f1f5f9' } },
                                y: { ticks: { color: '#f1f5f9' } }
                            }
                        }
                    });
                }
                
                loadData();
                setInterval(loadData, 10000);
            </script>
        </body>
        </html>
    `);
});

// API endpoint
app.get('/api/stats', (req, res) => {
    db.all('SELECT * FROM logs', [], (err, rows) => {
        if (err || !rows) {
            // Return sample data if no database
            return res.json({
                total: 25,
                uniqueIPs: 8,
                critical: 3,
                attackTypes: {
                    'SQL Injection': 8,
                    'XSS': 6,
                    'Brute Force': 5,
                    'Directory Traversal': 4,
                    'Command Injection': 2
                },
                threatLevels: {
                    'Critical': 3,
                    'High': 8,
                    'Medium': 10,
                    'Low': 4
                }
            });
        }
        
        const stats = {
            total: rows.length,
            uniqueIPs: [...new Set(rows.map(r => r.ip))].length,
            critical: rows.filter(r => r.threat_level === 'critical').length,
            attackTypes: {},
            threatLevels: {}
        };
        
        rows.forEach(row => {
            stats.attackTypes[row.attack_type] = (stats.attackTypes[row.attack_type] || 0) + 1;
            stats.threatLevels[row.threat_level] = (stats.threatLevels[row.threat_level] || 0) + 1;
        });
        
        res.json(stats);
    });
});

app.listen(PORT, () => {
    console.log(`🚀 Analytics Server: http://localhost:${PORT}/analytics`);
});