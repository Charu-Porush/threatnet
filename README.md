# 🍯 Enhanced Honeypot Security System

A comprehensive web-based honeypot designed to detect, log, and analyze cyber attacks. This enhanced version includes advanced features like real-time monitoring, IP blocking, email alerts, and detailed analytics.

## 🚀 Features

### Core Security Features
- **Advanced Attack Detection**: Detects SQL injection, XSS, command injection, path traversal, and bot activities
- **Real-time IP Blocking**: Automatically blocks suspicious IPs after multiple attack attempts
- **Rate Limiting**: Prevents brute force attacks with configurable limits
- **Session Tracking**: Monitors persistent attackers across sessions

### Monitoring & Analytics
- **Real-time Dashboard**: Live monitoring of attacks and system status
- **Advanced Analytics**: Charts and graphs showing attack patterns and trends
- **Attack Classification**: Categorizes attacks by type and severity level
- **Geolocation Tracking**: Maps attacker locations (optional)

### Alert System
- **Email Notifications**: Instant email alerts for high-severity attacks
- **Webhook Integration**: Slack/Discord notifications support
- **Daily Reports**: Automated summary reports
- **Customizable Thresholds**: Configure when alerts are triggered

### Data Management
- **SQLite Database**: Efficient logging of all attack attempts
- **Export Functionality**: CSV/JSON export of logs
- **Automatic Cleanup**: Configurable log retention policies
- **Database Backups**: Automated backup system

### Decoy Services
- **Fake Endpoints**: Multiple decoy URLs to attract attackers
- **Realistic Responses**: Convincing error messages and responses
- **Honeypot Detection**: Identifies reconnaissance attempts

## 📦 Installation

### Prerequisites
- Node.js (v14 or higher)
- npm or yarn

### Quick Setup
```bash
# Clone or download the project
cd HoneyPot

# Run the setup script
node setup.js

# Configure your settings (optional)
cp .env.example .env
nano .env

# Start the honeypot
npm start
```

### Manual Installation
```bash
# Install dependencies
npm install

# Create required directories
mkdir logs backups

# Start the server
node enhanced-server.js
```

## 🔧 Configuration

### Basic Configuration
Edit `config.js` to customize your honeypot settings:

```javascript
module.exports = {
    server: {
        port: 3000,
        host: 'localhost'
    },
    rateLimit: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 5 // max attempts per window
    },
    // ... more settings
};
```

### Email Alerts Setup
1. Enable email alerts in `config.js`:
```javascript
emailAlerts: {
    enabled: true,
    smtp: {
        host: 'smtp.gmail.com',
        port: 587,
        auth: {
            user: 'your-email@gmail.com',
            pass: 'your-app-password'
        }
    },
    recipients: ['admin@yourdomain.com']
}
```

2. For Gmail, create an App Password:
   - Go to Google Account settings
   - Enable 2-factor authentication
   - Generate an App Password
   - Use the App Password in the config

### Webhook Alerts (Slack/Discord)
```javascript
webhookAlerts: {
    enabled: true,
    urls: [
        'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
    ]
}
```

## 🖥️ Usage

### Starting the Honeypot
```bash
# Standard start
npm start

# Development mode with auto-restart
npm run dev

# Using the shell script
./start.sh
```

### Accessing the Interface
- **Honeypot**: http://localhost:3000
- **Admin Dashboard**: http://localhost:3000/admin
- **Analytics**: http://localhost:3000/analytics.html
- **Blocked IPs**: http://localhost:3000/blocked-ips

### Testing the Honeypot
Try these test payloads to trigger detection:
```
Username: admin' OR '1'='1
Password: ' UNION SELECT * FROM users--
```

## 📊 Monitoring

### Dashboard Features
- Real-time attack statistics
- Attack type distribution
- Top attacking IPs
- Threat level indicators
- Live attack feed

### Log Analysis
The system logs detailed information about each attack:
- IP address and geolocation
- User agent and session data
- Attack payload and classification
- Severity level and timestamp

### Export Options
- **CSV Export**: `/export/csv`
- **JSON Export**: `/export/json`
- **Blocked IPs**: `/blocked-ips`

## 🛡️ Security Considerations

### Production Deployment
1. **Change Default Endpoints**: Modify admin URLs
2. **Use HTTPS**: Implement SSL/TLS certificates
3. **Firewall Rules**: Restrict admin access by IP
4. **Regular Updates**: Keep dependencies updated
5. **Monitor Resources**: Watch CPU/memory usage

### Network Security
- Deploy behind a reverse proxy (nginx/Apache)
- Use fail2ban for additional IP blocking
- Implement network segmentation
- Regular security audits

## 🔍 Attack Detection

### Supported Attack Types
- **SQL Injection**: Various SQL injection patterns
- **Cross-Site Scripting (XSS)**: Script injection attempts
- **Command Injection**: System command execution attempts
- **Path Traversal**: Directory traversal attacks
- **Bot/Scanner Detection**: Automated tool identification

### Custom Patterns
Add custom detection patterns in `config.js`:
```javascript
detection: {
    customPatterns: [
        { 
            name: 'Custom Attack', 
            pattern: /your-regex-here/i, 
            severity: 4 
        }
    ]
}
```

## 📈 Analytics & Reporting

### Real-time Metrics
- Total attacks per day
- Unique attacking IPs
- Attack success/failure rates
- Geographic distribution

### Historical Analysis
- Attack trends over time
- Seasonal patterns
- IP reputation tracking
- Attack evolution analysis

## 🚨 Alert System

### Alert Types
- **Immediate**: High-severity attacks
- **Threshold**: Multiple attempts from same IP
- **Daily Summary**: End-of-day reports
- **System Health**: Server status updates

### Notification Channels
- Email (SMTP)
- Slack webhooks
- Discord webhooks
- Custom webhook endpoints

## 🔧 Maintenance

### Database Management
```bash
# Backup database
npm run backup

# View database size
ls -lh honeypot.db

# Clean old logs (manual)
sqlite3 honeypot.db "DELETE FROM logs WHERE timestamp < datetime('now', '-30 days');"
```

### Log Rotation
The system automatically manages log files:
- Maximum file size: 10MB
- Maximum files: 5
- Automatic compression

## 🤝 Contributing

### Adding Features
1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests if applicable
5. Submit a pull request

### Reporting Issues
- Use GitHub issues for bug reports
- Include system information
- Provide reproduction steps
- Attach relevant logs

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This honeypot is designed for educational and defensive security purposes only. Users are responsible for:
- Complying with local laws and regulations
- Proper network security implementation
- Regular monitoring and maintenance
- Ethical use of collected data

## 🆘 Support

### Documentation
- Check this README for common issues
- Review configuration examples
- Examine log files for errors

### Community
- GitHub Discussions for questions
- Issue tracker for bugs
- Wiki for additional documentation

---

**Happy Hunting! 🍯🐛**

Remember: A honeypot is only as good as its monitoring and response procedures. Stay vigilant!