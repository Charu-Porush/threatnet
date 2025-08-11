#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

console.log('🍯 Setting up Enhanced Honeypot...\n');

// Create logs directory
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir);
    console.log('✅ Created logs directory');
}

// Create backup directory
const backupDir = path.join(__dirname, 'backups');
if (!fs.existsSync(backupDir)) {
    fs.mkdirSync(backupDir);
    console.log('✅ Created backups directory');
}

// Install dependencies
console.log('\n📦 Installing dependencies...');
try {
    execSync('npm install', { stdio: 'inherit' });
    console.log('✅ Dependencies installed successfully');
} catch (error) {
    console.error('❌ Failed to install dependencies:', error.message);
    process.exit(1);
}

// Create environment file template
const envTemplate = `# Honeypot Configuration
PORT=3000
HOST=localhost

# Email Configuration (Optional)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password
EMAIL_RECIPIENTS=admin@yourdomain.com

# Webhook URLs (Optional)
SLACK_WEBHOOK_URL=
DISCORD_WEBHOOK_URL=

# Security Settings
MAX_SUSPICIOUS_ATTEMPTS=3
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX=5

# Database
DB_PATH=./honeypot.db
`;

const envPath = path.join(__dirname, '.env.example');
fs.writeFileSync(envPath, envTemplate);
console.log('✅ Created .env.example file');

// Create startup scripts
const startScript = `#!/bin/bash
echo "🍯 Starting Enhanced Honeypot..."
node enhanced-server.js
`;

const startScriptPath = path.join(__dirname, 'start.sh');
fs.writeFileSync(startScriptPath, startScript);
fs.chmodSync(startScriptPath, '755');
console.log('✅ Created start.sh script');

// Update package.json scripts
const packageJsonPath = path.join(__dirname, 'package.json');
const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));

packageJson.scripts = {
    ...packageJson.scripts,
    "start": "node enhanced-server.js",
    "dev": "nodemon enhanced-server.js",
    "setup": "node setup.js",
    "backup": "node backup.js"
};

fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2));
console.log('✅ Updated package.json scripts');

// Create backup script
const backupScript = `const fs = require('fs');
const path = require('path');

const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
const backupPath = path.join(__dirname, 'backups', \`honeypot-backup-\${timestamp}.db\`);

try {
    fs.copyFileSync('./honeypot.db', backupPath);
    console.log(\`✅ Database backed up to: \${backupPath}\`);
} catch (error) {
    console.error('❌ Backup failed:', error.message);
}
`;

fs.writeFileSync(path.join(__dirname, 'backup.js'), backupScript);
console.log('✅ Created backup.js script');

console.log('\n🎉 Setup completed successfully!\n');

console.log('📋 Next steps:');
console.log('1. Copy .env.example to .env and configure your settings');
console.log('2. Run: npm start (or node enhanced-server.js)');
console.log('3. Visit: http://localhost:3000 for the honeypot');
console.log('4. Visit: http://localhost:3000/admin for the dashboard');
console.log('5. Visit: http://localhost:3000/analytics.html for analytics\n');

console.log('🔧 Available commands:');
console.log('- npm start: Start the honeypot server');
console.log('- npm run backup: Backup the database');
console.log('- ./start.sh: Alternative start script\n');

console.log('⚠️  Security Notes:');
console.log('- Change default admin endpoint in production');
console.log('- Configure email alerts in config.js');
console.log('- Set up proper firewall rules');
console.log('- Monitor logs regularly');
console.log('- Keep dependencies updated\n');

console.log('🍯 Your enhanced honeypot is ready to catch attackers!');