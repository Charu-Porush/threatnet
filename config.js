module.exports = {
    // Server Configuration
    server: {
        port: process.env.PORT || 3000,
        host: process.env.HOST || 'localhost'
    },

    // Rate Limiting
    rateLimit: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 5, // limit each IP to 5 requests per windowMs
        skipSuccessfulRequests: false
    },

    // IP Blocking
    ipBlocking: {
        maxSuspiciousAttempts: 3,
        blockDuration: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
        autoUnblock: true
    },

    // Email Alerts Configuration
    emailAlerts: {
        enabled: false, // Set to true to enable email alerts
        smtp: {
            host: 'smtp.gmail.com',
            port: 587,
            secure: false,
            auth: {
                user: 'your-email@gmail.com', // Replace with your email
                pass: 'your-app-password'     // Replace with your app password
            }
        },
        recipients: ['admin@yourdomain.com'], // Replace with admin emails
        alertThreshold: 3, // Send alert after this many attacks from same IP
        cooldownPeriod: 60 * 60 * 1000 // 1 hour between alerts for same IP
    },

    // Webhook Alerts (for Slack, Discord, etc.)
    webhookAlerts: {
        enabled: false,
        urls: [
            // 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK',
            // 'https://discord.com/api/webhooks/YOUR/DISCORD/WEBHOOK'
        ],
        alertThreshold: 5
    },

    // Attack Detection Sensitivity
    detection: {
        sensitivity: 'medium', // low, medium, high
        customPatterns: [
            // Add your custom attack patterns here
            // { name: 'Custom Pattern', pattern: /your-regex-here/i, severity: 3 }
        ]
    },

    // Geolocation
    geolocation: {
        enabled: true,
        logLocation: true,
        blockCountries: [], // ['CN', 'RU'] - ISO country codes to block
        allowCountries: []  // If specified, only these countries are allowed
    },

    // Database
    database: {
        path: './honeypot.db',
        backupInterval: 24 * 60 * 60 * 1000, // 24 hours
        maxLogAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        autoCleanup: true
    },

    // Decoy Services
    decoyServices: {
        enabled: true,
        endpoints: [
            '/admin.php',
            '/wp-admin',
            '/phpmyadmin',
            '/.env',
            '/config.php',
            '/backup.sql',
            '/database.sql',
            '/admin/login',
            '/administrator',
            '/wp-login.php'
        ]
    },

    // Logging
    logging: {
        level: 'info', // error, warn, info, debug
        logToFile: true,
        logFile: './logs/honeypot.log',
        maxFileSize: 10 * 1024 * 1024, // 10MB
        maxFiles: 5
    }
};