// AI-Enhanced Honeypot Demo
const express = require('express');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// AI-Powered Threat Analysis (Free)
async function aiThreatAnalysis(payload) {
    try {
        const response = await fetch('https://api-inference.huggingface.co/models/cardiffnlp/twitter-roberta-base-sentiment-latest', {
            method: 'POST',
            headers: {
                'Authorization': 'Bearer hf_demo',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ inputs: payload })
        });
        
        const result = await response.json();
        const sentiment = result[0]?.label || 'NEUTRAL';
        const confidence = result[0]?.score || 0.5;
        
        return {
            ai_analysis: sentiment,
            ai_confidence: Math.round(confidence * 100),
            ai_threat_level: sentiment === 'NEGATIVE' ? 'HIGH' : 'MEDIUM'
        };
    } catch (error) {
        // Fallback simulation
        const threats = ['union', 'select', 'script', '../', 'admin'];
        const detected = threats.filter(t => payload.toLowerCase().includes(t));
        
        return {
            ai_analysis: detected.length > 0 ? 'MALICIOUS' : 'BENIGN',
            ai_confidence: detected.length > 0 ? 85 : 60,
            ai_threat_level: detected.length > 1 ? 'HIGH' : 'MEDIUM'
        };
    }
}

app.get('/', (req, res) => {
    res.send(`
    <h1>🤖 AI-Powered Honeypot Demo</h1>
    <form method="post" action="/test-ai">
        <input type="text" name="payload" placeholder="Enter test payload" style="padding: 10px; width: 300px;">
        <button type="submit" style="padding: 10px;">Analyze with AI</button>
    </form>
    `);
});

app.post('/test-ai', async (req, res) => {
    const payload = req.body.payload || '';
    const aiResult = await aiThreatAnalysis(payload);
    
    res.json({
        input: payload,
        ai_analysis: aiResult
    });
});

app.listen(3001, () => {
    console.log('🤖 AI Demo running on http://localhost:3001');
});