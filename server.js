const express = require('express');
const path = require('path');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

// Pinterest OAuth config
const PINTEREST_APP_ID = process.env.PINTEREST_APP_ID || '1550576';
const PINTEREST_APP_SECRET = process.env.PINTEREST_APP_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI || 'https://maincoonmafia.com/auth/pinterest/callback';
const SCOPES = 'boards:read,boards:write,pins:read,pins:write';

// In-memory session store (good enough for demo)
const sessions = {};

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Simple session middleware
app.use((req, res, next) => {
    let sid = req.headers.cookie?.match(/sid=([^;]+)/)?.[1];
    if (!sid || !sessions[sid]) {
        sid = crypto.randomBytes(16).toString('hex');
        sessions[sid] = {};
        res.setHeader('Set-Cookie', `sid=${sid}; Path=/; HttpOnly; SameSite=Lax`);
    }
    req.session = sessions[sid];
    next();
});

// ============ Pinterest OAuth Flow ============

// Step 1: Initiate OAuth - redirect to Pinterest
app.get('/auth/pinterest', (req, res) => {
    const state = crypto.randomBytes(16).toString('hex');
    req.session.oauth_state = state;
    
    const authUrl = `https://www.pinterest.com/oauth/?` +
        `client_id=${PINTEREST_APP_ID}` +
        `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
        `&response_type=code` +
        `&scope=${encodeURIComponent(SCOPES)}` +
        `&state=${state}`;
    
    res.redirect(authUrl);
});

// Step 2: OAuth callback - exchange code for token
app.get('/auth/pinterest/callback', async (req, res) => {
    const { code, state } = req.query;
    
    if (!code) {
        return res.redirect('/pinterest-demo?error=no_code');
    }
    
    // Verify state
    if (state !== req.session.oauth_state) {
        return res.redirect('/pinterest-demo?error=state_mismatch');
    }
    
    try {
        // Exchange code for access token
        const basicAuth = Buffer.from(`${PINTEREST_APP_ID}:${PINTEREST_APP_SECRET}`).toString('base64');
        
        const tokenRes = await fetch('https://api.pinterest.com/v5/oauth/token', {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${basicAuth}`,
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: REDIRECT_URI,
            }),
        });
        
        const tokenData = await tokenRes.json();
        
        if (tokenData.access_token) {
            req.session.pinterest_token = tokenData.access_token;
            req.session.token_type = tokenData.token_type;
            req.session.scope = tokenData.scope;
            res.redirect('/pinterest-demo?success=1');
        } else {
            console.error('Token exchange failed:', tokenData);
            res.redirect('/pinterest-demo?error=token_failed');
        }
    } catch (err) {
        console.error('OAuth error:', err);
        res.redirect('/pinterest-demo?error=exception');
    }
});

// ============ Pinterest API Endpoints ============

// Get user's boards
app.get('/api/pinterest/boards', async (req, res) => {
    if (!req.session.pinterest_token) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    try {
        // Use sandbox API for trial access
        const resp = await fetch('https://api-sandbox.pinterest.com/v5/boards', {
            headers: { 'Authorization': `Bearer ${req.session.pinterest_token}` }
        });
        const data = await resp.json();
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Create a pin
app.post('/api/pinterest/pins', async (req, res) => {
    if (!req.session.pinterest_token) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const { board_id, title, description, link, image_url } = req.body;
    
    try {
        // Use sandbox API for trial access (switch to production after Standard approval)
        const resp = await fetch('https://api-sandbox.pinterest.com/v5/pins', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${req.session.pinterest_token}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                board_id,
                title,
                description,
                link,
                media_source: {
                    source_type: 'image_url',
                    url: image_url,
                },
            }),
        });
        const data = await resp.json();
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Check auth status
app.get('/api/pinterest/status', (req, res) => {
    res.json({ 
        authenticated: !!req.session.pinterest_token,
        scope: req.session.scope || null
    });
});

// Disconnect
app.post('/api/pinterest/disconnect', (req, res) => {
    delete req.session.pinterest_token;
    delete req.session.scope;
    res.json({ ok: true });
});

// ============ Pages ============

app.get('/privacy', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'privacy.html'));
});

app.get('/pinterest-demo', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'pinterest-demo.html'));
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Maine Coon Mafia server running on port ${PORT}`));
