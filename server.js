const express = require('express');
const path = require('path');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

// Pinterest OAuth config
const PINTEREST_APP_ID = process.env.PINTEREST_APP_ID || '1550576';
const PINTEREST_APP_SECRET = process.env.PINTEREST_APP_SECRET;
const PINTEREST_REDIRECT_URI = process.env.REDIRECT_URI || 'https://maincoonmafia.com/auth/pinterest/callback';
const PINTEREST_SCOPES = 'boards:read,boards:write,pins:read,pins:write';

// Etsy OAuth config
const ETSY_API_KEY = process.env.ETSY_API_KEY || 'f9onc3kqhz4zns3cyt9gshz1';
const ETSY_SHARED_SECRET = process.env.ETSY_SHARED_SECRET;
const ETSY_REDIRECT_URI = process.env.ETSY_REDIRECT_URI || 'https://maincoonmafia.com/auth/etsy/callback';
const ETSY_SCOPES = 'shops_r shops_w listings_r listings_w listings_d images_r images_w';

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

// ============ PKCE Helper ============
function generatePKCE() {
    // Code verifier: 43-128 character random string
    const verifier = crypto.randomBytes(32).toString('base64url');
    // Code challenge: SHA256 hash of verifier, base64url encoded
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    return { verifier, challenge };
}

// ============ Pinterest OAuth Flow ============

app.get('/auth/pinterest', (req, res) => {
    const state = crypto.randomBytes(16).toString('hex');
    req.session.pinterest_oauth_state = state;
    
    const authUrl = `https://www.pinterest.com/oauth/?` +
        `client_id=${PINTEREST_APP_ID}` +
        `&redirect_uri=${encodeURIComponent(PINTEREST_REDIRECT_URI)}` +
        `&response_type=code` +
        `&scope=${encodeURIComponent(PINTEREST_SCOPES)}` +
        `&state=${state}`;
    
    res.redirect(authUrl);
});

app.get('/auth/pinterest/callback', async (req, res) => {
    const { code, state } = req.query;
    
    if (!code) return res.redirect('/pinterest-demo?error=no_code');
    if (state !== req.session.pinterest_oauth_state) return res.redirect('/pinterest-demo?error=state_mismatch');
    
    try {
        const basicAuth = Buffer.from(`${PINTEREST_APP_ID}:${PINTEREST_APP_SECRET}`).toString('base64');
        const tokenRes = await fetch('https://api.pinterest.com/v5/oauth/token', {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${basicAuth}`,
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                code,
                redirect_uri: PINTEREST_REDIRECT_URI,
            }),
        });
        const tokenData = await tokenRes.json();
        
        if (tokenData.access_token) {
            req.session.pinterest_token = tokenData.access_token;
            req.session.pinterest_scope = tokenData.scope;
            res.redirect('/pinterest-demo?success=1');
        } else {
            console.error('Pinterest token exchange failed:', tokenData);
            res.redirect('/pinterest-demo?error=token_failed');
        }
    } catch (err) {
        console.error('Pinterest OAuth error:', err);
        res.redirect('/pinterest-demo?error=exception');
    }
});

// Pinterest API endpoints
app.get('/api/pinterest/boards', async (req, res) => {
    if (!req.session.pinterest_token) return res.status(401).json({ error: 'Not authenticated' });
    try {
        const resp = await fetch('https://api.pinterest.com/v5/boards', {
            headers: { 'Authorization': `Bearer ${req.session.pinterest_token}` }
        });
        res.json(await resp.json());
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/pinterest/pins', async (req, res) => {
    if (!req.session.pinterest_token) return res.status(401).json({ error: 'Not authenticated' });
    const { board_id, title, description, link, image_url } = req.body;
    try {
        const resp = await fetch('https://api.pinterest.com/v5/pins', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${req.session.pinterest_token}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                board_id, title, description, link,
                media_source: { source_type: 'image_url', url: image_url },
            }),
        });
        res.json(await resp.json());
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/pinterest/status', (req, res) => {
    res.json({ authenticated: !!req.session.pinterest_token, scope: req.session.pinterest_scope || null });
});

app.post('/api/pinterest/disconnect', (req, res) => {
    delete req.session.pinterest_token;
    delete req.session.pinterest_scope;
    res.json({ ok: true });
});

// ============ Etsy OAuth Flow (with PKCE) ============

app.get('/auth/etsy', (req, res) => {
    const state = crypto.randomBytes(16).toString('hex');
    const pkce = generatePKCE();
    
    req.session.etsy_oauth_state = state;
    req.session.etsy_code_verifier = pkce.verifier;
    
    const authUrl = `https://www.etsy.com/oauth/connect?` +
        `response_type=code` +
        `&client_id=${ETSY_API_KEY}` +
        `&redirect_uri=${encodeURIComponent(ETSY_REDIRECT_URI)}` +
        `&scope=${encodeURIComponent(ETSY_SCOPES)}` +
        `&state=${state}` +
        `&code_challenge=${pkce.challenge}` +
        `&code_challenge_method=S256`;
    
    res.redirect(authUrl);
});

app.get('/auth/etsy/callback', async (req, res) => {
    const { code, state, error } = req.query;
    
    if (error) return res.redirect(`/etsy-demo?error=${error}`);
    if (!code) return res.redirect('/etsy-demo?error=no_code');
    if (state !== req.session.etsy_oauth_state) return res.redirect('/etsy-demo?error=state_mismatch');
    
    try {
        // Exchange authorization code for access token (with PKCE verifier)
        const tokenRes = await fetch('https://api.etsy.com/v3/public/oauth/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: ETSY_API_KEY,
                redirect_uri: ETSY_REDIRECT_URI,
                code,
                code_verifier: req.session.etsy_code_verifier,
            }),
        });
        const tokenData = await tokenRes.json();
        
        if (tokenData.access_token) {
            req.session.etsy_token = tokenData.access_token;
            req.session.etsy_refresh_token = tokenData.refresh_token;
            req.session.etsy_token_expires = Date.now() + (tokenData.expires_in * 1000);
            res.redirect('/etsy-demo?success=1');
        } else {
            console.error('Etsy token exchange failed:', tokenData);
            res.redirect(`/etsy-demo?error=token_failed&detail=${encodeURIComponent(JSON.stringify(tokenData))}`);
        }
    } catch (err) {
        console.error('Etsy OAuth error:', err);
        res.redirect('/etsy-demo?error=exception');
    }
});

// Etsy API endpoints
app.get('/api/etsy/status', (req, res) => {
    res.json({
        authenticated: !!req.session.etsy_token,
        expires_in: req.session.etsy_token_expires ? Math.max(0, Math.round((req.session.etsy_token_expires - Date.now()) / 1000)) : null,
    });
});

// Get shop info (uses the user's token to find their shop)
app.get('/api/etsy/me', async (req, res) => {
    if (!req.session.etsy_token) return res.status(401).json({ error: 'Not authenticated' });
    try {
        // First get user info
        const userResp = await fetch('https://openapi.etsy.com/v3/application/users/me', {
            headers: {
                'Authorization': `Bearer ${req.session.etsy_token}`,
                'x-api-key': ETSY_API_KEY,
            }
        });
        const userData = await userResp.json();
        
        if (userData.user_id) {
            // Then get their shop
            const shopResp = await fetch(`https://openapi.etsy.com/v3/application/users/${userData.user_id}/shops`, {
                headers: {
                    'Authorization': `Bearer ${req.session.etsy_token}`,
                    'x-api-key': ETSY_API_KEY,
                }
            });
            const shopData = await shopResp.json();
            res.json({ user: userData, shop: shopData });
        } else {
            res.json({ user: userData, shop: null });
        }
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Get shop listings
app.get('/api/etsy/listings', async (req, res) => {
    if (!req.session.etsy_token) return res.status(401).json({ error: 'Not authenticated' });
    const shopId = req.query.shop_id;
    if (!shopId) return res.status(400).json({ error: 'shop_id required' });
    
    try {
        const resp = await fetch(`https://openapi.etsy.com/v3/application/shops/${shopId}/listings?limit=10&state=active`, {
            headers: {
                'Authorization': `Bearer ${req.session.etsy_token}`,
                'x-api-key': ETSY_API_KEY,
            }
        });
        res.json(await resp.json());
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Upload listing image
app.post('/api/etsy/listings/:listingId/images', async (req, res) => {
    if (!req.session.etsy_token) return res.status(401).json({ error: 'Not authenticated' });
    const { listingId } = req.params;
    const { image_url } = req.body;
    
    try {
        // Fetch the image first
        const imgResp = await fetch(image_url);
        const imgBuffer = Buffer.from(await imgResp.arrayBuffer());
        
        // Create multipart form data manually
        const boundary = crypto.randomBytes(16).toString('hex');
        const body = Buffer.concat([
            Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="image"; filename="mockup.jpg"\r\nContent-Type: image/jpeg\r\n\r\n`),
            imgBuffer,
            Buffer.from(`\r\n--${boundary}--\r\n`),
        ]);
        
        const resp = await fetch(`https://openapi.etsy.com/v3/application/shops/${req.query.shop_id}/listings/${listingId}/images`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${req.session.etsy_token}`,
                'x-api-key': ETSY_API_KEY,
                'Content-Type': `multipart/form-data; boundary=${boundary}`,
            },
            body,
        });
        res.json(await resp.json());
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/etsy/disconnect', (req, res) => {
    delete req.session.etsy_token;
    delete req.session.etsy_refresh_token;
    delete req.session.etsy_token_expires;
    res.json({ ok: true });
});

// ============ Review System ============

// In-memory review store (keyed by batch ID)
const reviewBatches = {};

// Create a new review batch (called by automation scripts)
app.post('/api/review/batch', express.json(), (req, res) => {
    const { pin, images, batchName } = req.body;
    if (!pin || !images || !Array.isArray(images)) {
        return res.status(400).json({ error: 'pin and images[] required' });
    }
    const batchId = require('crypto').randomBytes(5).toString('hex');
    reviewBatches[batchId] = {
        pin,
        batchName: batchName || 'Mockup Review',
        images: images.map((img, i) => ({
            id: i,
            url: img.url,
            label: img.label || `Image ${i + 1}`,
            design: img.design || '',
            style: img.style || '',
            status: 'pending' // pending | approved | rejected
        })),
        createdAt: new Date().toISOString(),
        completedAt: null
    };
    res.json({ batchId, reviewUrl: `/review/${batchId}`, pinRequired: true });
});

// Get batch data (PIN required via query param)
app.get('/api/review/:batchId', (req, res) => {
    const batch = reviewBatches[req.params.batchId];
    if (!batch) return res.status(404).json({ error: 'Batch not found' });
    if (req.query.pin !== batch.pin) return res.status(401).json({ error: 'Invalid PIN' });
    res.json({
        batchName: batch.batchName,
        images: batch.images,
        createdAt: batch.createdAt,
        completedAt: batch.completedAt
    });
});

// Submit decisions
app.post('/api/review/:batchId/submit', express.json(), (req, res) => {
    const batch = reviewBatches[req.params.batchId];
    if (!batch) return res.status(404).json({ error: 'Batch not found' });
    if (req.body.pin !== batch.pin) return res.status(401).json({ error: 'Invalid PIN' });
    
    const { decisions } = req.body; // { "0": "approved", "1": "rejected", ... }
    if (!decisions) return res.status(400).json({ error: 'decisions required' });
    
    for (const [id, status] of Object.entries(decisions)) {
        const img = batch.images[parseInt(id)];
        if (img && (status === 'approved' || status === 'rejected')) {
            img.status = status;
        }
    }
    
    const allDecided = batch.images.every(img => img.status !== 'pending');
    if (allDecided) batch.completedAt = new Date().toISOString();
    
    const approved = batch.images.filter(i => i.status === 'approved').length;
    const rejected = batch.images.filter(i => i.status === 'rejected').length;
    const pending = batch.images.filter(i => i.status === 'pending').length;
    
    res.json({ approved, rejected, pending, complete: allDecided });
});

// Get results (for automation to poll)
app.get('/api/review/:batchId/results', (req, res) => {
    const batch = reviewBatches[req.params.batchId];
    if (!batch) return res.status(404).json({ error: 'Batch not found' });
    // No PIN needed for results — only returns status, not image URLs
    res.json({
        complete: batch.completedAt !== null,
        approved: batch.images.filter(i => i.status === 'approved').map(i => ({ id: i.id, label: i.label, design: i.design, style: i.style, url: i.url })),
        rejected: batch.images.filter(i => i.status === 'rejected').map(i => ({ id: i.id, label: i.label, design: i.design, style: i.style })),
        pending: batch.images.filter(i => i.status === 'pending').length
    });
});

// Review page
app.get('/review/:batchId', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'review.html'));
});

// ============ Pages ============

app.get('/privacy', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'privacy.html'));
});

app.get('/pinterest-demo', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'pinterest-demo.html'));
});

app.get('/etsy-demo', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'etsy-demo.html'));
});

// Serve massage demo static assets from /massage-demo/assets/*
app.use('/massage-demo/assets', express.static(path.join(__dirname, 'massage-demo')));

// Massage therapy demo routes
app.get('/massage-demo', (req, res) => {
    res.sendFile(path.join(__dirname, 'massage-demo', 'index.html'));
});

app.get('/massage-demo/', (req, res) => {
    res.sendFile(path.join(__dirname, 'massage-demo', 'index.html'));
});

// Mobile-optimized version with inline styles
app.get('/massage-demo/mobile', (req, res) => {
    res.sendFile(path.join(__dirname, 'massage-demo', 'mobile.html'));
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Maine Coon Mafia server running on port ${PORT}`));
