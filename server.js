const express = require('express');
const https = require('https');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────── WireGuard key generation ───────────────
function generateWireGuardKeys() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
    const privBytes = privateKey.export({ type: 'pkcs8', format: 'der' });
    const pubBytes  = publicKey.export({ type: 'spki',  format: 'der' });
    return {
        priv: Buffer.from(privBytes).slice(-32).toString('base64'),
        pub:  Buffer.from(pubBytes).slice(-32).toString('base64'),
    };
}

// ─────────────── Cloudflare API helper ───────────────
function cfRequest(method, path, token, body, useProxy) {
    const baseHost = useProxy
        ? 'api.zeroteam.top'
        : 'api.cloudflareclient.com';
    const basePath = useProxy ? '/warp' : '/v0i1909051800';

    return new Promise((resolve, reject) => {
        const data = body ? JSON.stringify(body) : null;
        const options = {
            hostname: baseHost,
            port: 443,
            path: `${basePath}/${path}`,
            method,
            headers: {
                'User-Agent': 'okhttp/3.12.1',
                'Content-Type': 'application/json',
                ...(token && { 'Authorization': `Bearer ${token}` }),
                ...(data && { 'Content-Length': Buffer.byteLength(data) }),
            },
        };
        const req = https.request(options, (res) => {
            let raw = '';
            res.on('data', (chunk) => { raw += chunk; });
            res.on('end', () => {
                try { resolve(JSON.parse(raw)); }
                catch (e) { resolve({ _raw: raw }); }
            });
        });
        req.on('error', reject);
        if (data) req.write(data);
        req.end();
    });
}

// ─────────────── QUIC presets ───────────────
const QUIC_PRESETS = {
    // Российские
    yandex:    '<b 0x084481800001000300000000077469636b65740677696467657409 6b696e6f706f69736b0272750000010001c00c0005000100000039001806776964676574077469636b65740679616e646578c025c0390005000100000039002b1765787465726e616c2d7469636b6574732d776964676574066166697368610679616e646578036e657400c05d000100010000001c000457fafe25>',
    vk:        '<b 0x432101000001000000000000 02766b03636f6d0000010001>',
    ok:        '<b 0x432101000001000000000000026f6b0272750000010001>',
    mail:      '<b 0x432101000001000000000000046d61696c0272750000010001>',
    gosuslugi: '<b 0x432101000001000000000000096 76f7375736c7567690272750000010001>',
    sberbank:  '<b 0x432101000001000000000000066f6e6c696e65077362657262616e6b0272750000010001>',
    // Международные
    google:    '<b 0x432101000001000000000000 06676f6f676c6503636f6d0000010001>',
    youtube:   '<b 0x432101000001000000000000 07796f757475626503636f6d0000010001>',
    apple:     '<b 0x432101000001000000000000056170706c6503636f6d0000010001>',
    microsoft: '<b 0x432101000001000000000000096d6963726f736f667403636f6d0000010001>',
    amazon:    '<b 0x432101000001000000000000 06616d617a6f6e03636f6d0000010001>',
    cloudflare:'<b 0xc000000001085adbc23f2c9b4c00002a0a0d0a0d6578616d706c652e636f6d00000f0001c00c000500010000003900180b6578616d706c652d636f6d0769642e636f6e74656e74>',
};

const QUIC_KEYS = Object.keys(QUIC_PRESETS);

// ─────────────── Randomization helpers ───────────────
function randomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generateObfsParams() {
    // S1-S4: small byte offsets
    const s1 = randomInt(10, 110);
    const s2 = randomInt(5,  55);
    const s3 = randomInt(10, 110);
    const s4 = randomInt(1,  10);

    // H1-H4: 4 non-overlapping ranges within uint32
    const max32 = 4294967295;
    const pts = Array.from({ length: 8 }, () => Math.floor(Math.random() * max32)).sort((a, b) => a - b);

    return {
        s1, s2, s3, s4,
        h1: `${pts[0]}-${pts[1]}`,
        h2: `${pts[2]}-${pts[3]}`,
        h3: `${pts[4]}-${pts[5]}`,
        h4: `${pts[6]}-${pts[7]}`,
    };
}

// ─────────────── Main API endpoint ───────────────
app.post('/api/generate', async (req, res) => {
    try {
        const {
            licenseKey  = '',
            obfsProfile = '1',   // '1' | '2' | '3'
            endpointPort = '2408',
            quicPreset  = 'random',
            useProxy    = false,
        } = req.body;

        // Jc/Jmin/Jmax profiles
        const profiles = {
            '1': { jc: 120, jmin: 23,  jmax: 911 },
            '2': { jc: 4,   jmin: 40,  jmax: 70  },
            '3': { jc: 10,  jmin: 100, jmax: 300 },
        };
        const { jc, jmin, jmax } = profiles[obfsProfile] || profiles['1'];

        // QUIC I1
        let i1 = '';
        if (quicPreset === 'none') {
            i1 = '';
        } else if (quicPreset === 'random' || !QUIC_PRESETS[quicPreset]) {
            i1 = QUIC_PRESETS[QUIC_KEYS[Math.floor(Math.random() * QUIC_KEYS.length)]];
        } else {
            i1 = QUIC_PRESETS[quicPreset];
        }

        // Randomized S/H params
        const { s1, s2, s3, s4, h1, h2, h3, h4 } = generateObfsParams();

        // Generate WireGuard keys
        const { priv, pub } = generateWireGuardKeys();

        // Register device
        const tos = new Date().toISOString();
        const regResp = await cfRequest('POST', 'reg', null, {
            install_id: '', tos, key: pub, fcm_token: '', type: 'ios', locale: 'en_US',
        }, useProxy);

        const id    = regResp?.result?.id;
        const token = regResp?.result?.token;
        if (!id || !token) {
            return res.status(502).json({ error: 'Cloudflare registration failed', details: regResp });
        }

        // Apply WARP+ key if provided
        let accountType = 'free';
        if (licenseKey.trim()) {
            const licResp = await cfRequest('PUT', `reg/${id}/account`, token, { license: licenseKey.trim() }, useProxy);
            accountType = licResp?.result?.account_type || 'free';
        }

        // Enable WARP
        const warpResp = await cfRequest('PATCH', `reg/${id}`, token, { warp_enabled: true }, useProxy);
        const peerPub  = warpResp?.result?.config?.peers?.[0]?.public_key;
        const ipv4     = warpResp?.result?.config?.interface?.addresses?.v4;
        const ipv6     = warpResp?.result?.config?.interface?.addresses?.v6;

        if (!peerPub || !ipv4) {
            return res.status(502).json({ error: 'Failed to get WARP config from Cloudflare', details: warpResp });
        }

        const ep = `162.159.192.1:${endpointPort}`;

        const config = `\
[Interface]
PrivateKey = ${priv}
Address = ${ipv4}/32, ${ipv6}/128
DNS = 1.1.1.1, 2606:4700:4700::1111, 1.0.0.1, 2606:4700:4700::1001
MTU = 1280
Jc = ${jc}
Jmin = ${jmin}
Jmax = ${jmax}
S1 = ${s1}
S2 = ${s2}
S3 = ${s3}
S4 = ${s4}
H1 = ${h1}
H2 = ${h2}
H3 = ${h3}
H4 = ${h4}
I1 = ${i1}
I2 = 
I3 = 
I4 = 
I5 = 

[Peer]
PublicKey = ${peerPub}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${ep}
PersistentKeepalive = 25
`;

        res.json({ config, accountType, endpoint: ep });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`WarpGen listening on http://localhost:${PORT}`));
