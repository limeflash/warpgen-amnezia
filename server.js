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
    const pubBytes = publicKey.export({ type: 'spki', format: 'der' });
    return {
        priv: Buffer.from(privBytes).slice(-32).toString('base64'),
        pub: Buffer.from(pubBytes).slice(-32).toString('base64'),
    };
}

// ─────────────── Cloudflare API helper ───────────────
function cfRequest(method, urlPath, token, body, useProxy) {
    const baseHost = useProxy ? 'api.zeroteam.top' : 'api.cloudflareclient.com';
    const basePath = useProxy ? '/warp' : '/v0i1909051800';

    return new Promise((resolve, reject) => {
        const data = body ? JSON.stringify(body) : null;
        const options = {
            hostname: baseHost,
            port: 443,
            path: `${basePath}/${urlPath}`,
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

// ─────────────── QUIC I1 presets — NO spaces in hex! ───────────────
// Header for DNS queries: TxID(2b) + Flags 0100 + QDCOUNT 0001 + 0(6b) = 432101000001000000000000
const QUIC_PRESETS = {
    // Verified from a known-working config (exact capture)
    yandex: '<b 0x084481800001000300000000077469636b65747306776964676574096b696e6f706f69736b0272750000010001c00c0005000100000039001806776964676574077469636b6574730679616e646578c025c0390005000100000039002b1765787465726e616c2d7469636b6574732d776964676574066166697368610679616e646578036e657400c05d000100010000001c000457fafe25>',
    // Clean DNS A-query packets for various domains
    vk: '<b 0x43210100000100000000000002766b03636f6d0000010001>',
    ok: '<b 0x432101000001000000000000026f6b0272750000010001>',
    mail: '<b 0x432101000001000000000000046d61696c0272750000010001>',
    gosuslugi: '<b 0x43210100000100000000000009676f7375736c7567690272750000010001>',
    sberbank: '<b 0x4321010000010000000000000873626572 62616e6b0272750000010001>',
    google: '<b 0x43210100000100000000000006676f6f676c6503636f6d0000010001>',
    youtube: '<b 0x43210100000100000000000007796f757475626503636f6d0000010001>',
    apple: '<b 0x432101000001000000000000056170706c6503636f6d0000010001>',
    microsoft: '<b 0x432101000001000000000000096d6963726f736f667403636f6d0000010001>',
    amazon: '<b 0x43210100000100000000000006616d617a6f6e03636f6d0000010001>',
};

const QUIC_KEYS = Object.keys(QUIC_PRESETS);

// ─────────────── Main API endpoint ───────────────
app.post('/api/generate', async (req, res) => {
    try {
        const {
            licenseKey = '',
            obfsProfile = '1',
            endpointPort = '2408',
            quicPreset = 'random',
            useProxy = false,
        } = req.body;

        // Jc/Jmin/Jmax (default = profile 1 = stable for WARP)
        const profiles = {
            '1': { jc: 4, jmin: 40, jmax: 70 },  // proven stable
            '2': { jc: 120, jmin: 23, jmax: 911 },
            '3': { jc: 10, jmin: 100, jmax: 300 },
        };
        const { jc, jmin, jmax } = profiles[obfsProfile] || profiles['1'];

        // QUIC I1
        let i1 = (quicPreset === 'none') ? ''
            : (QUIC_PRESETS[quicPreset] ?? QUIC_PRESETS[QUIC_KEYS[Math.floor(Math.random() * QUIC_KEYS.length)]]);

        // Generate WireGuard keys
        const { priv, pub } = generateWireGuardKeys();

        // Register device
        const tos = new Date().toISOString();
        const regResp = await cfRequest('POST', 'reg', null, {
            install_id: '', tos, key: pub, fcm_token: '', type: 'ios', locale: 'en_US',
        }, useProxy);

        const id = regResp?.result?.id;
        const token = regResp?.result?.token;
        if (!id || !token) {
            return res.status(502).json({ error: 'Cloudflare registration failed', details: regResp });
        }

        // Apply WARP+ key
        let accountType = 'free';
        if (licenseKey.trim()) {
            const licResp = await cfRequest('PUT', `reg/${id}/account`, token, { license: licenseKey.trim() }, useProxy);
            accountType = licResp?.result?.account_type || 'free';
        }

        // Enable WARP
        const warpResp = await cfRequest('PATCH', `reg/${id}`, token, { warp_enabled: true }, useProxy);
        const peerPub = warpResp?.result?.config?.peers?.[0]?.public_key;
        const ipv4 = warpResp?.result?.config?.interface?.addresses?.v4;
        const ipv6 = warpResp?.result?.config?.interface?.addresses?.v6;
        // Use API-returned host, strip port, fallback to known anycast
        const apiEpHost = (warpResp?.result?.config?.peers?.[0]?.endpoint?.host || '').split(':')[0] || '162.159.192.1';

        if (!peerPub || !ipv4) {
            return res.status(502).json({ error: 'Failed to get WARP config from Cloudflare', details: warpResp });
        }

        const ep = `${apiEpHost}:${endpointPort}`;

        // H1-H4 = 1,2,3,4 — REQUIRED for standard WireGuard WARP server.
        // Range format (e.g. "748507351-1332761127") is for selfhosted AmneziaWG only.
        // S1=S2=0 — proven working default for WARP.
        const lines = [
            '[Interface]',
            `PrivateKey = ${priv}`,
            `Address = ${ipv4}/32, ${ipv6}/128`,
            'DNS = 1.1.1.1, 2606:4700:4700::1111, 1.0.0.1, 2606:4700:4700::1001',
            'MTU = 1280',
            `Jc = ${jc}`,
            `Jmin = ${jmin}`,
            `Jmax = ${jmax}`,
            'S1 = 0',
            'S2 = 0',
            'H1 = 1',
            'H2 = 2',
            'H3 = 3',
            'H4 = 4',
            ...(i1 ? [`I1 = ${i1}`] : []),
            '',
            '[Peer]',
            `PublicKey = ${peerPub}`,
            'AllowedIPs = 0.0.0.0/0, ::/0',
            `Endpoint = ${ep}`,
            'PersistentKeepalive = 25',
        ];

        const config = lines.join('\n');
        res.json({ config, accountType, endpoint: ep });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`WarpGen listening on http://localhost:${PORT}`));
