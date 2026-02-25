const express = require('express');
const https = require('https');
const dns = require('dns').promises;
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

// ─────────────── QUIC Initial Packet generator ───────────────
// Generates a structurally valid QUIC v1 Initial Packet (RFC 9000)
// with a TLS 1.3 ClientHello + SNI for the given hostname.
// DPI classifies this as QUIC traffic, not WireGuard.
function encodeQUICVarInt(n) {
    if (n < 64) return Buffer.from([n]);
    if (n < 16384) return Buffer.from([(0x40 | (n >> 8)) & 0xff, n & 0xff]);
    if (n < 1073741824) {
        return Buffer.from([
            (0x80 | (n >> 24)) & 0xff,
            (n >> 16) & 0xff,
            (n >> 8) & 0xff,
            n & 0xff,
        ]);
    }
    throw new Error('VarInt too large');
}

function prependLen16(buf) {
    return Buffer.concat([Buffer.from([(buf.length >> 8) & 0xff, buf.length & 0xff]), buf]);
}

// ─────────────── DNS Response builder ───────────────
// RFC 1035 — mimics a real DNS response (like the Yandex/Kinopoisk capture).
// QR=1 (response), RA=1 — looks like a reply from a DNS server.
// DPI sees normal DNS response traffic.
function buildDNSResponse(domain) {
    const txId = crypto.randomBytes(2);
    // Flags: QR=1 Response, Opcode=0, AA=0, TC=0, RD=1, RA=1, RCODE=0
    const flags = Buffer.from([0x81, 0x80]);
    const qdcount = Buffer.from([0x00, 0x01]); // 1 question
    const ancount = Buffer.from([0x00, 0x01]); // 1 answer
    const nscount = Buffer.from([0x00, 0x00]);
    const arcount = Buffer.from([0x00, 0x00]);

    // Question: encode domain name
    const labels = domain.split('.');
    const nameParts = labels.map(l => Buffer.concat([Buffer.from([l.length]), Buffer.from(l, 'ascii')]));
    const qname = Buffer.concat([...nameParts, Buffer.from([0x00])]);
    const question = Buffer.concat([qname, Buffer.from([0x00, 0x01, 0x00, 0x01])]); // type A, class IN

    // Answer: CNAME pointer back to name, then fake A record IP
    const fakeIp = crypto.randomBytes(4); // random plausible IP
    const answer = Buffer.concat([
        Buffer.from([0xc0, 0x0c]),          // pointer to question name
        Buffer.from([0x00, 0x01]),          // type A
        Buffer.from([0x00, 0x01]),          // class IN
        Buffer.from([0x00, 0x00, 0x00, 0x3c]), // TTL 60s
        Buffer.from([0x00, 0x04]),          // rdlength 4
        fakeIp,
    ]);

    const pkt = Buffer.concat([txId, flags, qdcount, ancount, nscount, arcount, question, answer]);
    return `<b 0x${pkt.toString('hex')}>`;
}

// ─────────────── STUN Binding Request ───────────────
// RFC 5389 — looks like WebRTC / VoIP traffic to DPI.
function buildSTUNRequest() {
    const magicCookie = Buffer.from([0x21, 0x12, 0xa4, 0x42]);
    const txId = crypto.randomBytes(12);
    const msgType = Buffer.from([0x00, 0x01]); // Binding Request
    const msgLength = Buffer.from([0x00, 0x00]); // no attributes
    return `<b 0x${Buffer.concat([msgType, msgLength, magicCookie, txId]).toString('hex')}>`;
}

// ─────────────── NTP Request ───────────────
// RFC 5905 — looks like routine clock sync traffic, never blocked.
function buildNTPRequest() {
    const pkt = Buffer.alloc(48, 0);
    pkt[0] = 0x1b; // LI=0, VN=3, Mode=3 (client)
    // Reference timestamp — random-ish to avoid fingerprinting
    crypto.randomBytes(8).copy(pkt, 24);
    return `<b 0x${pkt.toString('hex')}>`;
}

// ─────────────── DTLS 1.2 ClientHello ───────────────
// RFC 6347 — datagram TLS used by WebRTC, DTLS-SRTP, etc.
// DPI sees a normal DTLS handshake initiation.
function buildDTLS12Hello() {
    const random = crypto.randomBytes(32);
    const sessionId = Buffer.from([0x00]); // empty
    const cookie = Buffer.from([0x00]);    // empty (first flight)
    const cipherSuites = prependLen16(Buffer.from([
        0xc0, 0x2b, // ECDHE-ECDSA-AES128-GCM-SHA256
        0xc0, 0x2f, // ECDHE-RSA-AES128-GCM-SHA256
        0xc0, 0x0a, // ECDHE-ECDSA-AES256-SHA
        0xc0, 0x14, // ECDHE-RSA-AES256-SHA
        0x00, 0xff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    ]));
    const compression = Buffer.from([0x01, 0x00]); // null
    const helloBody = Buffer.concat([
        Buffer.from([0xfe, 0xfd]),  // client version: DTLS 1.2
        random,
        sessionId,
        cookie,
        cipherSuites,
        compression,
    ]);
    const msgSeq = Buffer.from([0x00, 0x00]);
    const fragOffset = Buffer.from([0x00, 0x00, 0x00]);
    const len3 = Buffer.from([
        (helloBody.length >> 16) & 0xff,
        (helloBody.length >> 8) & 0xff,
        helloBody.length & 0xff,
    ]);
    // DTLS Handshake header: type=0x01, length, msg_seq, frag_offset, frag_length
    const handshake = Buffer.concat([
        Buffer.from([0x01]), len3, msgSeq, fragOffset, len3, helloBody,
    ]);
    // DTLS Record: ContentType=22 (Handshake), Version=FE FD, Epoch=0, Seq=0
    const record = Buffer.concat([
        Buffer.from([0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        prependLen16(handshake),
    ]);
    return `<b 0x${record.toString('hex')}>`;
}

function buildTLSClientHello(sni) {
    const random = crypto.randomBytes(32);
    const sessionId = crypto.randomBytes(32);

    const cipherSuites = prependLen16(Buffer.from([
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x13, 0x02, // TLS_AES_256_GCM_SHA384
        0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
        0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30,
        0xc0, 0x09, 0xc0, 0x13, 0xc0, 0x0a, 0xc0, 0x14,
        0x00, 0x9c, 0x00, 0xff,
    ]));

    // SNI extension  type=0x0000
    const sniBytes = Buffer.from(sni, 'ascii');
    const sniEntry = Buffer.concat([Buffer.from([0x00]), prependLen16(sniBytes)]);
    const sniList = prependLen16(sniEntry);
    const sniExt = Buffer.concat([Buffer.from([0x00, 0x00]), prependLen16(sniList)]);

    // Supported groups  type=0x000a
    const groupsExt = Buffer.concat([
        Buffer.from([0x00, 0x0a]),
        prependLen16(prependLen16(Buffer.from([0x00, 0x1d, 0x00, 0x17, 0x00, 0x18]))),
    ]);

    // Supported versions  type=0x002b
    const versionsExt = Buffer.concat([
        Buffer.from([0x00, 0x2b]),
        prependLen16(Buffer.from([0x04, 0x03, 0x04, 0x03, 0x03])),
    ]);

    // Key share  type=0x0033
    const pubKey = crypto.randomBytes(32);
    const ksEntry = Buffer.concat([Buffer.from([0x00, 0x1d]), prependLen16(pubKey)]);
    const keyShareExt = Buffer.concat([
        Buffer.from([0x00, 0x33]),
        prependLen16(prependLen16(ksEntry)),
    ]);

    // QUIC transport params  type=0xffa5
    const quicParamsExt = Buffer.concat([
        Buffer.from([0xff, 0xa5]),
        prependLen16(Buffer.alloc(0)),
    ]);

    const extensions = Buffer.concat([sniExt, groupsExt, versionsExt, keyShareExt, quicParamsExt]);

    const clientHelloBody = Buffer.concat([
        Buffer.from([0x03, 0x03]),          // legacy version
        random,
        Buffer.from([sessionId.length]),
        sessionId,
        cipherSuites,
        Buffer.from([0x01, 0x00]),          // compression: null only
        prependLen16(extensions),
    ]);

    // Handshake type 0x01 = ClientHello
    const len3 = Buffer.from([
        (clientHelloBody.length >> 16) & 0xff,
        (clientHelloBody.length >> 8) & 0xff,
        clientHelloBody.length & 0xff,
    ]);
    return Buffer.concat([Buffer.from([0x01]), len3, clientHelloBody]);
}


function buildQUICInitialPacket(sni) {
    const dcid = crypto.randomBytes(8);
    const scid = crypto.randomBytes(8);
    const clientHello = buildTLSClientHello(sni);

    // QUIC CRYPTO frame: type=0x06, offset=0, data=clientHello
    const cryptoFrame = Buffer.concat([
        Buffer.from([0x06]),
        encodeQUICVarInt(0),                   // offset
        encodeQUICVarInt(clientHello.length),   // length
        clientHello,
    ]);

    // No artificial zero-padding — compact packet only contains real QUIC/TLS data.
    // Padding with zeros was causing DPI to flag the packets as synthetic.
    const payload = cryptoFrame;
    const pktNum = Buffer.from([0x00]);       // 1-byte packet number (more common)
    const lengthField = encodeQUICVarInt(pktNum.length + payload.length);

    const packet = Buffer.concat([
        Buffer.from([0xC0]),                    // Long header | Initial | 1-byte pkt num
        Buffer.from([0x00, 0x00, 0x00, 0x01]), // QUIC v1
        Buffer.from([dcid.length]), dcid,
        Buffer.from([scid.length]), scid,
        Buffer.from([0x00]),                    // Token length = 0
        lengthField,
        pktNum,
        payload,
    ]);

    return `<b 0x${packet.toString('hex')}>`;
}

// Pre-generate I1 packets at startup (fresh random IDs each run)
const QUIC_PRESETS = {
    // Verified real captured QUIC Initial Packet (from warpgen.net)
    warpgen: '<b 0xc2000000011419fa4bb3599f336777de79f81ca9a8d80d91eeec000044c635cef024a885dcb66d1420a91a8c427e87d6cf8e08b563932f449412cddf77d3e2594ea1c7a183c238a89e9adb7ffa57c133e55c59bec101634db90afb83f75b19fe703179e26a31902324c73f82d9354e1ed8da39af610afcb27e6590a44341a0828e5a3d2f0e0f7b0945d7bf3402feea0ee6332e19bdf48ffc387a97227aa97b205a485d282cd66d1c384bafd63dc42f822c4df2109db5b5646c458236ddcc01ae1c493482128bc0830c9e1233f0027a0d262f92b49d9d8abd9a9e0341f6e1214761043c021d7aa8c464b9d865f5fbe234e49626e00712031703a3e23ef82975f014ee1e1dc428521dc23ce7c6c13663b19906240b3efe403cf30559d798871557e4e60e86c29ea4504ed4d9bb8b549d0e8acd6c334c39bb8fb42ede68fb2aadf00cfc8bcc12df03602bbd4fe701d64a39f7ced112951a83b1dbbe6cd696dd3f15985c1b9fef72fa8d0319708b633cc4681910843ce753fac596ed9945d8b839aeff8d3bf0449197bd0bb22ab8efd5d63eb4a95db8d3ffc796ed5bcf2f4a136a8a36c7a0c65270d511aebac733e61d414050088a1c3d868fb52bc7e57d3d9fd132d78b740a6ecdc6c24936e92c28672dbe00928d89b891865f885aeb4c4996d50c2bbbb7a99ab5de02ac89b3308e57bcecf13f2da0333d1420e18b66b4c23d625d836b538fc0c221d6bd7f566a31fa292b85be96041d8e0bfe655d5dc1afed23eb8f2b3446561bbee7644325cc98d31cea38b865bdcc507e48c6ebdc7553be7bd6ab963d5a14615c4b81da7081c127c791224853e2d19bafdc0d9f3f3a6de898d14abb0e2bc849917e0a599ed4a541268ad0e60ea4d147dc33d17fa82f22aa505ccb53803a31d10a7ca2fea0b290a52ee92c7bf4aab7cea4e3c07b1989364eed87a3c6ba65188cd349d37ce4eefde9ec43bab4b4dc79e03469c2ad6b902e28e0bbbbf696781ad4edf424ffb35ce0236d373629008f142d04b5e08a124237e03e3149f4cdde92d7fae581a1ac332e26b2c9c1a6bdec5b3a9c7a2a870f7a0c25fc6ce245e029b686e346c6d862ad8df6d9b62474fbc31dbb914711f78074d4441f4e6e9edca3c52315a5c0653856e23f681558d669f4a4e6915bcf42b56ce36cb7dd3983b0b1d6fdf0f8efddb68e7ca0ae9dd4570fe6978fbb524109f6ec957ca61f1767ef74eb803b0f16abd0087cf2d01bc1db1c01d97ac81b3196c934586963fe7cf2d310e0739621e8bd00dc23fded18576d8c8f285d7bb5f43b547af3c76235de8b6f757f817683b2151600b11721219212bf27558edd439e73fce951f61d582320e5f4d6c315c71129b719277fc144bbe8ded25ab6d29b6e189c9bd9b16538faf60cc2aab3c3bb81fc2213657f2dd0ceb9b3b871e1423d8d3e8cc008721ef03b28e0ee7bb66b8f2a2ac01ef88df1f21ed49bf1ce435df31ac34485936172567488812429c269b49ee9e3d99652b51a7a614b7c460bf0d2d64d8349ded7345bedab1ea0a766a8470b1242f38d09f7855a32db39516c2bd4bcc538c52fa3a90c8714d4b006a15d9c7a7d04919a1cab48da7cce0d5de1f9e5f8936cffe469132991c6eb84c5191d1bcf69f70c58d9a7b66846440a9f0eef25ee6ab62715b50ca7bef0bc3013d4b62e1639b5028bdf757454356e9326a4c76dabfb497d451a3a1d2dbd46ec283d255799f72dfe878ae25892e25a2542d3ca9018394d8ca35b53ccd94947a8>',
    // Verified real captured DNS/QUIC packet (Yandex/Kinopoisk)
    yandex: '<b 0x084481800001000300000000077469636b65747306776964676574096b696e6f706f69736b0272750000010001c00c0005000100000039001806776964676574077469636b6574730679616e646578c025c0390005000100000039002b1765787465726e616c2d7469636b6574732d776964676574066166697368610679616e646578036e657400c05d000100010000001c000457fafe25>',
    // Verified real captured DNS packet (web.max.ru)
    dns_web_max_ru: '<b 0xce40f5295b5ae03f49dff318080045000068000040004011b65cc0a80101c0a801d700350a700054ca21645f8180000100030000000003776562036d61780272750000010001c00c00010001000000a300049bd4cc8fc00c00010001000000a300049bd4cc4ec00c00010001000000a300049bd4ccc1>',
    // Generated QUIC v1 Initial Packets with correct TLS ClientHello + SNI
    // Russian services
    vk: buildQUICInitialPacket('vk.com'),
    ok: buildQUICInitialPacket('ok.ru'),
    mail: buildQUICInitialPacket('mail.ru'),
    gosuslugi: buildQUICInitialPacket('gosuslugi.ru'),
    sberbank: buildQUICInitialPacket('online.sberbank.ru'),
    ya: buildQUICInitialPacket('ya.ru'),
    dzen: buildQUICInitialPacket('dzen.ru'),
    rutube: buildQUICInitialPacket('rutube.ru'),
    ozon: buildQUICInitialPacket('ozon.ru'),
    wildberries: buildQUICInitialPacket('wildberries.ru'),
    avito: buildQUICInitialPacket('avito.ru'),
    mos: buildQUICInitialPacket('mos.ru'),
    nalog: buildQUICInitialPacket('nalog.gov.ru'),
    // International services
    google: buildQUICInitialPacket('www.google.com'),
    youtube: buildQUICInitialPacket('www.youtube.com'),
    apple: buildQUICInitialPacket('www.apple.com'),
    microsoft: buildQUICInitialPacket('www.microsoft.com'),
    amazon: buildQUICInitialPacket('www.amazon.com'),
    discord: buildQUICInitialPacket('discord.com'),
    twitch: buildQUICInitialPacket('www.twitch.tv'),
    whatsapp: buildQUICInitialPacket('www.whatsapp.com'),
    zoom: buildQUICInitialPacket('zoom.us'),
    skype: buildQUICInitialPacket('www.skype.com'),
    steam: buildQUICInitialPacket('steampowered.com'),
    github: buildQUICInitialPacket('github.com'),
    // Other protocols - DNS Response (like Yandex capture)
    dns_vk: buildDNSResponse('vk.com'),
    dns_ya: buildDNSResponse('ya.ru'),
    dns_ozon: buildDNSResponse('ozon.ru'),
    dns_rutube: buildDNSResponse('rutube.ru'),
    dns_google: buildDNSResponse('www.google.com'),
    dns_youtube: buildDNSResponse('www.youtube.com'),
    // STUN - looks like WebRTC/VoIP traffic
    stun: buildSTUNRequest(),
    // NTP - clock sync, virtually never blocked
    ntp: buildNTPRequest(),
    // DTLS 1.2 - WebRTC media transport
    dtls: buildDTLS12Hello(),
};

const QUIC_KEYS = Object.keys(QUIC_PRESETS);

// ─────────────── Known Cloudflare WARP endpoints ───────────────
const WARP_ENDPOINTS = {
    // 162.159.192.x — Free WARP anycast
    '162.159.192.1': 'Free WARP anycast #1',
    '162.159.192.2': 'Free WARP anycast #2',
    '162.159.192.5': 'Free WARP anycast #5',
    // 162.159.193.x
    '162.159.193.1': 'WARP 193.1',
    '162.159.193.2': 'WARP 193.2',
    // 162.159.195.x — used in many working configs
    '162.159.195.1': 'WARP 195.1',
    '162.159.195.4': 'WARP 195.4 (confirmed working)',
    '162.159.195.100': 'WARP 195.100',
    '162.159.195.134': 'WARP 195.134',
    // 162.159.204.x
    '162.159.204.1': 'WARP 204.1',
    // 188.114.96-99.x — European PoPs
    '188.114.96.1': 'EU WARP 96.1',
    '188.114.97.1': 'EU WARP 97.1',
    '188.114.98.1': 'EU WARP 98.1',
    '188.114.99.1': 'EU WARP 99.1',
    'auto': 'Авто (из API)',
};

// ─────────────── Cloudflare API helper ───────────────
function cfRequest(method, urlPath, token, body) {
    return new Promise((resolve, reject) => {
        const data = body ? JSON.stringify(body) : null;
        const options = {
            hostname: 'api.cloudflareclient.com',
            port: 443,
            path: `/v0i1909051800/${urlPath}`,
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
                try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); }
                catch (e) { resolve({ status: res.statusCode, body: { _raw: raw } }); }
            });
        });
        req.on('error', reject);
        if (data) req.write(data);
        req.end();
    });
}

async function resolveHost(host) {
    if (!host || /^\d+\.\d+\.\d+\.\d+$/.test(host)) return host || '162.159.192.1';
    try {
        const addrs = await dns.resolve4(host);
        return addrs[0] || '162.159.192.1';
    } catch { return '162.159.192.1'; }
}

// Return endpoint list to populate frontend
app.get('/api/endpoints', (req, res) => {
    res.json(WARP_ENDPOINTS);
});

// ─────────────── Main generate endpoint ───────────────
app.post('/api/generate', async (req, res) => {
    try {
        const {
            licenseKey = '',
            obfsProfile = '1',
            endpointPort = '2408',
            endpointIp = 'auto',
            quicPreset = 'yandex',
            dnsServer = 'cloudflare',
        } = req.body;

        const DNS_SERVERS = {
            cloudflare: '1.1.1.1, 2606:4700:4700::1111, 1.0.0.1, 2606:4700:4700::1001',
            cloudflare_mal: '1.1.1.2, 2606:4700:4700::1112, 1.0.0.2, 2606:4700:4700::1002',   // блокирует малварь
            google: '8.8.8.8, 2001:4860:4860::8888, 8.8.4.4, 2001:4860:4860::8844',
            adguard: '94.140.14.14, 2a10:50c0::ad1:ff, 94.140.15.15, 2a10:50c0::ad2:ff',
            adguard_family: '94.140.14.15, 2a10:50c0::bad1:ff, 94.140.15.16, 2a10:50c0::bad2:ff',
            adguard_nofilter: '94.140.14.140, 2a10:50c0::1:ff, 94.140.14.141, 2a10:50c0::2:ff',
            yandex: '77.88.8.8, 2a02:6b8::feed:0ff, 77.88.8.1, 2a02:6b8:0:1::feed:0ff',
            yandex_safe: '77.88.8.88, 2a02:6b8::feed:bad, 77.88.8.2, 2a02:6b8:0:1::feed:bad',
            yandex_family: '77.88.8.7, 2a02:6b8::feed:a11, 77.88.8.3, 2a02:6b8:0:1::feed:a11',
            quad9: '9.9.9.9, 2620:fe::fe, 149.112.112.112, 2620:fe::9',              // с фильтрацией
            quad9_ecs: '9.9.9.11, 2620:fe::11, 149.112.112.11, 2620:fe::fe:11',          // с ECS (быстрее CDN)
            quad9_nofilter: '9.9.9.10, 2620:fe::10, 149.112.112.10, 2620:fe::fe:10',          // без фильтрации
            opendns: '208.67.222.222, 2620:119:35::35, 208.67.220.220, 2620:119:53::53',
            opendns_family: '208.67.222.123, 2620:119:35::123, 208.67.220.123, 2620:119:53::123',
            gcore: '95.85.95.85, 2a03:90c0:999d::1, 2.56.220.2, 2a03:90c0:9992::1',
            dnssb: '185.222.222.222, 2a09::, 45.11.45.11, 2a11::',
            dns0eu: '193.110.81.0, 2a0f:fc80::, 185.253.5.0, 2a0f:fc81::',
            nextdns: '45.90.28.0, 2a07:a8c0::, 45.90.30.0, 2a07:a8c1::',   // блокирует рекламу
            mullvad: '194.242.2.2, 2a07:e340::2',                            // без логов, без рекламы
        };
        const dnsLine = DNS_SERVERS[dnsServer] || DNS_SERVERS.cloudflare;

        const profiles = {
            '1': { jc: 4, jmin: 40, jmax: 70 },
            '2': { jc: 120, jmin: 23, jmax: 911 },
            '3': { jc: 10, jmin: 100, jmax: 300 },
        };
        const { jc, jmin, jmax } = profiles[obfsProfile] || profiles['1'];

        // QUIC I1 — generate fresh per request when using generated presets
        let i1;
        if (quicPreset === 'none') {
            i1 = '';
        } else if (quicPreset === 'random') {
            i1 = QUIC_PRESETS[QUIC_KEYS[Math.floor(Math.random() * QUIC_KEYS.length)]];
        } else if (QUIC_PRESETS[quicPreset]) {
            // For generated presets (not static captures), regenerate each time
            const generatedKeys = [
                'vk', 'ok', 'mail', 'gosuslugi', 'sberbank',
                'ya', 'dzen', 'rutube', 'ozon', 'wildberries', 'avito', 'mos', 'nalog',
                'google', 'youtube', 'apple', 'microsoft', 'amazon',
                'discord', 'twitch', 'whatsapp', 'zoom', 'skype', 'steam', 'github',
            ];
            const sniMap = {
                vk: 'vk.com', ok: 'ok.ru', mail: 'mail.ru', gosuslugi: 'gosuslugi.ru',
                sberbank: 'online.sberbank.ru',
                ya: 'ya.ru', dzen: 'dzen.ru', rutube: 'rutube.ru', ozon: 'ozon.ru',
                wildberries: 'wildberries.ru', avito: 'avito.ru', mos: 'mos.ru', nalog: 'nalog.gov.ru',
                google: 'www.google.com', youtube: 'www.youtube.com',
                apple: 'www.apple.com', microsoft: 'www.microsoft.com', amazon: 'www.amazon.com',
                discord: 'discord.com', twitch: 'www.twitch.tv', whatsapp: 'www.whatsapp.com',
                zoom: 'zoom.us', skype: 'www.skype.com', steam: 'steampowered.com', github: 'github.com',
            };
            i1 = generatedKeys.includes(quicPreset)
                ? buildQUICInitialPacket(sniMap[quicPreset])
                : QUIC_PRESETS[quicPreset];
        } else {
            i1 = QUIC_PRESETS[QUIC_KEYS[Math.floor(Math.random() * QUIC_KEYS.length)]];
        }

        const { priv, pub } = generateWireGuardKeys();

        // Register
        const regResult = await cfRequest('POST', 'reg', null, {
            install_id: '', tos: new Date().toISOString(),
            key: pub, fcm_token: '', type: 'ios', locale: 'en_US',
        });
        if (regResult.status !== 200 || !regResult.body?.result?.id) {
            return res.status(502).json({
                error: `Cloudflare registration failed (HTTP ${regResult.status})`,
                details: regResult.body,
            });
        }

        const id = regResult.body.result.id;
        const token = regResult.body.result.token;

        // WARP+ key
        let accountType = 'free';
        let licenseError = null;
        if (licenseKey.trim()) {
            const licResult = await cfRequest('PUT', `reg/${id}/account`, token, { license: licenseKey.trim() });
            console.log('[WARP+] license response:', JSON.stringify(licResult.body));

            // Cloudflare API returns account_type in different places depending on version
            const body = licResult.body;
            const acType = body?.result?.account_type       // most common
                || body?.result?.account?.account_type  // nested
                || body?.result?.type                   // legacy
                || (body?.result?.warp_plus ? 'warp_plus' : null); // boolean flag

            if (acType === 'warp_plus' || acType === 'unlimited') {
                accountType = acType;
            } else {
                const rawErr = body?.errors?.[0]?.message || body?.error || '';
                if (rawErr.toLowerCase().includes('too many connected devices') || rawErr.toLowerCase().includes('too many devices')) {
                    licenseError = 'На этом ключе превышен лимит устройств (макс. 5). Удалите лишние — откройте приложение 1.1.1.1 → Меню → Устройства.';
                } else if (rawErr.toLowerCase().includes('invalid') || rawErr.toLowerCase().includes('not found')) {
                    licenseError = 'Ключ WARP+ недействителен или не существует.';
                } else if (rawErr) {
                    licenseError = rawErr;
                } else {
                    // HTTP 200 but type unknown — treat as applied if success=true
                    if (body?.success === true) {
                        accountType = 'warp_plus';
                    } else {
                        licenseError = `Ключ принят, но тип аккаунта не распознан (см. логи сервера)`;
                    }
                }
            }
        }

        // Enable WARP
        const warpResult = await cfRequest('PATCH', `reg/${id}`, token, { warp_enabled: true });
        if (warpResult.status !== 200 || !warpResult.body?.result?.config) {
            return res.status(502).json({
                error: `Failed to enable WARP (HTTP ${warpResult.status})`,
                details: warpResult.body,
            });
        }

        const cfg = warpResult.body.result.config;
        const peerPub = cfg.peers?.[0]?.public_key;
        const ipv4 = cfg.interface?.addresses?.v4;
        const ipv6 = cfg.interface?.addresses?.v6;

        // Endpoint IP resolution
        let epIp;
        if (endpointIp === 'auto' || !endpointIp) {
            const rawHost = (cfg.peers?.[0]?.endpoint?.host || '').split(':')[0];
            epIp = await resolveHost(rawHost);
        } else {
            epIp = endpointIp;
        }
        const ep = `${epIp}:${endpointPort}`;

        const address = ipv6 ? `${ipv4}, ${ipv6}` : ipv4;

        const config = [
            '[Interface]',
            `PrivateKey = ${priv}`,
            'S1 = 0',
            'S2 = 0',
            `Jc = ${jc}`,
            `Jmin = ${jmin}`,
            `Jmax = ${jmax}`,
            'H1 = 1',
            'H2 = 2',
            'H3 = 3',
            'H4 = 4',
            'MTU = 1280',
            `Address = ${address}`,
            `DNS = ${dnsLine}`,
            ...(i1 ? [`I1 = ${i1}`] : []),
            '',
            '[Peer]',
            `PublicKey = ${peerPub}`,
            'AllowedIPs = 0.0.0.0/0, ::/0',
            `Endpoint = ${ep}`,
            'PersistentKeepalive = 25',
        ].join('\n');

        res.json({ config, accountType, endpoint: ep, licenseError });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`WarpGen on http://localhost:${PORT}`));
