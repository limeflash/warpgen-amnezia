const express = require('express');
const dns = require('dns').promises;
const crypto = require('crypto');
const net = require('net');
const path = require('path');
const fs = require('fs');
const { execSync } = require('child_process');
const { createCloudflareApi } = require('./lib/cloudflare');
const { createRateLimitManager } = require('./lib/ratelimit');
const { createOutboundUtils } = require('./lib/outbound');
const { createClashUtils } = require('./lib/clash');

function getEnvInt(name, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
    const raw = process.env[name];
    const parsed = Number.parseInt(String(raw ?? ''), 10);
    if (!Number.isFinite(parsed)) return fallback;
    if (parsed < min) return min;
    if (parsed > max) return max;
    return parsed;
}

function getEnvBool(name, fallback = false) {
    const raw = String(process.env[name] ?? '').trim().toLowerCase();
    if (!raw) return fallback;
    if (['1', 'true', 'yes', 'on'].includes(raw)) return true;
    if (['0', 'false', 'no', 'off'].includes(raw)) return false;
    return fallback;
}

const OUTBOUND_REQUEST_TIMEOUT_MS = getEnvInt('OUTBOUND_REQUEST_TIMEOUT_MS', 12000, { min: 1000, max: 120000 });
const OUTBOUND_REQUEST_RETRIES = getEnvInt('OUTBOUND_REQUEST_RETRIES', 2, { min: 0, max: 5 });
const OUTBOUND_REQUEST_RETRY_BASE_MS = getEnvInt('OUTBOUND_REQUEST_RETRY_BASE_MS', 350, { min: 100, max: 5000 });
const DOWNLOAD_PROXY_TIMEOUT_MS = getEnvInt('DOWNLOAD_PROXY_TIMEOUT_MS', 30000, { min: 1000, max: 300000 });
const DOWNLOAD_PROXY_MAX_BYTES = getEnvInt('DOWNLOAD_PROXY_MAX_BYTES', 1_500_000_000, { min: 1_000_000, max: 5_000_000_000 });
const DNS_CACHE_TTL_MS = getEnvInt('DNS_CACHE_TTL_MS', 10 * 60 * 1000, { min: 10_000, max: 24 * 60 * 60 * 1000 });
const DNS_NEGATIVE_CACHE_TTL_MS = getEnvInt('DNS_NEGATIVE_CACHE_TTL_MS', 90 * 1000, { min: 10_000, max: 60 * 60 * 1000 });
const DNS_MAX_CACHE_ENTRIES = getEnvInt('DNS_MAX_CACHE_ENTRIES', 20_000, { min: 1000, max: 200_000 });
const DNS_RESOLVE_CONCURRENCY = getEnvInt('DNS_RESOLVE_CONCURRENCY', 24, { min: 1, max: 256 });
const TRUST_PROXY_ENABLED = getEnvBool('TRUST_PROXY', false);
const PUBLIC_BASE_URL = String(process.env.PUBLIC_BASE_URL || '').trim();
const RATE_LIMIT_WINDOW_MS = getEnvInt('RATE_LIMIT_WINDOW_MS', 60_000, { min: 1_000, max: 3_600_000 });
const RATE_LIMIT_GENERATE_MAX = getEnvInt('RATE_LIMIT_GENERATE_MAX', 25, { min: 1, max: 10_000 });
const RATE_LIMIT_LICENSE_CHECK_MAX = getEnvInt('RATE_LIMIT_LICENSE_CHECK_MAX', 20, { min: 1, max: 10_000 });
const RATE_LIMIT_TEST_LICENSE_MAX = getEnvInt('RATE_LIMIT_TEST_LICENSE_MAX', 8, { min: 1, max: 10_000 });
const RATE_LIMIT_DOWNLOAD_MAX = getEnvInt('RATE_LIMIT_DOWNLOAD_MAX', 60, { min: 1, max: 10_000 });
const RATE_LIMIT_MAX_ENTRIES = getEnvInt('RATE_LIMIT_MAX_ENTRIES', 100_000, { min: 1000, max: 1_000_000 });
const CLASH_PROFILE_MAX_ENTRIES = getEnvInt('CLASH_PROFILE_MAX_ENTRIES', 5000, { min: 100, max: 200_000 });
const SPLIT_RUNTIME_MAX_DOMAINS = getEnvInt('SPLIT_RUNTIME_MAX_DOMAINS', 5000, { min: 100, max: 200_000 });
const SPLIT_RUNTIME_MAX_CIDRS_PER_DOMAIN = getEnvInt('SPLIT_RUNTIME_MAX_CIDRS_PER_DOMAIN', 64, { min: 4, max: 1024 });

const app = express();
app.set('trust proxy', TRUST_PROXY_ENABLED ? 1 : false);
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.get('/clash', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'clash.html'));
});

function safeExec(cmd) {
    try {
        return execSync(cmd, {
            cwd: __dirname,
            stdio: ['ignore', 'pipe', 'ignore'],
            encoding: 'utf8',
        }).trim();
    } catch {
        return '';
    }
}

function readPackageVersion() {
    try {
        const pkgRaw = fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8');
        const pkg = JSON.parse(pkgRaw);
        if (typeof pkg.version === 'string' && pkg.version.trim()) return pkg.version.trim();
    } catch {
        // ignore
    }
    return '0.0.0';
}

const APP_VERSION = process.env.APP_VERSION || readPackageVersion();
const GIT_SHA = (process.env.GIT_SHA || safeExec('git rev-parse --short=8 HEAD') || 'dev').trim();
const GIT_DATE = process.env.GIT_DATE || safeExec('git show -s --format=%cI HEAD') || new Date().toISOString();
const VERSION_DISPLAY = `${APP_VERSION}+${GIT_SHA}`;

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function isRetryableStatus(statusCode) {
    return [408, 429, 500, 502, 503, 504].includes(Number(statusCode) || 0);
}

function isRetryableNetworkError(err) {
    const code = String(err?.code || '').toUpperCase();
    return ['ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'EAI_AGAIN', 'ENOTFOUND', 'EPIPE'].includes(code);
}

const cloudflareApi = createCloudflareApi({
    requestTimeoutMs: OUTBOUND_REQUEST_TIMEOUT_MS,
    retries: OUTBOUND_REQUEST_RETRIES,
    retryBaseMs: OUTBOUND_REQUEST_RETRY_BASE_MS,
    isRetryableStatus,
    isRetryableNetworkError,
    sleep,
});
const { isWarpLicenseFormat, generateWireGuardKeys, cfRequest } = cloudflareApi;

// ─────────────── QUIC Initial Packet generator ───────────────
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
function buildDNSResponse(domain) {
    const txId = crypto.randomBytes(2);
    const flags = Buffer.from([0x81, 0x80]);
    const qdcount = Buffer.from([0x00, 0x01]);
    const ancount = Buffer.from([0x00, 0x01]);
    const nscount = Buffer.from([0x00, 0x00]);
    const arcount = Buffer.from([0x00, 0x00]);

    const labels = domain.split('.');
    const nameParts = labels.map(l => Buffer.concat([Buffer.from([l.length]), Buffer.from(l, 'ascii')]));
    const qname = Buffer.concat([...nameParts, Buffer.from([0x00])]);
    const question = Buffer.concat([qname, Buffer.from([0x00, 0x01, 0x00, 0x01])]);

    const fakeIp = crypto.randomBytes(4);
    const answer = Buffer.concat([
        Buffer.from([0xc0, 0x0c]),
        Buffer.from([0x00, 0x01]),
        Buffer.from([0x00, 0x01]),
        Buffer.from([0x00, 0x00, 0x00, 0x3c]),
        Buffer.from([0x00, 0x04]),
        fakeIp,
    ]);

    const pkt = Buffer.concat([txId, flags, qdcount, ancount, nscount, arcount, question, answer]);
    return `<b 0x${pkt.toString('hex')}>`;
}

// ─────────────── STUN Binding Request ───────────────
function buildSTUNRequest() {
    const magicCookie = Buffer.from([0x21, 0x12, 0xa4, 0x42]);
    const txId = crypto.randomBytes(12);
    const msgType = Buffer.from([0x00, 0x01]);
    const msgLength = Buffer.from([0x00, 0x00]);
    return `<b 0x${Buffer.concat([msgType, msgLength, magicCookie, txId]).toString('hex')}>`;
}

// ─────────────── NTP Request ───────────────
function buildNTPRequest() {
    const pkt = Buffer.alloc(48, 0);
    pkt[0] = 0x1b;
    crypto.randomBytes(8).copy(pkt, 24);
    return `<b 0x${pkt.toString('hex')}>`;
}

// ─────────────── DTLS 1.2 ClientHello ───────────────
function buildDTLS12Hello() {
    const random = crypto.randomBytes(32);
    const sessionId = Buffer.from([0x00]);
    const cookie = Buffer.from([0x00]);
    const cipherSuites = prependLen16(Buffer.from([
        0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0xff,
    ]));
    const compression = Buffer.from([0x01, 0x00]);
    const helloBody = Buffer.concat([
        Buffer.from([0xfe, 0xfd]), random, sessionId, cookie, cipherSuites, compression,
    ]);
    const msgSeq = Buffer.from([0x00, 0x00]);
    const fragOffset = Buffer.from([0x00, 0x00, 0x00]);
    const len3 = Buffer.from([
        (helloBody.length >> 16) & 0xff, (helloBody.length >> 8) & 0xff, helloBody.length & 0xff,
    ]);
    const handshake = Buffer.concat([
        Buffer.from([0x01]), len3, msgSeq, fragOffset, len3, helloBody,
    ]);
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
        0x13, 0x01, 0x13, 0x02, 0x13, 0x03,
        0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30,
        0xc0, 0x09, 0xc0, 0x13, 0xc0, 0x0a, 0xc0, 0x14,
        0x00, 0x9c, 0x00, 0xff,
    ]));

    const sniBytes = Buffer.from(sni, 'ascii');
    const sniEntry = Buffer.concat([Buffer.from([0x00]), prependLen16(sniBytes)]);
    const sniList = prependLen16(sniEntry);
    const sniExt = Buffer.concat([Buffer.from([0x00, 0x00]), prependLen16(sniList)]);

    const groupsExt = Buffer.concat([
        Buffer.from([0x00, 0x0a]),
        prependLen16(prependLen16(Buffer.from([0x00, 0x1d, 0x00, 0x17, 0x00, 0x18]))),
    ]);

    const versionsExt = Buffer.concat([
        Buffer.from([0x00, 0x2b]),
        prependLen16(Buffer.from([0x04, 0x03, 0x04, 0x03, 0x03])),
    ]);

    const pubKey = crypto.randomBytes(32);
    const ksEntry = Buffer.concat([Buffer.from([0x00, 0x1d]), prependLen16(pubKey)]);
    const keyShareExt = Buffer.concat([
        Buffer.from([0x00, 0x33]),
        prependLen16(prependLen16(ksEntry)),
    ]);

    const quicParamsExt = Buffer.concat([
        Buffer.from([0xff, 0xa5]),
        prependLen16(Buffer.alloc(0)),
    ]);

    const extensions = Buffer.concat([sniExt, groupsExt, versionsExt, keyShareExt, quicParamsExt]);

    const clientHelloBody = Buffer.concat([
        Buffer.from([0x03, 0x03]), random, Buffer.from([sessionId.length]),
        sessionId, cipherSuites, Buffer.from([0x01, 0x00]), prependLen16(extensions),
    ]);

    const len3 = Buffer.from([
        (clientHelloBody.length >> 16) & 0xff, (clientHelloBody.length >> 8) & 0xff, clientHelloBody.length & 0xff,
    ]);
    return Buffer.concat([Buffer.from([0x01]), len3, clientHelloBody]);
}


function buildQUICInitialPacket(sni) {
    const dcid = crypto.randomBytes(8);
    const scid = crypto.randomBytes(8);
    const clientHello = buildTLSClientHello(sni);

    const cryptoFrame = Buffer.concat([
        Buffer.from([0x06]),
        encodeQUICVarInt(0),
        encodeQUICVarInt(clientHello.length),
        clientHello,
    ]);

    const payload = cryptoFrame;
    const pktNum = Buffer.from([0x00]);
    const lengthField = encodeQUICVarInt(pktNum.length + payload.length);

    const packet = Buffer.concat([
        Buffer.from([0xC0]),
        Buffer.from([0x00, 0x00, 0x00, 0x01]),
        Buffer.from([dcid.length]), dcid,
        Buffer.from([scid.length]), scid,
        Buffer.from([0x00]),
        lengthField,
        pktNum,
        payload,
    ]);

    return `<b 0x${packet.toString('hex')}>`;
}

const QUIC_PRESETS = {
    warpgen: '<b 0xc2000000011419fa4bb3599f336777de79f81ca9a8d80d91eeec000044c635cef024a885dcb66d1420a91a8c427e87d6cf8e08b563932f449412cddf77d3e2594ea1c7a183c238a89e9adb7ffa57c133e55c59bec101634db90afb83f75b19fe703179e26a31902324c73f82d9354e1ed8da39af610afcb27e6590a44341a0828e5a3d2f0e0f7b0945d7bf3402feea0ee6332e19bdf48ffc387a97227aa97b205a485d282cd66d1c384bafd63dc42f822c4df2109db5b5646c458236ddcc01ae1c493482128bc0830c9e1233f0027a0d262f92b49d9d8abd9a9e0341f6e1214761043c021d7aa8c464b9d865f5fbe234e49626e00712031703a3e23ef82975f014ee1e1dc428521dc23ce7c6c13663b19906240b3efe403cf30559d798871557e4e60e86c29ea4504ed4d9bb8b549d0e8acd6c334c39bb8fb42ede68fb2aadf00cfc8bcc12df03602bbd4fe701d64a39f7ced112951a83b1dbbe6cd696dd3f15985c1b9fef72fa8d0319708b633cc4681910843ce753fac596ed9945d8b839aeff8d3bf0449197bd0bb22ab8efd5d63eb4a95db8d3ffc796ed5bcf2f4a136a8a36c7a0c65270d511aebac733e61d414050088a1c3d868fb52bc7e57d3d9fd132d78b740a6ecdc6c24936e92c28672dbe00928d89b891865f885aeb4c4996d50c2bbbb7a99ab5de02ac89b3308e57bcecf13f2da0333d1420e18b66b4c23d625d836b538fc0c221d6bd7f566a31fa292b85be96041d8e0bfe655d5dc1afed23eb8f2b3446561bbee7644325cc98d31cea38b865bdcc507e48c6ebdc7553be7bd6ab963d5a14615c4b81da7081c127c791224853e2d19bafdc0d9f3f3a6de898d14abb0e2bc849917e0a599ed4a541268ad0e60ea4d147dc33d17fa82f22aa505ccb53803a31d10a7ca2fea0b290a52ee92c7bf4aab7cea4e3c07b1989364eed87a3c6ba65188cd349d37ce4eefde9ec43bab4b4dc79e03469c2ad6b902e28e0bbbbf696781ad4edf424ffb35ce0236d373629008f142d04b5e08a124237e03e3149f4cdde92d7fae581a1ac332e26b2c9c1a6bdec5b3a9c7a2a870f7a0c25fc6ce245e029b686e346c6d862ad8df6d9b62474fbc31dbb914711f78074d4441f4e6e9edca3c52315a5c0653856e23f681558d669f4a4e6915bcf42b56ce36cb7dd3983b0b1d6fdf0f8efddb68e7ca0ae9dd4570fe6978fbb524109f6ec957ca61f1767ef74eb803b0f16abd0087cf2d01bc1db1c01d97ac81b3196c934586963fe7cf2d310e0739621e8bd00dc23fded18576d8c8f285d7bb5f43b547af3c76235de8b6f757f817683b2151600b11721219212bf27558edd439e73fce951f61d582320e5f4d6c315c71129b719277fc144bbe8ded25ab6d29b6e189c9bd9b16538faf60cc2aab3c3bb81fc2213657f2dd0ceb9b3b871e1423d8d3e8cc008721ef03b28e0ee7bb66b8f2a2ac01ef88df1f21ed49bf1ce435df31ac34485936172567488812429c269b49ee9e3d99652b51a7a614b7c460bf0d2d64d8349ded7345bedab1ea0a766a8470b1242f38d09f7855a32db39516c2bd4bcc538c52fa3a90c8714d4b006a15d9c7a7d04919a1cab48da7cce0d5de1f9e5f8936cffe469132991c6eb84c5191d1bcf69f70c58d9a7b66846440a9f0eef25ee6ab62715b50ca7bef0bc3013d4b62e1639b5028bdf757454356e9326a4c76dabfb497d451a3a1d2dbd46ec283d255799f72dfe878ae25892e25a2542d3ca9018394d8ca35b53ccd94947a8>',
    ya_ru_capture: '<b 0x02000000450004fe00004000401124f30a08010305fffff2ff4601bb04ea3dc6cd0000000108cf372eb1c5c5fe8f000044d08974fe2db906297b34eca003e69509523d6ba0b7717b5b9fc8eb4fcb9b1c9fc0208819ab797a5be1c96a954517640d526cd85324a36c7fe1e4607f2b5e74f507533d973b7e49ca8a5f8fde34afadbd9a4a68cb72df0889d868ab4bd9e886486dc6c98aefbad367f07b6157e2ff201e80006e1a2e787414362fda9c040c4e44b0cd9a3d30283f5fe5cbbc7c687a41771f28611df08fb79852d73f9a533e515659694c00bbdf60111244d1a3c8e767dbd44d8e1b88b5fa3eb382c54ac2be0205839b85daba6d66be3713b13eb589e7ec95e898f202292410a1b279be255f20e594780ef076f1f9fed57bb4aca0c7617c0de007d83b1ad9c434adf12c48c2ad25a7fec5d0e9a15775a986e3ff3e9c64102e4eeec60e23ab668a3abbe6fbac03abc4db59adfd792545340f260ecf08ee41d4ebf991bda29e0360dbc0eb469bac14f45f3828317e892f46873da22b35fa25bf4e674bf4e7c7da0a22509f41a1aa954fafc50c2a2973a8aab4fc30a6eee9bf868bc594f904ba33cb5589deef807a8962962ec5226e6d9872aa4c396ecdbf5adbaba777837bcff86a9f7b6f847e6c067286dd2959901fa94f0acf110fed2108cac1434e57337f0aa2236d53b2fcf07063ce0e6eb6d55736b2c48096a574b384a2197e3f3e30f79daa825ef60fda14732bec2fd7c4926e7259b349bb9901eb7a2b56ecbab02f32e72d5df3541263e87ff29f064b07e28b788ead8a5e350ee4d175959a34d6464744e84f9110111e8313213713431013d8d06a15383d4203431b37ef072f7545499c81e96c694422de131723cb79cf7f760ca849cac3121442542d1d41576fea14a0f4854dc75f9a21fd7f5ef7d2c2ae9a89408ae672748910ea623a03998019b572068c70d1688f07d036c78df6e47ac7fc37e2ec736f58a18749c6eed5ed4ae58004dbec58de9040cf0579270f5a1499828024119316f0dfa81972feef9541f96ceda2c8b7965f8342798a7aa70e37885afe08b9f5d7b58f224b8afcab02b6fb126dd215de1e6906f46dfc78e2329657cf6fd340ba2cf5be5e27ea0bbc3e95323d635b4321bd2fc75e15dcd4cca794a64876942f37ec43e8636e5f1a208fc37ceadf25ca8156f4a76794ef2eacdec4d437937d0a1a24dbb84f3e8160b4d4a5e89485f5bc3443b27ba0302ea4227b1997a6be19bfbec4d4fb36f8c705c1005720afd50dc545c25b3a697d67ac4436d2a6dbf37231d6585f2eff7ee5475f60df2d7180a61901bfc7202201575dfb3263315ff10fbe1db6c9c81c9cec5501b0b271e4fbf883f74ef1e88aa3af13dcf0510981d85a223e38437b94c332f25023e39d2a7e1a99ae4a90a723a2d7de271a2cb9cee7e71fe940b9c32bd0fdea494dad65e55ec8160470bd443e7d4c0c3079ed4b66197907b9c1d59b29aea927a47bd1e5cbb6e856d50a10521e80b4d188624902b638403344bc7fc9f5e8dd6cf4b841e324eccdb22924427c17be09d36bb57cf583f2022030eaf0fa96f369cf8d8c6ee03dacf980259d109616fbd1e21c4877c25ed3c05fad32f62b21c0593a698af2e7f01063976cacf4305a93e080844a0dbab8de7760f41b451d1fdc0a921c28959832f82f1b04d640b1bb209eb17bf5501b95909831853c31e840118b99064c40667446d87edc7a38e2f03c01d0256d685260b935a76f03720e43d0a41352e34ba7987d63e05f0d124cfe3ec15ec5f7a4659a7486dc083103e4e9ed>',
    cloudflare_capture: '<b 0x02000000450004fe00004000401155a10a080103ac402903f38701bb04ea63a3cc0000000108b59c7b5317dddb9d000044d0f5dc768fc8479d149c4e1640e24e07ffd673cbf381e508b09c453a34ea5a5bd2922c3e30cd4525fae8b3688810e21634edcab8e4aa8cbb848e1db5947148b843c7bdf7cb95e3ed9be3ebe0ae3866ff5b8267684dd9e27f00ff5d49098195d3d9614f1943160d795bc5c05920e6bb7297eed99272a833b8132a4c1d05de5594fa4eb098ab242868a5af025bc0e391b9fae60a9328643dcbeeb5b4672347de6ae7c67d583892ae002bdea5c5a7eee4326b90e68ecf0148a72f926583d6020a07212bb457c1fa44b010527e9e3f8b8f3f2b4ad3be45f82767b266566e10457991e38139060c5458f13cf46ddea70f703020772bc43f781ade846a44ee2ba4f2bc1c94e2eafd4966ef4c7a78edb65588fdc1f5724e1ec7e01b2b862bd243dbc4145cb28b9ec4ff92ace7c840caf80b0fbd6757f866a37439f6c576ad23a89a0953a2e3d2f7b95875cf7867f73cb15a19a00a319c6903252ff85751a9f50709301cafcbcd4cbca9a646587aa7644bf3bbf5599731c2d32c7f78ddc743b011fcd0580f93b6e9cf2048f2861387c5c4eae9a983a604c2f96e877984c6a114662f8025da49e462dfbc5891da7e2723b50547bd1171380e13d2a929aa1039f244054985ce6e4deafdd0e66781be3c57e7bc498d37266926f1a7b47875bbc38d35089742f1bbae96362dd22287d0f980d90361cc42d9619f8a43abad0bd0c5cdaa0c9c759674e1973ee5600988570c89857114981c4a129c030fc2706a2bb829ed40368b9c27665608c3f6e06c21da9b852a1edaf04f4d15df8f1010163df3f02b5aeaacf72bf2ae590b04c7e134c22834d453b3b10e0a21732d71977d12530f5299f543b2d273a8ec8c5f63d1fedba3dd2575143cbfba65dc02045b8a0662083af598eaf6b8f4b5e72bb43fa360bbf250c1a34bbd5b76acf019815f2088a266cf65ef5e2537250f2c2d57fd5221f9ba760bc7a6abe71e1bebdd3a962f367c30464ad0c0567b1d96b1831dc3503b38b60f77fb8bf9e49d960b657a2841e6c12dbc2c13f596386d9bfb7e0e8a5622ef20c5cada2266e9bc9e4f12f3a23b4ef9643d270aa3a30f0705eba691a0e662119af38a8a889105747504276063da120b809c0ce46379f4df6cd99c708021eee3175935ecddedaddf561bcd1e8a0828c7422114ef6214e2237705f3ca3f54eada9cc7c5f603522e877540aa3a57d74b48fd2cd8f8d594348300a9ed6e1094c05670aeb4c9534c655a8b7dc60180047686e58cc74cdcee57e2cb268ace7397f5ba254a26ed4a4b222f92bf5c349b13741f437118cecad9acb49bb316da6de4874d659737489d00972df8b95d621b625acc6500535e7c20fb006fb3ceb32de1282639c9229e5a7a3b8ee7778c8cbc9d38f3bea7de337a74e283b8cd4915802252e67c7855b031d05ecccb2fc1e8937e52f2283abd234fb89b52e0367fe0d0b692164d6d7a9e0d25350b91e455390c57831f8f84e469b9a7c8c99a25423b263093c939117e50fb6eddbdca9c48d7deee1ba5b40751bec923b0d18b773b0cc74392b8b874be89260d5be7d8eac4cb09e1fa0a39a58bfee5380b68d561bfbc9ec7432e608814df187165588c799857f9e10230a5becf267e0ef6b0455888d291e9bf359c7f388648e65fb32f9ad8a1be7f9d9c21ff0dffc2870f381f589b772be07a644416a1c1a409f8a1cc1f2c46cccb091fb0d350faea2d1ec057cfa1268172848a4fa02aded704>',
    google_capture: '<b 0x02000000450004fe000040004011489d0a08010340e9a15ec73e01bb04ea71d1ca00000001088be83851d332138a00404600e5708422454eb06dd454d6bca529b82006cc8c8f9425357331566918bdeb5c599b2a874af15e213bce044ed2790ff29ecbb4af203aaa25dc8f4d4b372ac399af3d833098ea44898aa175aed82755a9419e269aebe607f65534fc5fea00a382151c447fb575f85d5817714e77afe5d3e76d3f9d5a886feac4bc14fd17d35aa6604893cc1444f5c26be9001202da62168c092843982f17e6ef3d291e7f7eea1797e97d6105c63516b860f0940ece34be539146baf2be2f91405dcfdeb55f9534ebccc0cc6622c5e73e0d1825d8bb19d411bdc8ac5dbbdc688da901b7b67ac3b8340d3d2248ff973fd8814a8450896f2da563bb88eb87cd6825515daa7860bd31d85e47c10e6ecdf998acc654b50954387d35e90b5a6f9f0eb731e01257ec897188b08dba2e9fa8157e7934efb7fb2f6d3928c9172bd25d83284eddd6d85849d2e40ff477e32b76fdf383d7ae4cb6ca1e11fae9d37094fa8512a98de10d585de952a82e2ee7ebdfd59a077052382b4898e36509b654851c4dc9535c9f65a6dfb447edb2d4c2342a52c2c8dafd23d2485e4f5c242b6b6f8f6f58929221a82f262d27af2b0fa1e294467bc98679eac3930edac5ce663f41a1e76f0b18374aa9bf67d2bc738591c1a6d7008d270563bf50bcbd73ba6888a18280b08a52f5ccc469d59d3b7b464692f9d720ac07eb35d2ecf2c66c608df67563bf86d8e29917b531045964366377a865c181f3f21d6d6e7391bd23ec66e9eee11f2071d7d93df7bd23358bd658cb31ac5432dc185fbe439c2f6c96307237049a80b3b704fad5a0766ffa590490f645f55d7d51dc35dfb41314a113dd2e88c1c5db683f2c0941af31ace0b57aba60376f42701fbcea42cf284261821542ddf7351a7ea5ca0dbaeb54ebb1cf3703a30d6bd9f4f5bf8cb773ecf32c1e830666a38bf9ba7f382770d3def0e22338782d796d6cefb4b347f26444ba44d2c99e69e7fe44f2a4de1f2ab9cd477d3b9dc501a7c47436acc2350eb203d2521f89f25e8550375e7e9e142bb94b1ee485fea389f2c585e25e6390fcd2bc953372d4c083a155385bc5ce3b444f76df96ae4c1362fd7c117ac9859852d94fe1e5dce08905317e10a48fc333bff1ffddcf98242c49383a0b85877d22296c2b3cb42ac0a3ae493a5d618c7779d67ddd64207aa6d2fb43c1273192b906edbf2d3ccddd3ec2cdd1f2182ebb213bec3270c7f3afa7d8d0bcf220e76c4898013d18116051ab7a59d7f046583b195c0f461a8c4c8b0a1c597293b8faf068f7bc7ca4b26731f63b54c16c20855fdc756c0b322b89b342fb097f61bb8c843e034ad71478f4521af06aff4853ee113a9202deb1c64f763c65ae47c8df54e01747137fe9111bc0122155a94abec038c1999d077853d6bd25c67ae82bbf34dcd5a6fbaeabc01a6d0d67f2f2269f42e4bc702acd38cd767bf2ed59369ba4cd81135f4aefed786a12d7dc3088c71066e233bab7b6e82bdb4022f232d9ced5a5ec9dedc54065825a3f0a77c1123fc0899b7423550fb94ad590366f659916e9b4bb60d7ddd2a24b15915883d3998ecb53f9bfe0a94d8778935027fd3d1fe113548d2e233fc03bd99d3e5d47d8a99f9261541ea746b1f5f89fcd764834ef9e1c5f76ceb771185553d34aca16b3103563331537a90197f62aa84b6d8936ccd6407453eb1987307904e2cc860ff76f07b76d44668ead78f0e6ae9a9bba766bd0c315ac0e0c72f09a82c9>',
    capture_195_85_59_162: '<b 0x02000000450004fe0000400040112bed0a080103c3553ba2fa5801bb04ea837dce0000000108e75bbe163a455fc8000044d050419383bcdee4b02a1ae12f7fdc0c77ce54baad7c5f0fd1b1272301b865bc6091ae57a11d28f63a64542022fe54a807b530f7a50abefec317140682e21cc5b215fbb68879365fd57696af9241e01faacfacb386e5724320f864b5b209b752b7f2ad0c96e528e36cc7e72b4b8847a0ee3bc9a03b351db5138bf7de3c76f3e20545d91a3e9ec107800ffb88c44192c2169832fe16ceea96af02efe5ca65ef8ec02119e099840080145f04a679a2b8497b649c75f4ed60239bc05033af91eb66953e11ac8e93306f7a5bf799f552576dee0b5883d55e78d8a6acc0f91ebd3624f9ff051820785e869d612b1c5019155835cc198c758ec5bb5bb88f93aca709b0a77b313051a3e2d3cb3ac3251b91b2a1b3fcb8844d99a84f856acd00747c665e48800425ca5ad250f45da49be11b62a2f2384fdfda66717081fab5868d4f25cdc854cd587fc0eee2dd997dd6f4b073e4b1d5d93b56e0bddde79660e0aa2eeeda0feeeb3a73a301208476c7d11664cbd6f67e07dd167763ec8e7236af42bb80c9e2ed999992b78d8fdce14dcc5c43fb45b37915da30d5c1c2c08475a6e899a611054c2c0d0995071a0ea5c7746089984022328a1168badeca79ef47422c360f32223f6e33355f0211f1445b99e18cbc4271db7b3c843f01203ad15a932c9ebd403829b1f1aeb9291a4c4e069df0dc4c88a8cb14dfa4cde33ea69dc5dba26c1c1727072d2b1b8966bc275353f3a1b4e63bbf338ae3b131e7a5e687782d69b3a766d1d297d1f346faf6eb3d5ab471d18f2d371f6244229db58b8fe445a23232e68cd42c92061e4f6e729498be9d83959afa542bc57a7ad61cfbe91cd316a5b4cebb9beb5f86ec74ec5198ce5d78c47bdeaea510775661d7bd4a7d127ef9f62acb224c19ca8dd86a8df16154dda9691dcc0edd8e0b866201a46c46c5a2ac1efd9c7559f77a5065ed9ac3df6acd79ebcb0132e29ad5bb7d28a7be350a3deea4062b811eb0e9d40bb7846e7adaae47ba2adface6187879c0cc7269e0978c9b365fc8350f2043fd74dc0bec77874d13c3c624e4272cb13003928736d0736b4e22e766ecbb512145b82be2b222ece3c651353f86ce0cd7de89f2f7f89d479f16dc3035a958dae982d2c82ef3b67a3ec1c57132fddd82a38518e94370fa045eff42df52b87b4d3b0c96d75545d362cdb3edfbe4f1711d79f4499efb7a3888b339a4387fb33ca21d32f2af8eae646418e62f4dbd041d721d7e1be49394c9a871658dca7df36d46c0a354925c4f6a04592bc195fb27b362e64f644e615a235359d9957b6a2cb33613dd284d95af0e33100a80d7bd6a9806b03facffb0ee5172cab44af43e37e3baa8e955da08b8019300ecde0d04a1933a432ec80fb58ef1e316e6ce858134119dd72e2c3f670a24538e9985f319877ae50f7ce4ab1304a761a90b58595c870123a1f7c67df27a29a07dd007f52c98d1437b954926e9f59e6645a5f796a2cfe9874456010ab626529a9cc54b6457d532c48ded16adf5a846b71de14913854b1365e810fec5b202874cd54fab0ef89549be8352cef3ce2f029730d01ff81d6521c0230f9fdffed0dfd4ded780a1f2e410acba61f7a7a5f155b382a40bdd127efa8c16a2c09a41bf4373d79fb8ac742325c8850bb98c5513ab52e5f738bc458fb5c6d050b94cbc2b86a077353f0f25be928b9b32f9585ba84aff7926ff0796922ae64a397e70dc88e7757d1388051839cb>',
    capture_87_245_197_142: '<b 0x02000000450004fe0000400040110d610a08010357f5c58eefac01bb04ea1598c4000000010852f2fdb53a46781c000044d004d25e2fb615972a1d53d8dd5c4c9e478b2c0e373e254e89193779fc59ab1ad91100721e2ed2fbed95f05cdfcad08f0a664f0d4a2873585a68ba2bea4509ef72bed9ec6e768ed2b948bd6885293f690aa6104a25a652ed5dcc65bc29ddb62b7aab411ac8f9fe293473d15070f77878de54dfb628949049144af2a4f51ef8760ca9b183a3cba948c113104c1953d2458430dc8d6f773e69ed8c124824042ee37b0aa1a18f22bc42cb008c0a95c246a93ffcde653da47ab32bc779d360af3a90db8f12a6ade988a29e8107843ced66b173ad2525c8771886f08c0aea9f3354a58050ab71f88476b445b174220bfe87fb4a4ac6dc49ad9fdbdfad1b0d6417913167df741b7bdef8c9bfec114e621dfe11eae9d3dbb890ae7c8df2c985c4bd3666323c386b62815eed2fb504314e9f020021dfeb44a7db4e13630674a83a51417af6c2c0a168fbe86254f4cdb691a60679fe651470bed37974f75f7246fa2a3a3b5b64fc0afc91c445924921e909dd0f9893bf14c56c8c7b9020506e68ca734e187affd96b67004eef6643d6d53ccce416aec032e3c4106fb44159c7bf72dea3ccf1f4e47232ccde706327fdb6044223eb42dd414fd7c316ab5fa6b479ba191014124142c018ff3ab545d599c9028e470d56d256b8baf19f1a5ed80a9377cc9604b3e1c36271a6a88714e0c6340d6e828e55e2b332673e92c344e76afaa6a435ff8f729e9e21707cd9242fe568cf121a7a3955a60a38ffe3b3850b60a280e6db50af3ccf3e3f4982eb9a0ced349813bd1c4b2e6f531c71a9d338921af2f824b23bf3bed336f01951719cdf409252d0abf476028019760ff11288d61c99a6026da4d34ea4930bf929f082d4659df1a6b8585270fec919f67b692b4d7dcb320401206b716530a9479ae838442fa39b7cfb000661350a7fc1b652cc31a5cb4b4154151ac9d9d02113c8df79bd73d258f49d64f97a6ee36e48561a21098879fae12d0bed5dc4dc7075ccd3ab8dc11333e6b4d282f357cd848e753b95bbe16b0a42998d53f5d8ef0ccb8f7e6fb37d2d889d44ec7dbf789c903f7cfb7a0ef6325f530531d7c7e5601dbdcfeeb13655c498cbaba070fe301a11fdca27d7fe75ace8a1c07119c0f2a0a900930feb7193d7fcfbb04f13c0cf4d7b101043a253cb8e5d7cf7c58cb2b878dab118dc09d2e4f1dcb29895dacc61267abc5dda271b094154d218e50f9826f8c4badcb7be3b67bae33a40d4c290e9de48f060b3a39846f73fa13d133ace35faef1eddedc4a51a57848c04943a85da62236a700006b54cad929de6d95efc54b89252d92e5a1b4b57bd2e181e442fcf05ae111f9615fedd6614de8203b2e9d02dc34bc4cb8df4fa03363a5b18cc78b71103b28662dd28dbff0608511cde742706fd476e8cdecf96540c85c2c3b86edd28898a2a58221bd75eb93b3ef1bc64d4510222aab46ec43a6f5964b4e311dedb10c3222723c301cd34441f8dae12edc0718ec3e0628e6eafbe0946689501dc7ee01fd458d02c5bb7ddf4978bdddd9c2eb7b2b7c4a5220783733a86d47ecb505100c445a126b17a1dbc42d7a9565b90971c9deae29a3f83e69316d2242d6b52de52971936cf33c26464ecbade3405bbdbf911bae1670ff3959ccb76fb63ba91fa6be1b799ea275818d833e165b6dba06b19c62bff570a0f601806408f9e8da5afee6190b06d5732acc1dc032cd98e60e16fc5c11cde9374894e61798bdca8>',
    yandex: '<b 0x084481800001000300000000077469636b65747306776964676574096b696e6f706f69736b0272750000010001c00c0005000100000039001806776964676574077469636b6574730679616e646578c025c0390005000100000039002b1765787465726e616c2d7469636b6574732d776964676574066166697368610679616e646578036e657400c05d000100010000001c000457fafe25>',
    dns_web_max_ru: '<b 0xce40f5295b5ae03f49dff318080045000068000040004011b65cc0a80101c0a801d700350a700054ca21645f8180000100030000000003776562036d61780272750000010001c00c00010001000000a300049bd4cc8fc00c00010001000000a300049bd4cc4ec00c00010001000000a300049bd4ccc1>',
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
    dns_vk: buildDNSResponse('vk.com'),
    dns_ya: buildDNSResponse('ya.ru'),
    dns_ozon: buildDNSResponse('ozon.ru'),
    dns_rutube: buildDNSResponse('rutube.ru'),
    dns_google: buildDNSResponse('www.google.com'),
    dns_youtube: buildDNSResponse('www.youtube.com'),
    stun: buildSTUNRequest(),
    ntp: buildNTPRequest(),
    dtls: buildDTLS12Hello(),
};

const QUIC_KEYS = Object.keys(QUIC_PRESETS);

const ALLOWED_WARP_PORTS = [
    500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946,
    955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408,
    2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281,
    7559, 8319, 8742, 8854, 8886,
];
const ALLOWED_WARP_PORT_SET = new Set(ALLOWED_WARP_PORTS);

const STATIC_WARP_ENDPOINTS = [
    ...Array.from({ length: 20 }, (_, idx) => `162.159.192.${idx + 1}`),
    ...Array.from({ length: 10 }, (_, idx) => `162.159.195.${idx + 1}`),
    'engage.cloudflareclient.com',
];
const ALLOWED_WARP_ENDPOINT_SET = new Set(STATIC_WARP_ENDPOINTS.map((value) => value.toLowerCase()));

const WARP_ENDPOINT_GROUPS = [
    {
        label: 'Рекомендуемые',
        items: [
            { value: 'auto', label: 'Авто (engage.cloudflareclient.com)' },
            { value: 'engage.cloudflareclient.com', label: 'engage.cloudflareclient.com' },
        ],
    },
    {
        label: '162.159.192.1-20',
        items: Array.from({ length: 20 }, (_, idx) => {
            const ip = `162.159.192.${idx + 1}`;
            return { value: ip, label: ip };
        }),
    },
    {
        label: '162.159.195.1-10',
        items: Array.from({ length: 10 }, (_, idx) => {
            const ip = `162.159.195.${idx + 1}`;
            return { value: ip, label: ip };
        }),
    },
];

const WARP_ENDPOINTS = WARP_ENDPOINT_GROUPS.reduce((acc, group) => {
    for (const item of group.items) acc[item.value] = item.label;
    return acc;
}, {});

const SPEEDTEST_SESSION_TTL_MS = 20 * 60 * 1000;
const SPEEDTEST_SESSIONS = new Map();
const SPEEDTEST_LAST_GOOD_BY_IP = new Map();
const SPEEDTEST_ENDPOINT_STATS = new Map();
const SPEEDTEST_FALLBACK_CURSOR_BY_IP = new Map();
const SPEEDTEST_IP_TOUCH_TS = new Map();
const SPEEDTEST_IP_STATE_TTL_MS = 24 * 60 * 60 * 1000;
const SPEEDTEST_ENDPOINT_STATS_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const SPEEDTEST_MAX_TRACKED_CLIENTS = 5000;
const SPEEDTEST_MAX_ENDPOINT_STATS = 4096;
const SPEEDTEST_DEFAULT_FALLBACK_ENDPOINTS = [
    '162.159.192.5:2408',
    '162.159.192.1:2408',
    '162.159.195.1:1701',
    '162.159.195.2:908',
    '162.159.192.18:908',
    '162.159.195.1:1843',
    '162.159.192.15:7559',
    'engage.cloudflareclient.com:2408',
    'engage.cloudflareclient.com:1701',
    'engage.cloudflareclient.com:908',
];
const CLASH_PROFILE_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const CLASH_PROFILES = new Map();
const WARP_WIREGUARD_PUBLIC_KEY = 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=';

const DNS_SERVERS = {
    malw_link: '84.21.189.133, 193.23.209.189, 2a12:bec4:1460:294::2, 2a01:ecc0:680:120::2',
    cloudflare: '1.1.1.1, 2606:4700:4700::1111, 1.0.0.1, 2606:4700:4700::1001',
    cloudflare_mal: '1.1.1.2, 2606:4700:4700::1112, 1.0.0.2, 2606:4700:4700::1002',
    google: '8.8.8.8, 2001:4860:4860::8888, 8.8.4.4, 2001:4860:4860::8844',
    adguard: '94.140.14.14, 2a10:50c0::ad1:ff, 94.140.15.15, 2a10:50c0::ad2:ff',
    adguard_family: '94.140.14.15, 2a10:50c0::bad1:ff, 94.140.15.16, 2a10:50c0::bad2:ff',
    adguard_nofilter: '94.140.14.140, 2a10:50c0::1:ff, 94.140.14.141, 2a10:50c0::2:ff',
    yandex: '77.88.8.8, 2a02:6b8::feed:0ff, 77.88.8.1, 2a02:6b8:0:1::feed:0ff',
    yandex_safe: '77.88.8.88, 2a02:6b8::feed:bad, 77.88.8.2, 2a02:6b8:0:1::feed:bad',
    yandex_family: '77.88.8.7, 2a02:6b8::feed:a11, 77.88.8.3, 2a02:6b8:0:1::feed:a11',
    quad9: '9.9.9.9, 2620:fe::fe, 149.112.112.112, 2620:fe::9',
    quad9_ecs: '9.9.9.11, 2620:fe::11, 149.112.112.11, 2620:fe::fe:11',
    quad9_nofilter: '9.9.9.10, 2620:fe::10, 149.112.112.10, 2620:fe::fe:10',
    opendns: '208.67.222.222, 2620:119:35::35, 208.67.220.220, 2620:119:53::53',
    opendns_family: '208.67.222.123, 2620:119:35::123, 208.67.220.123, 2620:119:53::123',
    gcore: '95.85.95.85, 2a03:90c0:999d::1, 2.56.220.2, 2a03:90c0:9992::1',
    dnssb: '185.222.222.222, 2a09::, 45.11.45.11, 2a11::',
    dns0eu: '193.110.81.0, 2a0f:fc80::, 185.253.5.0, 2a0f:fc81::',
    nextdns: '45.90.28.0, 2a07:a8c0::, 45.90.30.0, 2a07:a8c1::',
    mullvad: '194.242.2.2, 2a07:e340::2',
    xbox_dns_ru: 'xbox-dns.ru',
    dns_geohide_ru: 'dns.geohide.ru',
    dns_comss_one: 'dns.comss.one',
};

function splitDnsLineToList(line) {
    return String(line || '')
        .split(',')
        .map((x) => x.trim())
        .filter(Boolean);
}

function createClashDnsProvider({ key, label, group, doh = [], dot = [], doq = [] }) {
    return {
        key,
        label,
        group,
        plain: splitDnsLineToList(DNS_SERVERS[key] || ''),
        doh,
        dot,
        doq,
    };
}

const CLASH_DNS_PROVIDERS = [
    createClashDnsProvider({
        key: 'malw_link',
        label: 'dns.malw.link — разблокировка',
        group: 'Разблокировка внешних сервисов',
        doh: ['https://dns.malw.link/dns-query'],
        dot: ['tls://dns.malw.link'],
    }),
    createClashDnsProvider({
        key: 'xbox_dns_ru',
        label: 'xbox-dns.ru — разблокировка зарубежных сервисов',
        group: 'Разблокировка внешних сервисов',
        doh: ['https://xbox-dns.ru/dns-query'],
        dot: ['tls://xbox-dns.ru'],
    }),
    createClashDnsProvider({
        key: 'dns_geohide_ru',
        label: 'dns.geohide.ru — разблокировка зарубежных сервисов',
        group: 'Разблокировка внешних сервисов',
        doh: ['https://dns.geohide.ru/dns-query'],
        dot: ['tls://dns.geohide.ru'],
    }),
    createClashDnsProvider({
        key: 'dns_comss_one',
        label: 'dns.comss.one — разблокировка зарубежных сервисов',
        group: 'Разблокировка внешних сервисов',
        doh: ['https://dns.comss.one/dns-query'],
        dot: ['tls://dns.comss.one'],
    }),
    createClashDnsProvider({
        key: 'cloudflare',
        label: 'Cloudflare',
        group: 'Без фильтрации — быстрые публичные',
        doh: ['https://1.1.1.1/dns-query', 'https://1.0.0.1/dns-query'],
        dot: ['tls://1.1.1.1', 'tls://1.0.0.1'],
        doq: ['quic://1.1.1.1', 'quic://1.0.0.1'],
    }),
    createClashDnsProvider({
        key: 'google',
        label: 'Google Public DNS',
        group: 'Без фильтрации — быстрые публичные',
        doh: ['https://dns.google/dns-query'],
        dot: ['tls://dns.google'],
    }),
    createClashDnsProvider({
        key: 'quad9_nofilter',
        label: 'Quad9 No Filter',
        group: 'Без фильтрации — быстрые публичные',
        doh: ['https://dns10.quad9.net/dns-query'],
        dot: ['tls://dns10.quad9.net'],
    }),
    createClashDnsProvider({
        key: 'quad9_ecs',
        label: 'Quad9 ECS',
        group: 'Без фильтрации — быстрые публичные',
        doh: ['https://dns11.quad9.net/dns-query'],
        dot: ['tls://dns11.quad9.net'],
    }),
    createClashDnsProvider({
        key: 'opendns',
        label: 'OpenDNS',
        group: 'Без фильтрации — быстрые публичные',
        doh: ['https://doh.opendns.com/dns-query'],
        dot: ['tls://doh.opendns.com'],
    }),
    createClashDnsProvider({
        key: 'gcore',
        label: 'G-Core DNS',
        group: 'Без фильтрации — быстрые публичные',
    }),
    createClashDnsProvider({
        key: 'yandex',
        label: 'Яндекс DNS',
        group: 'Без фильтрации — быстрые публичные',
        dot: ['tls://common.dot.dns.yandex.net'],
    }),
    createClashDnsProvider({
        key: 'adguard',
        label: 'AdGuard (ads+trackers)',
        group: 'Блокировка рекламы и трекеров',
        doh: ['https://dns.adguard-dns.com/dns-query'],
        dot: ['tls://dns.adguard-dns.com'],
        doq: ['quic://dns.adguard-dns.com'],
    }),
    createClashDnsProvider({
        key: 'adguard_nofilter',
        label: 'AdGuard (без фильтрации)',
        group: 'Блокировка рекламы и трекеров',
        doh: ['https://unfiltered.adguard-dns.com/dns-query'],
        dot: ['tls://unfiltered.adguard-dns.com'],
    }),
    createClashDnsProvider({
        key: 'nextdns',
        label: 'NextDNS',
        group: 'Блокировка рекламы и трекеров',
        doh: ['https://dns.nextdns.io'],
        dot: ['tls://dns.nextdns.io'],
        doq: ['quic://dns.nextdns.io'],
    }),
    createClashDnsProvider({
        key: 'cloudflare_mal',
        label: 'Cloudflare Security',
        group: 'Блокировка рекламы и трекеров',
        doh: ['https://security.cloudflare-dns.com/dns-query'],
        dot: ['tls://security.cloudflare-dns.com'],
    }),
    createClashDnsProvider({
        key: 'quad9',
        label: 'Quad9 Security',
        group: 'Блокировка рекламы и трекеров',
        doh: ['https://dns.quad9.net/dns-query'],
        dot: ['tls://dns.quad9.net'],
        doq: ['quic://dns.quad9.net'],
    }),
    createClashDnsProvider({
        key: 'adguard_family',
        label: 'AdGuard Family',
        group: 'Семейный',
        doh: ['https://family.adguard-dns.com/dns-query'],
        dot: ['tls://family.adguard-dns.com'],
    }),
    createClashDnsProvider({
        key: 'yandex_safe',
        label: 'Яндекс Safe',
        group: 'Семейный',
    }),
    createClashDnsProvider({
        key: 'yandex_family',
        label: 'Яндекс Family',
        group: 'Семейный',
    }),
    createClashDnsProvider({
        key: 'opendns_family',
        label: 'OpenDNS Family',
        group: 'Семейный',
        doh: ['https://doh.familyshield.opendns.com/dns-query'],
        dot: ['tls://doh.familyshield.opendns.com'],
    }),
    createClashDnsProvider({
        key: 'mullvad',
        label: 'Mullvad DNS',
        group: 'Privacy / независимые',
        doh: ['https://dns.mullvad.net/dns-query'],
        dot: ['tls://dns.mullvad.net'],
    }),
    createClashDnsProvider({
        key: 'dnssb',
        label: 'DNS.SB',
        group: 'Privacy / независимые',
        doh: ['https://doh.dns.sb/dns-query'],
        dot: ['tls://dns.sb'],
    }),
    createClashDnsProvider({
        key: 'dns0eu',
        label: 'dns0.eu',
        group: 'Privacy / независимые',
        doh: ['https://zero.dns0.eu/dns-query'],
        dot: ['tls://zero.dns0.eu'],
    }),
];

const CLASH_DNS_TRANSPORTS = ['plain', 'doh', 'dot', 'doq', 'mixed'];
const CLASH_DNS_FALLBACK_BY_TRANSPORT = {
    plain: ['1.1.1.1', '9.9.9.9', '8.8.8.8'],
    doh: ['https://1.1.1.1/dns-query', 'https://dns.google/dns-query'],
    dot: ['tls://1.1.1.1', 'tls://9.9.9.9'],
    doq: ['quic://1.1.1.1', 'quic://dns.adguard-dns.com'],
    mixed: ['https://1.1.1.1/dns-query', 'tls://9.9.9.9', '8.8.8.8'],
};

const PROTOCOL_MASK_IP_VALUES = new Set(['quic', 'tls', 'https', 'http2', 'dtls', 'stun', 'random']);
const PROTOCOL_MASK_IB_VALUES = new Set(['firefox', 'chrome', 'edge', 'safari', 'android', 'ios', 'random']);

const CDN_CIDRS = {
    cloudflare: ['104.16.0.0/13', '172.64.0.0/13', '188.114.96.0/20', '162.159.0.0/16', '2606:4700::/32', '2a06:98c0::/29'],
    akamai: ['23.0.0.0/12', '23.32.0.0/11', '23.64.0.0/14', '2600:1400::/24'],
    aws: ['3.0.0.0/8', '13.0.0.0/8', '15.0.0.0/7', '18.0.0.0/8', '35.71.0.0/16'],
    cdn77: ['37.19.192.0/19', '45.64.64.0/22', '2a02:26f0::/32'],
    cogent: ['38.0.0.0/8', '154.54.0.0/16', '2001:550::/32'],
    contabo: ['62.171.0.0/16', '185.217.0.0/16'],
    datacamp: ['89.38.96.0/19', '80.82.64.0/20'],
    digitalocean: ['104.131.0.0/16', '159.65.0.0/16', '167.99.0.0/16', '2a03:b0c0::/32'],
    fastly: ['23.235.32.0/20', '43.249.72.0/22', '2a04:4e42::/32'],
    hetzner: ['49.12.0.0/16', '88.198.0.0/16', '2a01:4f8::/32'],
    oracle: ['129.146.0.0/16', '132.145.0.0/16', '2603:c020::/32'],
    ovh: ['51.68.0.0/16', '54.36.0.0/15', '2001:41d0::/32'],
    roblox: ['128.116.0.0/16', '128.116.64.0/18'],
    scaleway: ['51.15.0.0/16', '62.210.0.0/16', '2001:bc8::/32'],
    vercel: ['76.76.21.0/24', '76.76.22.0/24'],
};

const CLASH_DOMAIN_PRESETS = {
    blocked_sites: [
        'discord.com', 'discord.gg', 'discordapp.net', 'youtube.com', 'googlevideo.com', 'x.com',
        'twitter.com', 't.co', 'instagram.com', 'twitch.tv', 'telegram.org', 't.me',
        'steamcommunity.com', 'steampowered.com', 'steam-chat.com', 'faceit.com', 'open.faceit.com',
        'apexlegends.com', 'ea.com', 'origin.com', 'battle.net', 'blizzard.com',
        'playhearthstone.com', 'pubg.com', 'playbattlegrounds.com', 'krafton.com',
        'whatsapp.com', 'whatsapp.net', 'viber.com', 'tiktok.com', 'tiktokv.com',
        'jetbrains.com', 'download.jetbrains.com', 'plugins.jetbrains.com',
    ],
    ru_direct: ['yandex.ru', 'vk.com', 'rutube.ru', 'gosuslugi.ru', 'sberbank.ru'],
};

const CLIENT_DOWNLOADS = {
    wireguard: {
        title: 'WireGuard',
        links: {
            windows: 'https://download.wireguard.com/windows-client/wireguard-installer.exe',
            macos: 'https://apps.apple.com/us/app/wireguard/id1451685025',
            linux: 'https://www.wireguard.com/install/',
            android: 'https://play.google.com/store/apps/details?id=com.wireguard.android',
            ios: 'https://apps.apple.com/us/app/wireguard/id1451685025',
        },
    },
    amnezia: {
        title: 'AmneziaVPN',
        github: {
            repo: 'amnezia-vpn/amnezia-client',
            platformAssetPatterns: {
                windows: /_x64\.exe$/i,
                macos: /_macos\.pkg$/i,
                linux: /_linux_x64\.tar$/i,
                android: /android9\+_arm64-v8a\.apk$/i,
            },
        },
        links: {
            windows: 'https://github.com/amnezia-vpn/amnezia-client/releases/latest',
            macos: 'https://github.com/amnezia-vpn/amnezia-client/releases/latest',
            linux: 'https://github.com/amnezia-vpn/amnezia-client/releases/latest',
            android: 'https://github.com/amnezia-vpn/amnezia-client/releases/latest',
            ios: 'https://apps.apple.com/us/app/amneziavpn/id1600529900',
        },
    },
    clash_verge: {
        title: 'Clash Verge',
        github: {
            repo: 'clash-verge-rev/clash-verge-rev',
            platformAssetPatterns: {
                windows: /_x64-setup\.exe$/i,
                macos: /_x64\.dmg$/i,
                linux: /_amd64\.deb$/i,
            },
        },
        links: {
            windows: 'https://github.com/clash-verge-rev/clash-verge-rev/releases/latest',
            macos: 'https://github.com/clash-verge-rev/clash-verge-rev/releases/latest',
            linux: 'https://github.com/clash-verge-rev/clash-verge-rev/releases/latest',
            android: 'https://github.com/clash-verge-rev/clash-verge-rev/releases/latest',
            ios: 'https://github.com/clash-verge-rev/clash-verge-rev/releases/latest',
        },
    },
    wiresock: {
        title: 'WireSock',
        links: {
            windows: 'https://www.wiresock.net/wiresock-secure-connect/download',
            macos: 'https://www.wiresock.net/downloads/',
            linux: 'https://www.wiresock.net/downloads/',
            android: 'https://www.wiresock.net/downloads/',
            ios: 'https://www.wiresock.net/downloads/',
        },
    },
};
const CLIENT_DOWNLOAD_CACHE_TTL_MS = 30 * 60 * 1000;
const CLIENT_DOWNLOAD_CACHE = new Map();

const SPLIT_TUNNEL_TARGETS = {
    discord: {
        label: 'Discord',
        domains: ['discord.com', 'canary.discord.com', 'ptb.discord.com', 'discord.co', 'discord.gg', 'dis.gd', 'discord.new', 'discord.store', 'discordapp.net', 'discordapp.io', 'discordcdn.com', 'api.discord.gg', 'gateway.discord.gg', 'voice.discord.gg', 'rtc.discord.gg', 'discordapp.com', 'updates.discord.com', 'dl.discordapp.net', 'dl2.discordapp.net', 'stable.dl2.discordapp.net', 'cdn.discordapp.com', 'cdn.discordapp.net', 'media.discordapp.net', 'images-ext-1.discordapp.net', 'images-ext-2.discordapp.net', 'router.discordapp.net', 'discord-attachments-uploads-prd.storage.googleapis.com', 'discord.media', 'discord.tools', 'meticulous-ingest.discord.tools', 'discordsays.com', 'best.discord.media', 'latency.discord.media', 'status.discord.com', 'status.discordapp.com', 'support.discord.com', 'support.discordapp.com', 'discordstatus.com', 'discord-activities.com', 'discordactivities.com', 'discord.design', 'discord.dev', 'discord.gift', 'discord.gifts', 'discordmerch.com', 'discordpartygames.com', 'gateway-us-east1-b.discord.gg', 'gateway-us-east1-c.discord.gg', 'gateway-us-east1-d.discord.gg'],
        cidrs: ['162.159.128.0/19', '162.159.136.0/22', '188.114.96.0/20', '104.16.0.0/13', '172.64.0.0/13', '2606:4700::/32', '2a06:98c0::/29'],
    },
    youtube: { label: 'YouTube', domains: ['youtube.com', 'www.youtube.com', 'youtu.be', 'googlevideo.com', 'i.ytimg.com', 's.ytimg.com'] },
    x_com: { label: 'X.com', domains: ['x.com', 'api.x.com', 'twitter.com', 't.co', 'pbs.twimg.com', 'video.twimg.com', 'abs.twimg.com'] },
    instagram: { label: 'Instagram', domains: ['instagram.com', 'www.instagram.com', 'ig.me', 'scontent.cdninstagram.com'] },
    twitch: { label: 'Twitch', domains: ['twitch.tv', 'www.twitch.tv', 'gql.twitch.tv', 'usher.ttvnw.net', 'static-cdn.jtvnw.net'] },
    telegram: { label: 'Telegram', domains: ['telegram.org', 't.me', 'telegram.me', 'tdesktop.com'] },
    steam: { label: 'Steam', domains: ['steampowered.com', 'store.steampowered.com', 'api.steampowered.com', 'steamcommunity.com', 'steam-chat.com', 'community.cloudflare.steamstatic.com', 'cdn.cloudflare.steamstatic.com'], processes: ['steam.exe', 'steamwebhelper.exe'] },
    faceit: { label: 'FACEIT', domains: ['faceit.com', 'www.faceit.com', 'open.faceit.com', 'api.faceit.com', 'anticheat-client.faceit.com', 'cdn.faceit.com'], cidrs: ['185.69.168.0/24', '193.41.200.0/24', '77.80.253.0/24', '77.80.254.0/24', '77.80.255.0/24', '2a05:2240::/32'], processes: ['faceit.exe', 'FaceitClient.exe'] },
    whatsapp: { label: 'WhatsApp', domains: ['whatsapp.com', 'whatsapp.net'] },
    viber: { label: 'Viber', domains: ['viber.com', 'download.cdn.viber.com', 'dl-media.viber.com'] },
    jetbrains: { label: 'JetBrains', domains: ['jetbrains.com', 'download.jetbrains.com', 'plugins.jetbrains.com', 'account.jetbrains.com'] },
    tiktok: { label: 'TikTok', domains: ['tiktok.com', 'www.tiktok.com', 'm.tiktok.com', 'tiktokv.com', 'api.tiktokv.com', 'v16-webapp.tiktok.com'] },
    ipcheck_2ip: { label: '2IP', domains: ['2ip.ru', '2ip.io', 'www.2ip.ru', 'www.2ip.io'] },
    speedtest: { label: 'Speedtest', domains: ['speedtest.com', 'speedtest.net', 'www.speedtest.net', 'ookla.com'] },
    fast_com: { label: 'Fast.com', domains: ['fast.com', 'api.fast.com', 'netflix.com', 'www.netflix.com', 'nflxvideo.net', 'assets.nflxext.com'] },
    whoer: { label: 'Whoer', domains: ['whoer.net', 'www.whoer.net'] },
    geosite_ru: {
        label: 'geosite:ru (core)',
        domains: [
            'yandex.ru', 'ya.ru', 'vk.com', 'mail.ru', 'ok.ru', 'dzen.ru', 'rutube.ru', 'avito.ru', 'gosuslugi.ru',
            'sberbank.ru', 'alfabank.ru', 'tbank.ru', 'vtb.ru', 'ozon.ru', 'wildberries.ru', 'cdek.ru', 'pochta.ru',
            'rbc.ru', 'lenta.ru', 'gazeta.ru', 'ria.ru', 'tass.ru', 'kommersant.ru', 'championat.com', 'sports.ru',
            'kinopoisk.ru', 'ivi.ru', 'okko.tv', 'yoomoney.ru', 'qiwi.com', 'consultant.ru', 'garant.ru',
            'nalog.gov.ru', 'mos.ru', 'moex.com', 'hh.ru', '2gis.ru', 'pikabu.ru', 'habr.com', 'yaplakal.com',
        ],
    },
    apex_legends: { label: 'Apex Legends', domains: ['apexlegends.com', 'www.playapex.com', 'respawn.com', 'ea.com', 'www.ea.com', 'origin.com', 'accounts.ea.com', 'gateway.ea.com', 'api1.origin.com', 'download.dm.origin.com', 'origin-a.akamaihd.net'], processes: ['r5apex.exe', 'EADesktop.exe'] },
    ea_app: { label: 'EA App', domains: ['ea.com', 'www.ea.com', 'origin.com', 'accounts.ea.com', 'gateway.ea.com', 'api1.origin.com', 'download.dm.origin.com', 'origin-a.akamaihd.net', 'eaassets-a.akamaihd.net'], processes: ['EADesktop.exe', 'EALauncher.exe', 'EADM.exe'] },
    battle_net: { label: 'Battle.net', domains: ['battle.net', 'www.battle.net', 'blizzard.com', 'www.blizzard.com', 'us.patch.battle.net', 'eu.patch.battle.net', 'blzddist1-a.akamaihd.net'], processes: ['Battle.net.exe', 'BlizzardBrowserHelper.exe'] },
    cs2: { label: 'CS2', domains: ['steampowered.com', 'store.steampowered.com', 'api.steampowered.com', 'steamcommunity.com', 'steam-chat.com', 'community.cloudflare.steamstatic.com', 'cdn.cloudflare.steamstatic.com', 'valvesoftware.com', 'www.valvesoftware.com', 'cm0.steampowered.com'], cidrs: ['45.121.184.0/22', '63.150.138.0/24', '103.10.124.0/23', '103.28.54.0/23', '146.66.152.0/21', '155.133.224.0/19', '162.254.192.0/21', '185.25.180.0/22', '190.216.121.0/24', '190.217.33.0/24', '192.69.96.0/22', '205.196.6.0/24', '208.64.200.0/22', '208.78.164.0/22'], processes: ['cs2.exe'] },
    hearthstone: { label: 'Hearthstone', domains: ['battle.net', 'www.battle.net', 'blizzard.com', 'www.blizzard.com', 'us.patch.battle.net', 'eu.patch.battle.net', 'blzddist1-a.akamaihd.net'], processes: ['Hearthstone.exe'] },
    pubg: { label: 'PUBG', domains: ['pubg.com', 'www.pubg.com', 'api.pubg.com', 'accounts.pubg.com', 'krafton.com', 'www.krafton.com', 'pubgmobile.com', 'www.pubgmobile.com', 'steamcdn-a.akamaihd.net'], processes: ['TslGame.exe', 'TslGame-EAC.exe'] },
    chatgpt: {
        label: 'ChatGPT (OpenAI)',
        domains: [
            'openai.com', 'www.openai.com', 'api.openai.com', 'auth.openai.com',
            'cdn.openai.com', 'platform.openai.com', 'help.openai.com', 'labs.openai.com',
            'chatgpt.com', 'chat.openai.com', 'oaistatic.com', 'oaiusercontent.com',
            'openaiapi-site.azureedge.net', 'sora.com', 'operator.chatgpt.com',
        ],
        cidrs: ['104.16.0.0/13', '172.64.0.0/13', '188.114.96.0/20', '2606:4700::/32'],
    },
    claude_ai: {
        label: 'Claude (Anthropic)',
        domains: [
            'anthropic.com', 'www.anthropic.com', 'api.anthropic.com',
            'console.anthropic.com', 'claude.ai', 'www.claude.ai', 'userprompt.com',
        ],
        cidrs: ['104.16.0.0/13', '172.64.0.0/13', '188.114.96.0/20', '2606:4700::/32'],
    },
    gemini: {
        label: 'Gemini (Google AI)',
        domains: [
            'gemini.google.com', 'aistudio.google.com', 'ai.google.dev', 'ai.google',
            'generativelanguage.googleapis.com', 'vertexai.googleapis.com',
            'makersuite.google.com', 'deepmind.com', 'www.deepmind.com',
            'notebooklm.google.com', 'labs.google',
        ],
        cidrs: ['142.250.0.0/15', '172.217.0.0/16', '216.58.0.0/15', '74.125.0.0/16', '2607:f8b0::/32'],
    },
    grok: {
        label: 'Grok (xAI)',
        domains: ['x.ai', 'grok.com', 'api.x.ai', 'accounts.x.ai'],
        cidrs: ['104.21.0.0/16', '172.67.0.0/16', '188.114.96.0/20', '2606:4700::/32'],
    },
};

// Fallback CIDR database for domains that frequently return no A/AAAA (ENODATA)
// even though app traffic still goes via known provider edge ranges.
const CF_DISCORD_CIDRS = ['162.159.128.0/19', '162.159.136.0/22', '188.114.96.0/20', '104.16.0.0/13', '172.64.0.0/13', '2606:4700::/32', '2a06:98c0::/29'];
const CF_ONLY_CIDRS = ['104.16.0.0/13', '172.64.0.0/13', '188.114.96.0/20', '2606:4700::/32'];

const STATIC_DOMAIN_FALLBACK_CIDRS = {
    // Discord — Cloudflare-hosted
    'best.discord.media':               CF_DISCORD_CIDRS,
    'cdn.discordapp.net':               CF_DISCORD_CIDRS,
    'router.discordapp.net':            CF_DISCORD_CIDRS,
    'discord.tools':                    CF_DISCORD_CIDRS,
    'discord-activities.com':           CF_DISCORD_CIDRS,
    'discordapp.net':                   CF_DISCORD_CIDRS,
    'api.discord.gg':                   CF_DISCORD_CIDRS,
    'voice.discord.gg':                 CF_DISCORD_CIDRS,
    'rtc.discord.gg':                   CF_DISCORD_CIDRS,
    'gateway.discord.gg':               CF_DISCORD_CIDRS,
    'discordapp.io':                    CF_DISCORD_CIDRS,
    'discordcdn.com':                   CF_DISCORD_CIDRS,
    'discord.media':                    CF_DISCORD_CIDRS,
    'latency.discord.media':            CF_DISCORD_CIDRS,
    'meticulous-ingest.discord.tools':  CF_DISCORD_CIDRS,
    'discordactivities.com':            CF_DISCORD_CIDRS,
    'discordsays.com':                  CF_DISCORD_CIDRS,
    // AI services — Cloudflare-hosted
    'openai.com':                       CF_ONLY_CIDRS,
    'www.openai.com':                   CF_ONLY_CIDRS,
    'api.openai.com':                   CF_ONLY_CIDRS,
    'auth.openai.com':                  CF_ONLY_CIDRS,
    'cdn.openai.com':                   CF_ONLY_CIDRS,
    'platform.openai.com':              CF_ONLY_CIDRS,
    'chatgpt.com':                      CF_ONLY_CIDRS,
    'chat.openai.com':                  CF_ONLY_CIDRS,
    'oaistatic.com':                    CF_ONLY_CIDRS,
    'oaiusercontent.com':               CF_ONLY_CIDRS,
    'sora.com':                         CF_ONLY_CIDRS,
    'operator.chatgpt.com':             CF_ONLY_CIDRS,
    'anthropic.com':                    CF_ONLY_CIDRS,
    'www.anthropic.com':                CF_ONLY_CIDRS,
    'api.anthropic.com':                CF_ONLY_CIDRS,
    'console.anthropic.com':            CF_ONLY_CIDRS,
    'claude.ai':                        CF_ONLY_CIDRS,
    'www.claude.ai':                    CF_ONLY_CIDRS,
    'userprompt.com':                   CF_ONLY_CIDRS,
    'x.ai':                             CF_ONLY_CIDRS,
    'grok.com':                         CF_ONLY_CIDRS,
    'api.x.ai':                         CF_ONLY_CIDRS,
    'accounts.x.ai':                    CF_ONLY_CIDRS,
};

// Runtime cache keeps last known IPs for domains that resolved successfully.
// If DNS later fails, these cached CIDRs are used as fallback.
const SPLIT_DOMAIN_RUNTIME_CACHE = new Map();
const DNS_RESOLVE_CACHE = new Map();
const DNS_RESOLVE_INFLIGHT = new Map();

function cleanupDnsResolveCache() {
    const now = Date.now();
    for (const [key, entry] of DNS_RESOLVE_CACHE.entries()) {
        if (!entry || (entry.expiresAt || 0) <= now) DNS_RESOLVE_CACHE.delete(key);
    }
    if (DNS_RESOLVE_CACHE.size <= DNS_MAX_CACHE_ENTRIES) return;
    const overflow = DNS_RESOLVE_CACHE.size - DNS_MAX_CACHE_ENTRIES;
    const oldest = Array.from(DNS_RESOLVE_CACHE.entries())
        .sort((a, b) => (a[1]?.storedAt || 0) - (b[1]?.storedAt || 0))
        .slice(0, overflow)
        .map(([key]) => key);
    for (const key of oldest) DNS_RESOLVE_CACHE.delete(key);
}

function mapLimit(items, limit, iterator) {
    return new Promise((resolve, reject) => {
        const arr = Array.isArray(items) ? items : [];
        const max = Math.max(1, Number.parseInt(String(limit || 1), 10) || 1);
        if (!arr.length) {
            resolve([]);
            return;
        }
        const results = new Array(arr.length);
        let inFlight = 0;
        let nextIndex = 0;
        let done = 0;
        let aborted = false;

        const pump = () => {
            if (aborted) return;
            while (inFlight < max && nextIndex < arr.length) {
                const idx = nextIndex++;
                inFlight += 1;
                Promise.resolve(iterator(arr[idx], idx))
                    .then((value) => {
                        results[idx] = value;
                        inFlight -= 1;
                        done += 1;
                        if (done >= arr.length) resolve(results);
                        else pump();
                    })
                    .catch((err) => {
                        aborted = true;
                        reject(err);
                    });
            }
        };

        pump();
    });
}

async function resolveDomainRecordsCached(hostname) {
    const host = String(hostname || '').trim().toLowerCase();
    if (!host || !isDnsHostname(host)) return { v4: [], v6: [] };

    const now = Date.now();
    const cached = DNS_RESOLVE_CACHE.get(host);
    if (cached && cached.expiresAt > now) {
        return {
            v4: Array.isArray(cached.v4) ? cached.v4.slice() : [],
            v6: Array.isArray(cached.v6) ? cached.v6.slice() : [],
        };
    }

    const inFlight = DNS_RESOLVE_INFLIGHT.get(host);
    if (inFlight) return inFlight;

    const task = (async () => {
        const [a4, a6] = await Promise.allSettled([dns.resolve4(host), dns.resolve6(host)]);
        const v4 = a4.status === 'fulfilled'
            ? a4.value.filter((ip) => net.isIP(ip) === 4)
            : [];
        const v6 = a6.status === 'fulfilled'
            ? a6.value.filter((ip) => net.isIP(ip) === 6)
            : [];

        const positive = v4.length > 0 || v6.length > 0;
        const ttl = positive ? DNS_CACHE_TTL_MS : DNS_NEGATIVE_CACHE_TTL_MS;
        DNS_RESOLVE_CACHE.set(host, {
            v4,
            v6,
            storedAt: Date.now(),
            expiresAt: Date.now() + ttl,
        });
        cleanupDnsResolveCache();
        return { v4: v4.slice(), v6: v6.slice() };
    })();

    DNS_RESOLVE_INFLIGHT.set(host, task);
    try {
        return await task;
    } finally {
        DNS_RESOLVE_INFLIGHT.delete(host);
    }
}

function cacheDomainCidrs(domain, cidrList) {
    if (!domain || !Array.isArray(cidrList) || !cidrList.length) return;
    const existing = SPLIT_DOMAIN_RUNTIME_CACHE.get(domain) || new Set();
    for (const cidr of cidrList) {
        if (typeof cidr === 'string' && cidr.trim()) existing.add(cidr.trim());
        if (existing.size >= SPLIT_RUNTIME_MAX_CIDRS_PER_DOMAIN) break;
    }
    if (!existing.size) return;
    SPLIT_DOMAIN_RUNTIME_CACHE.set(domain, existing);
    while (SPLIT_DOMAIN_RUNTIME_CACHE.size > SPLIT_RUNTIME_MAX_DOMAINS) {
        const oldest = SPLIT_DOMAIN_RUNTIME_CACHE.keys().next();
        if (oldest.done) break;
        SPLIT_DOMAIN_RUNTIME_CACHE.delete(oldest.value);
    }
}

function getDomainFallbackCidrs(domain) {
    const merged = new Set();
    const staticCidrs = STATIC_DOMAIN_FALLBACK_CIDRS[domain];
    if (Array.isArray(staticCidrs)) {
        for (const cidr of staticCidrs) {
            if (typeof cidr === 'string' && cidr.trim()) merged.add(cidr.trim());
        }
    }
    const cached = SPLIT_DOMAIN_RUNTIME_CACHE.get(domain);
    if (cached) {
        for (const cidr of cached.values()) merged.add(cidr);
    }
    return Array.from(merged);
}

async function resolveHost(host) {
    if (!host || net.isIP(host)) return host || '162.159.192.1';
    try {
        const { v4 } = await resolveDomainRecordsCached(host);
        return v4[0] || '162.159.192.1';
    } catch { return '162.159.192.1'; }
}

function normalizeInterfaceAddress(rawAddress) {
    if (typeof rawAddress !== 'string') return '';
    const value = rawAddress.trim();
    if (!value) return '';
    if (value.includes('/')) return value;
    const ipType = net.isIP(value);
    if (ipType === 4) return `${value}/32`;
    if (ipType === 6) return `${value}/128`;
    return value;
}

function dnsServersToCidrs(dnsLine) {
    if (typeof dnsLine !== 'string' || !dnsLine.trim()) return [];
    const cidrs = new Set();
    for (const raw of dnsLine.split(',')) {
        const host = raw.trim();
        if (!host) continue;
        const ipType = net.isIP(host);
        if (ipType === 4) cidrs.add(`${host}/32`);
        if (ipType === 6) cidrs.add(`${host}/128`);
    }
    return Array.from(cidrs);
}

function isDnsHostname(value) {
    const host = String(value || '').trim();
    if (!host) return false;
    if (net.isIP(host)) return false;
    return /^[a-z0-9.-]+$/i.test(host) && host.includes('.');
}

async function resolveDnsHostToIps(hostname) {
    const host = String(hostname || '').trim();
    if (!isDnsHostname(host)) return [];
    const { v4, v6 } = await resolveDomainRecordsCached(host);
    return Array.from(new Set([...(v4 || []), ...(v6 || [])]));
}

async function normalizeDnsLineForConfig(dnsLine) {
    if (typeof dnsLine !== 'string' || !dnsLine.trim()) return DNS_SERVERS.malw_link;
    const tokens = splitDnsLineToList(dnsLine);
    const expanded = [];
    const uniqueHosts = Array.from(new Set(tokens.filter((token) => isDnsHostname(token))));
    const resolvedHosts = new Map();

    await mapLimit(uniqueHosts, Math.min(DNS_RESOLVE_CONCURRENCY, 12), async (host) => {
        const ips = await resolveDnsHostToIps(host);
        resolvedHosts.set(host, ips);
    });

    for (const token of tokens) {
        const value = token.trim();
        if (!value) continue;
        const ipType = net.isIP(value);
        if (ipType === 4 || ipType === 6) {
            expanded.push(value);
            continue;
        }
        if (isDnsHostname(value)) {
            const ips = resolvedHosts.get(value) || [];
            if (ips.length) {
                expanded.push(...ips.slice(0, 4));
                continue;
            }
        }
    }

    const unique = Array.from(new Set(expanded));
    if (unique.length) return unique.join(', ');
    return DNS_SERVERS.malw_link;
}

function normalizeProtocolMaskField(rawValue, { fallback = '', maxLength = 128, allowed = null } = {}) {
    const value = typeof rawValue === 'string' ? rawValue.trim() : '';
    if (!value) return fallback;
    const normalized = value.toLowerCase();
    if (allowed instanceof Set && !allowed.has(normalized)) return fallback;
    return normalized.slice(0, maxLength);
}

function normalizeSplitTargets(splitTargets) {
    if (!Array.isArray(splitTargets)) return [];
    const uniq = new Set();
    for (const raw of splitTargets) {
        if (typeof raw !== 'string') continue;
        const key = raw.trim();
        if (!key || !SPLIT_TUNNEL_TARGETS[key]) continue;
        uniq.add(key);
    }
    return Array.from(uniq);
}

async function resolveSplitAllowedIPs(targetKeys) {
    const cidrs = new Set();
    const domains = new Set();

    for (const key of targetKeys) {
        const target = SPLIT_TUNNEL_TARGETS[key];
        if (!target) continue;
        for (const domain of target.domains || []) {
            if (typeof domain !== 'string') continue;
            const clean = domain.trim().toLowerCase();
            if (clean) domains.add(clean);
        }
        for (const cidr of target.cidrs || []) {
            if (typeof cidr === 'string' && cidr.trim()) cidrs.add(cidr.trim());
        }
    }

    const unresolvedDomains = [];
    const fallbackDomains = [];

    await mapLimit(Array.from(domains), DNS_RESOLVE_CONCURRENCY, async (domain) => {
        const ipType = net.isIP(domain);
        if (ipType === 4) {
            cidrs.add(`${domain}/32`);
            return;
        }
        if (ipType === 6) {
            cidrs.add(`${domain}/128`);
            return;
        }

        const { v4, v6 } = await resolveDomainRecordsCached(domain);
        let resolved = false;

        if (v4.length) {
            const resolved4 = v4.map(ip => `${ip}/32`);
            for (const cidr of resolved4) cidrs.add(cidr);
            cacheDomainCidrs(domain, resolved4);
            resolved = true;
        }
        if (v6.length) {
            const resolved6 = v6.map(ip => `${ip}/128`);
            for (const cidr of resolved6) cidrs.add(cidr);
            cacheDomainCidrs(domain, resolved6);
            resolved = true;
        }
        if (!resolved) {
            const fallback = getDomainFallbackCidrs(domain);
            if (fallback.length > 0) {
                for (const cidr of fallback) cidrs.add(cidr);
                fallbackDomains.push(domain);
            } else {
                unresolvedDomains.push(domain);
            }
        }
    });

    return {
        allowedIps: Array.from(cidrs).sort((a, b) => a.localeCompare(b)),
        unresolvedDomains: unresolvedDomains.sort((a, b) => a.localeCompare(b)),
        fallbackDomains: fallbackDomains.sort((a, b) => a.localeCompare(b)),
        sourceDomains: domains.size,
    };
}

function normalizeEndpointInput(value) {
    if (typeof value !== 'string') return '';
    return value.trim().toLowerCase();
}

function normalizePortInput(value) {
    const port = Number.parseInt(String(value), 10);
    if (!Number.isInteger(port)) return null;
    return port;
}

function isAllowedWarpEndpoint(value) {
    if (!value) return false;
    if (value === 'auto') return true;
    return ALLOWED_WARP_ENDPOINT_SET.has(value);
}

function isAllowedWarpPort(value) {
    if (!Number.isInteger(value)) return false;
    return ALLOWED_WARP_PORT_SET.has(value);
}

function isAllowedWarpResultIp(ip) {
    if (net.isIP(ip) !== 4) return false;
    const parts = ip.split('.').map((x) => Number.parseInt(x, 10));
    if (parts.length !== 4 || parts.some((x) => Number.isNaN(x))) return false;
    if (parts[0] !== 162 || parts[1] !== 159) return false;
    if (parts[2] === 192 && parts[3] >= 1 && parts[3] <= 20) return true;
    if (parts[2] === 195 && parts[3] >= 1 && parts[3] <= 10) return true;
    return false;
}

function isAllowedWarpResultHost(host) {
    if (typeof host !== 'string') return false;
    return host.trim().toLowerCase() === 'engage.cloudflareclient.com';
}

function parseEndpointHostPort(rawValue) {
    if (typeof rawValue !== 'string') return null;
    const clean = rawValue.trim();
    const match = clean.match(/^([^:]+):(\d{2,5})$/);
    if (!match) return null;
    const host = match[1].trim();
    const port = Number.parseInt(match[2], 10);
    if (!host || !Number.isInteger(port)) return null;
    return { host, port };
}

function normalizeIpCandidate(rawValue) {
    const value = String(rawValue || '').trim();
    if (!value) return '';
    if (net.isIP(value)) return value;
    const mapped = value.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
    if (mapped && net.isIP(mapped[1]) === 4) return mapped[1];
    return '';
}

function getClientIp(req) {
    if (TRUST_PROXY_ENABLED) {
        const xff = req.headers['x-forwarded-for'];
        if (typeof xff === 'string' && xff.trim()) {
            const firstHop = normalizeIpCandidate(xff.split(',')[0].trim());
            if (firstHop) return firstHop;
        }
    }
    const direct = normalizeIpCandidate(req.ip) || normalizeIpCandidate(req.socket?.remoteAddress);
    return direct || '';
}

const outboundUtils = createOutboundUtils({
    trustProxyEnabled: TRUST_PROXY_ENABLED,
    publicBaseUrl: PUBLIC_BASE_URL,
    outboundRequestTimeoutMs: OUTBOUND_REQUEST_TIMEOUT_MS,
    outboundRequestRetries: OUTBOUND_REQUEST_RETRIES,
    outboundRequestRetryBaseMs: OUTBOUND_REQUEST_RETRY_BASE_MS,
    downloadProxyTimeoutMs: DOWNLOAD_PROXY_TIMEOUT_MS,
    downloadProxyMaxBytes: DOWNLOAD_PROXY_MAX_BYTES,
    isRetryableStatus,
    isRetryableNetworkError,
    sleep,
    isDnsHostname,
});
const {
    getRequestBaseUrl,
    assertSafeImportUrl,
    assertSafeDownloadUrl,
    fetchRemoteText,
    proxyRemoteDownload,
    githubApiJson,
} = outboundUtils;

const rateLimitManager = createRateLimitManager({
    getClientIp,
    defaultWindowMs: RATE_LIMIT_WINDOW_MS,
    maxEntries: RATE_LIMIT_MAX_ENTRIES,
});
const { createRateLimitMiddleware, cleanupRateLimitState } = rateLimitManager;

const rateLimitGenerate = createRateLimitMiddleware({
    key: 'generate',
    maxPerWindow: RATE_LIMIT_GENERATE_MAX,
});
const rateLimitLicenseCheck = createRateLimitMiddleware({
    key: 'license-check',
    maxPerWindow: RATE_LIMIT_LICENSE_CHECK_MAX,
});
const rateLimitTestLicense = createRateLimitMiddleware({
    key: 'test-license',
    maxPerWindow: RATE_LIMIT_TEST_LICENSE_MAX,
});
const rateLimitClientDownload = createRateLimitMiddleware({
    key: 'client-download',
    maxPerWindow: RATE_LIMIT_DOWNLOAD_MAX,
});

const clashUtils = createClashUtils({
    warpWireguardPublicKey: WARP_WIREGUARD_PUBLIC_KEY,
    normalizeInterfaceAddress,
    isDnsHostname,
});
const {
    normalizeImportedConfigText,
    parseClashImportConfig,
    sanitizeProfileName,
    validateClashNode,
    buildClashYaml,
} = clashUtils;

function normalizeClientPlatform(value) {
    const raw = typeof value === 'string' ? value.trim().toLowerCase() : '';
    if (['windows', 'macos', 'linux', 'android', 'ios'].includes(raw)) return raw;
    return 'windows';
}

function parseDottedVersion(value) {
    return String(value || '')
        .split('.')
        .map((part) => Number.parseInt(part, 10))
        .map((num) => (Number.isFinite(num) ? num : 0));
}

function compareDottedVersions(a, b) {
    const left = parseDottedVersion(a);
    const right = parseDottedVersion(b);
    const length = Math.max(left.length, right.length);
    for (let i = 0; i < length; i += 1) {
        const l = left[i] || 0;
        const r = right[i] || 0;
        if (l > r) return 1;
        if (l < r) return -1;
    }
    return 0;
}

async function resolveWireSockWindowsDirectUrl() {
    const cacheKey = 'wiresock:windows:direct';
    const cached = CLIENT_DOWNLOAD_CACHE.get(cacheKey);
    if (cached && (Date.now() - cached.ts) < CLIENT_DOWNLOAD_CACHE_TTL_MS) return cached.url;

    const landingUrl = CLIENT_DOWNLOADS?.wiresock?.links?.windows;
    if (!landingUrl) return null;
    const safeLanding = await assertSafeDownloadUrl(landingUrl);
    const html = await fetchRemoteText(safeLanding, 0, 2 * 1024 * 1024);

    const regex = /https:\/\/wiresock\.net\/_api\/download-release\.php\?product=wiresock-secure-connect(?:&amp;|&)platform=windows_x64(?:&amp;|&)version=([0-9.]+)/gi;
    const candidates = [];
    let match;
    while ((match = regex.exec(html)) !== null) {
        const rawUrl = String(match[0] || '').replace(/&amp;/g, '&');
        const version = String(match[1] || '').trim();
        if (rawUrl && version) candidates.push({ rawUrl, version });
    }
    if (!candidates.length) return null;

    candidates.sort((a, b) => compareDottedVersions(b.version, a.version));
    const resolved = candidates[0].rawUrl;
    CLIENT_DOWNLOAD_CACHE.set(cacheKey, { ts: Date.now(), url: resolved });
    return resolved;
}

async function resolveGithubLatestAsset(appKey, appMeta, platform) {
    const repo = appMeta?.github?.repo;
    const pattern = appMeta?.github?.platformAssetPatterns?.[platform];
    if (!repo || !pattern) return null;
    const cacheKey = `${appKey}:${platform}`;
    const cached = CLIENT_DOWNLOAD_CACHE.get(cacheKey);
    if (cached && (Date.now() - cached.ts) < CLIENT_DOWNLOAD_CACHE_TTL_MS) return cached.url;

    const release = await githubApiJson(`/repos/${repo}/releases/latest`);
    const assets = Array.isArray(release?.assets) ? release.assets : [];
    const asset = assets.find((x) => pattern.test(String(x?.name || '')));
    const url = asset?.browser_download_url || null;
    if (url) CLIENT_DOWNLOAD_CACHE.set(cacheKey, { ts: Date.now(), url });
    return url;
}

async function resolveClientDownloadUrl(appKey, platform) {
    const appMeta = CLIENT_DOWNLOADS[appKey];
    if (!appMeta) return null;

    if (appKey === 'wiresock' && platform === 'windows') {
        try {
            const direct = await resolveWireSockWindowsDirectUrl();
            if (direct) return direct;
        } catch {
            // fallback below
        }
    }

    let url = null;
    try {
        url = await resolveGithubLatestAsset(appKey, appMeta, platform);
    } catch {
        url = null;
    }
    if (url) return url;
    return appMeta.links?.[platform] || appMeta.links?.windows || null;
}

function cleanupSpeedtestSessions() {
    const now = Date.now();
    for (const [id, session] of SPEEDTEST_SESSIONS.entries()) {
        if (now - session.createdAt > SPEEDTEST_SESSION_TTL_MS) {
            SPEEDTEST_SESSIONS.delete(id);
        }
    }
    cleanupSpeedtestAdaptiveState();
}

function normalizeSpeedtestClientKey(clientIp) {
    return typeof clientIp === 'string' ? clientIp.trim() : '';
}

function touchSpeedtestClientKey(clientIp) {
    const key = normalizeSpeedtestClientKey(clientIp);
    if (!key) return '';
    SPEEDTEST_IP_TOUCH_TS.set(key, Date.now());
    return key;
}

function cleanupSpeedtestAdaptiveState() {
    const now = Date.now();

    for (const [clientKey, touchedAt] of SPEEDTEST_IP_TOUCH_TS.entries()) {
        if ((now - touchedAt) <= SPEEDTEST_IP_STATE_TTL_MS) continue;
        SPEEDTEST_IP_TOUCH_TS.delete(clientKey);
        SPEEDTEST_LAST_GOOD_BY_IP.delete(clientKey);
        SPEEDTEST_FALLBACK_CURSOR_BY_IP.delete(clientKey);
    }

    for (const [endpoint, state] of SPEEDTEST_ENDPOINT_STATS.entries()) {
        const lastSeen = Number.parseInt(String(state?.lastSeen || 0), 10);
        if (Number.isFinite(lastSeen) && (now - lastSeen) <= SPEEDTEST_ENDPOINT_STATS_TTL_MS) continue;
        SPEEDTEST_ENDPOINT_STATS.delete(endpoint);
    }

    if (SPEEDTEST_IP_TOUCH_TS.size > SPEEDTEST_MAX_TRACKED_CLIENTS) {
        const overflow = SPEEDTEST_IP_TOUCH_TS.size - SPEEDTEST_MAX_TRACKED_CLIENTS;
        const oldest = Array.from(SPEEDTEST_IP_TOUCH_TS.entries())
            .sort((a, b) => a[1] - b[1])
            .slice(0, overflow)
            .map(([clientKey]) => clientKey);
        for (const clientKey of oldest) {
            SPEEDTEST_IP_TOUCH_TS.delete(clientKey);
            SPEEDTEST_LAST_GOOD_BY_IP.delete(clientKey);
            SPEEDTEST_FALLBACK_CURSOR_BY_IP.delete(clientKey);
        }
    }

    if (SPEEDTEST_ENDPOINT_STATS.size > SPEEDTEST_MAX_ENDPOINT_STATS) {
        const overflow = SPEEDTEST_ENDPOINT_STATS.size - SPEEDTEST_MAX_ENDPOINT_STATS;
        const oldestLeastPopular = Array.from(SPEEDTEST_ENDPOINT_STATS.entries())
            .sort((a, b) => {
                const hitsDiff = (a[1]?.hits || 0) - (b[1]?.hits || 0);
                if (hitsDiff !== 0) return hitsDiff;
                return (a[1]?.lastSeen || 0) - (b[1]?.lastSeen || 0);
            })
            .slice(0, overflow)
            .map(([endpoint]) => endpoint);
        for (const endpoint of oldestLeastPopular) {
            SPEEDTEST_ENDPOINT_STATS.delete(endpoint);
        }
    }
}

function normalizeEndpointForStats(endpoint) {
    const parsed = parseEndpointHostPort(endpoint);
    if (!parsed) return null;
    if (!isAllowedWarpPort(parsed.port)) return null;
    const hostAllowed = isAllowedWarpResultIp(parsed.host) || isAllowedWarpResultHost(parsed.host);
    if (!hostAllowed) return null;
    return `${parsed.host}:${parsed.port}`;
}

function recordSpeedtestEndpointStat(clientIp, endpoint) {
    const normalized = normalizeEndpointForStats(endpoint);
    if (!normalized) return;
    const clientKey = touchSpeedtestClientKey(clientIp);
    if (clientKey) {
        SPEEDTEST_LAST_GOOD_BY_IP.set(clientKey, normalized);
    }
    const current = SPEEDTEST_ENDPOINT_STATS.get(normalized) || { hits: 0, lastSeen: 0 };
    current.hits += 1;
    current.lastSeen = Date.now();
    SPEEDTEST_ENDPOINT_STATS.set(normalized, current);
}

function getRotatedDefaultFallbackEndpoints(clientIp) {
    const defaults = SPEEDTEST_DEFAULT_FALLBACK_ENDPOINTS.filter((endpoint) => !!normalizeEndpointForStats(endpoint));
    if (!defaults.length) return [];

    const key = touchSpeedtestClientKey(clientIp);
    if (!key) return defaults;

    const cursor = Number.parseInt(String(SPEEDTEST_FALLBACK_CURSOR_BY_IP.get(key) || 0), 10);
    const safeCursor = Number.isFinite(cursor) ? cursor : 0;
    const start = ((safeCursor % defaults.length) + defaults.length) % defaults.length;
    SPEEDTEST_FALLBACK_CURSOR_BY_IP.set(key, (start + 1) % defaults.length);
    return defaults.slice(start).concat(defaults.slice(0, start));
}

function getAdaptiveSpeedtestFallbackEndpoints(clientIp) {
    const out = new Set();
    const key = touchSpeedtestClientKey(clientIp);
    if (key && SPEEDTEST_LAST_GOOD_BY_IP.has(key)) {
        out.add(SPEEDTEST_LAST_GOOD_BY_IP.get(key));
    }

    const rankedGlobal = Array.from(SPEEDTEST_ENDPOINT_STATS.entries())
        .sort((a, b) => {
            const hitsDiff = (b[1]?.hits || 0) - (a[1]?.hits || 0);
            if (hitsDiff !== 0) return hitsDiff;
            return (b[1]?.lastSeen || 0) - (a[1]?.lastSeen || 0);
        })
        .slice(0, 12)
        .map(([endpoint]) => endpoint);
    for (const endpoint of rankedGlobal) out.add(endpoint);

    const rotatedDefaults = getRotatedDefaultFallbackEndpoints(clientIp);
    for (const endpoint of rotatedDefaults) out.add(endpoint);
    return Array.from(out).filter((endpoint) => !!normalizeEndpointForStats(endpoint));
}

function buildWindowsSpeedtestScript({ sessionId, reportUrl, fallbackCandidates = [], dpiFirst = false }) {
    const staticIps = [
        ...Array.from({ length: 20 }, (_, idx) => `162.159.192.${idx + 1}`),
        ...Array.from({ length: 10 }, (_, idx) => `162.159.195.${idx + 1}`),
    ];
    const psIpArray = staticIps.map((ip) => `'${ip}'`).join(', ');
    const safeFallbackCandidates = Array.isArray(fallbackCandidates) && fallbackCandidates.length
        ? fallbackCandidates
        : SPEEDTEST_DEFAULT_FALLBACK_ENDPOINTS;
    const fallbackEndpointsJson = JSON.stringify(safeFallbackCandidates.map((x) => String(x || '').trim()).filter(Boolean));
    const fallbackIpJson = JSON.stringify(
        safeFallbackCandidates
            .map((endpoint) => parseEndpointHostPort(endpoint))
            .filter((item) => item && net.isIP(item.host) === 4)
            .map((item) => item.host),
    );
    const warpPortsStr = ALLOWED_WARP_PORTS.join(',');
    const dpiFirstPs = dpiFirst ? '$true' : '$false';
    return `\uFEFF# Cloudflare WARP local endpoint speedtest helper
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [Console]::OutputEncoding
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$dpiFirst = ${dpiFirstPs}
$sessionId = '${sessionId}'
$reportUrl = '${reportUrl}'
$fallbackEndpoints = ConvertFrom-Json @'
${fallbackEndpointsJson}
'@
$fallbackIps = ConvertFrom-Json @'
${fallbackIpJson}
'@
$workDir = Join-Path $env:TEMP ('warp-speedtest-' + $sessionId)
if (Test-Path $workDir) { Remove-Item -Recurse -Force $workDir }
New-Item -ItemType Directory -Path $workDir | Out-Null
Set-Location $workDir

function Get-FileSha256Hex {
  param([string]$Path)
  try {
    return (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
  } catch {
    return $null
  }
}

function Try-DownloadChecksumsAsset {
  param(
    [object]$Release,
    [string]$TargetDir,
    [string]$Label
  )
  try {
    $checksumAsset = $Release.assets | Where-Object {
      $_.name -match '(?i)(sha256|checksums?)' -and $_.name -match '(?i)\\.(txt|sha256|sha256sum)$'
    } | Select-Object -First 1
    if (-not $checksumAsset) {
      Write-Host ('[Verify] ' + $Label + ': no checksum asset in release.')
      return $null
    }
    $checksumsPath = Join-Path $TargetDir ('checksums-' + $Label + '-' + $checksumAsset.name)
    Invoke-WebRequest -Uri $checksumAsset.browser_download_url -OutFile $checksumsPath -ErrorAction Stop
    return $checksumsPath
  } catch {
    Write-Host ('[Verify] ' + $Label + ': failed to download checksums: ' + $_.Exception.Message)
    return $null
  }
}

function Try-VerifyByChecksums {
  param(
    [string]$FilePath,
    [string]$FileName,
    [string]$ChecksumsPath,
    [string]$Label
  )
  if (-not $ChecksumsPath -or -not (Test-Path $ChecksumsPath)) { return $false }
  try {
    $expectedHash = $null
    $lines = Get-Content -Path $ChecksumsPath -ErrorAction Stop
    foreach ($line in $lines) {
      $trimmed = ($line | Out-String).Trim()
      if (-not $trimmed -or $trimmed.Length -lt 65) { continue }
      $hashCandidate = $trimmed.Substring(0, 64).ToLower()
      if ($hashCandidate -notmatch '^[a-f0-9]{64}$') { continue }
      $nameCandidate = $trimmed.Substring(64).Trim().TrimStart('*').Trim()
      if ($nameCandidate -ieq $FileName) {
        $expectedHash = $hashCandidate
        break
      }
    }
    if (-not $expectedHash) {
      Write-Host ('[Verify] ' + $Label + ': checksum entry not found for ' + $FileName)
      return $false
    }
    $actualHash = Get-FileSha256Hex -Path $FilePath
    if (-not $actualHash) {
      throw 'Failed to compute local SHA256 hash'
    }
    if ($actualHash -ne $expectedHash) {
      throw ('SHA256 mismatch. Expected=' + $expectedHash + ' Actual=' + $actualHash)
    }
    Write-Host ('[Verify] ' + $Label + ': SHA256 verified for ' + $FileName)
    return $true
  } catch {
    Write-Host ('[Verify] ' + $Label + ': checksum verification failed: ' + $_.Exception.Message)
    return $false
  }
}

function Report-AuthenticodeStatus {
  param([string]$FilePath, [string]$Label)
  try {
    $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
    if ($sig.Status -eq 'Valid') {
      $subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { 'unknown signer' }
      Write-Host ('[Verify] ' + $Label + ': Authenticode VALID (' + $subject + ')')
      return $true
    }
    Write-Host ('[Verify] ' + $Label + ': Authenticode status=' + $sig.Status)
    return $false
  } catch {
    Write-Host ('[Verify] ' + $Label + ': Authenticode check unavailable: ' + $_.Exception.Message)
    return $false
  }
}

function Select-WindowsArchiveAsset {
  param(
    [array]$Assets,
    [string]$Label
  )
  if (-not $Assets) { return $null }
  $archives = $Assets | Where-Object { $_.name -match '(?i)\\.(zip|7z|tar\\.gz|tgz|tar)$' }
  if (-not $archives -or $archives.Count -eq 0) {
    Write-Host ('[DPI] ' + $Label + ': no archive assets in release.')
    return $null
  }

  $preferredWin64 = $archives | Where-Object {
    $_.name -match '(?i)win' -and $_.name -match '(?i)(amd64|x64|64|win64)'
  } | Select-Object -First 1
  if ($preferredWin64) {
    Write-Host ('[DPI] ' + $Label + ': selected preferred windows-x64 asset ' + $preferredWin64.name)
    return $preferredWin64
  }

  $preferredWinAny = $archives | Where-Object { $_.name -match '(?i)win' } | Select-Object -First 1
  if ($preferredWinAny) {
    Write-Host ('[DPI] ' + $Label + ': selected windows archive asset ' + $preferredWinAny.name)
    return $preferredWinAny
  }

  $portableZip = $archives | Where-Object {
    $_.name -match '(?i)\\.zip$' -and $_.name -notmatch '(?i)(openwrt|embedded)'
  } | Select-Object -First 1
  if ($portableZip) {
    Write-Host ('[DPI] ' + $Label + ': selected portable zip asset ' + $portableZip.name)
    return $portableZip
  }

  $portableAny = $archives | Where-Object { $_.name -notmatch '(?i)(openwrt|embedded)' } | Select-Object -First 1
  if ($portableAny) {
    Write-Host ('[DPI] ' + $Label + ': selected portable archive asset ' + $portableAny.name)
    return $portableAny
  }

  $fallbackArchive = $archives | Select-Object -First 1
  if ($fallbackArchive) {
    Write-Host ('[DPI] ' + $Label + ': selected fallback archive asset ' + $fallbackArchive.name)
  }
  return $fallbackArchive
}

function Expand-ArchiveAny {
  param(
    [string]$ArchivePath,
    [string]$DestinationPath,
    [string]$Label
  )
  if (-not (Test-Path $DestinationPath)) { New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null }
  try {
    Expand-Archive -Path $ArchivePath -DestinationPath $DestinationPath -Force -ErrorAction Stop
    Write-Host ('[DPI] ' + $Label + ': archive extracted via Expand-Archive.')
    return $true
  } catch {
    Write-Host ('[DPI] ' + $Label + ': Expand-Archive failed: ' + $_.Exception.Message)
  }
  try {
    $tarCmd = Get-Command tar -ErrorAction SilentlyContinue
    if ($tarCmd) {
      & $tarCmd.Source -xf $ArchivePath -C $DestinationPath
      if ($LASTEXITCODE -eq 0) {
        Write-Host ('[DPI] ' + $Label + ': archive extracted via tar.')
        return $true
      }
      Write-Host ('[DPI] ' + $Label + ': tar extract failed with code ' + $LASTEXITCODE)
    } else {
      Write-Host ('[DPI] ' + $Label + ': tar command not found.')
    }
  } catch {
    Write-Host ('[DPI] ' + $Label + ': tar extract failed: ' + $_.Exception.Message)
  }
  return $false
}

function Find-WinwsExecutable {
  param([string]$SearchRoot)
  $candidates = @(
    Get-ChildItem -Path $SearchRoot -Recurse -File -Filter 'winws2.exe' -ErrorAction SilentlyContinue
  )
  if (-not $candidates -or $candidates.Count -eq 0) {
    $candidates = @(
      Get-ChildItem -Path $SearchRoot -Recurse -File -Filter 'winws.exe' -ErrorAction SilentlyContinue
    )
  }
  if (-not $candidates -or $candidates.Count -eq 0) {
    $candidates = @(
      Get-ChildItem -Path $SearchRoot -Recurse -File -Filter 'winws*.exe' -ErrorAction SilentlyContinue
    )
  }
  if (-not $candidates -or $candidates.Count -eq 0) { return $null }

  $best = $candidates | Sort-Object @{
      Expression = {
        $score = 0
        $p = $_.FullName.ToLower()
        if ($p -match 'binaries[\\\\/]+windows-x86_64') { $score += 100 }
        elseif ($p -match 'windows-x86_64|win64|x64') { $score += 80 }
        elseif ($p -match 'binaries[\\\\/]+windows-x86|win32|x86') { $score += 40 }
        if (Test-Path (Join-Path $_.DirectoryName 'cygwin1.dll')) { $score += 60 }
        if (Test-Path (Join-Path $_.DirectoryName 'WinDivert.dll')) { $score += 40 }
        if (Test-Path (Join-Path $_.DirectoryName 'WinDivert64.sys')) { $score += 10 }
        if (Test-Path (Join-Path $_.DirectoryName 'WinDivert32.sys')) { $score += 10 }
        $score
      }
      Descending = $true
    }, @{
      Expression = { $_.FullName.Length }
      Descending = $false
    } | Select-Object -First 1

  return $best
}

function Ensure-WinwsRuntimeFiles {
  param(
    [System.IO.FileInfo]$WinwsExe,
    [string]$SearchRoot
  )
  if (-not $WinwsExe) { return $false }
  $exeDir = $WinwsExe.DirectoryName
  if (-not (Test-Path $exeDir)) { return $false }

  function Copy-MissingRuntimeFile {
    param([string]$FileName)
    $targetPath = Join-Path $exeDir $FileName
    if (Test-Path $targetPath) { return $true }
    $source = Get-ChildItem -Path $SearchRoot -Recurse -File -Filter $FileName -ErrorAction SilentlyContinue |
      Sort-Object @{
        Expression = {
          $p = $_.DirectoryName.ToLower()
          if ($p -match 'binaries[\\\\/]+windows-x86_64') { 0 }
          elseif ($p -match 'windows-x86_64|win64|x64') { 1 }
          elseif ($p -match 'binaries[\\\\/]+windows-x86|win32|x86') { 2 }
          else { 9 }
        }
      }, FullName | Select-Object -First 1
    if (-not $source) { return $false }
    try {
      Copy-Item -Path $source.FullName -Destination $targetPath -Force -ErrorAction Stop
      Write-Host ('[DPI] Runtime file copied: ' + $FileName + ' <- ' + $source.FullName)
      return $true
    } catch {
      Write-Host ('[DPI] Failed to copy runtime file ' + $FileName + ': ' + $_.Exception.Message)
      return $false
    }
  }

  $okCygwin = Copy-MissingRuntimeFile -FileName 'cygwin1.dll'
  $okDivert = Copy-MissingRuntimeFile -FileName 'WinDivert.dll'
  $driverName = if ([Environment]::Is64BitOperatingSystem) { 'WinDivert64.sys' } else { 'WinDivert32.sys' }
  Copy-MissingRuntimeFile -FileName $driverName | Out-Null

  if (-not ($okCygwin -and $okDivert)) {
    Write-Host '[DPI] winws runtime incomplete: cygwin1.dll or WinDivert.dll missing.'
    return $false
  }

  $env:PATH = $exeDir + ';' + $env:PATH
  return $true
}

function Normalize-EndpointForReport {
  param(
    [string]$Endpoint,
    [array]$EngageIpList
  )
  # Keep raw endpoint from speedtest (IP:port), do not rewrite to domain.
  return $Endpoint
}

$cpu = [Math]::Max(1, [Environment]::ProcessorCount)
$workerP = [Math]::Max(8, [Math]::Min(32, $cpu * 2))
$primaryC = [Math]::Max(800, [Math]::Min(6000, $cpu * 350))
$rescueC = [Math]::Max(600, [Math]::Min(4500, [int]($primaryC * 0.75)))
$qualityC = [Math]::Max(1200, [Math]::Min(7000, [int]($primaryC * 1.25)))
$candidateP = [Math]::Max(4, [Math]::Min(16, [int]($workerP / 2)))
$candidateC = [Math]::Max(400, [Math]::Min(2200, [int]($rescueC / 2)))
Write-Host ('Adaptive engine: CPU=' + $cpu + ', p=' + $workerP + ', c=' + $primaryC + '/' + $rescueC + '/' + $qualityC)

Write-Host '[1/5] Downloading CloudflareWarpSpeedTest...'
$arch = if ([Environment]::Is64BitOperatingSystem) { 'amd64' } else { '386' }
$release = Invoke-RestMethod -Uri 'https://api.github.com/repos/peanut996/CloudflareWarpSpeedTest/releases/latest'
$asset = $release.assets | Where-Object { $_.name -like ('*windows-' + $arch + '.zip') } | Select-Object -First 1
if (-not $asset) { throw 'Windows build not found in latest release' }
$zipPath = Join-Path $workDir $asset.name
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath
$speedtestChecksums = Try-DownloadChecksumsAsset -Release $release -TargetDir $workDir -Label 'CloudflareWarpSpeedTest'
$speedtestHashOk = Try-VerifyByChecksums -FilePath $zipPath -FileName $asset.name -ChecksumsPath $speedtestChecksums -Label 'CloudflareWarpSpeedTest'
if (-not $speedtestHashOk) {
  Write-Host '[Verify] CloudflareWarpSpeedTest: checksum verification skipped or unavailable.'
}
Expand-Archive -Path $zipPath -DestinationPath $workDir -Force

$exe = Get-ChildItem -Path $workDir -Recurse -Filter '*.exe' | Where-Object { $_.Name -like 'CloudflareWarpSpeedTest*.exe' } | Select-Object -First 1
if (-not $exe) { throw 'CloudflareWarpSpeedTest executable not found after extraction' }
Report-AuthenticodeStatus -FilePath $exe.FullName -Label 'CloudflareWarpSpeedTest' | Out-Null

Write-Host '[2/5] Building local IP list...'
$staticIps = @(${psIpArray})
$engageIps = @()
try {
  $engageIps = Resolve-DnsName -Name 'engage.cloudflareclient.com' -Type A -ErrorAction Stop | Select-Object -ExpandProperty IPAddress -Unique
} catch {
  Write-Host 'engage.cloudflareclient.com DNS resolve failed, continuing with static ranges.'
}
$allIps = ($staticIps + $engageIps) | Sort-Object -Unique
if (-not $allIps -or $allIps.Count -eq 0) { throw 'No IPs to test' }
$ipFile = Join-Path $workDir 'ip.txt'
$allIps | Set-Content -Path $ipFile -Encoding ascii

if ($dpiFirst) {
  Write-Host '[3/5] DPI-first mode: skipping direct speedtest, going straight to DPI bypass...'
} else {
Write-Host '[3/5] Running speed test...'
$csvPath = Join-Path $workDir 'result.csv'
& $exe.FullName -all -n 60 -t 5 -c $primaryC -tl 450 -tll 0 -tlr 0.25 -p $workerP -f $ipFile -o $csvPath

Write-Host '[4/5] Selecting best endpoint...'
$rows = @()
if (Test-Path $csvPath) {
  try {
    $rows = Import-Csv -Path $csvPath | Where-Object { $_.'IP:Port' -and $_.Loss -and $_.Latency }
  } catch {
    Write-Host ('Failed to parse result.csv: ' + $_.Exception.Message)
    $rows = @()
  }
} else {
  Write-Host 'result.csv was not created by CloudflareWarpSpeedTest.'
}

$normalized = @()
if ($rows -and $rows.Count -gt 0) {
  $normalized = foreach ($r in $rows) {
    [PSCustomObject]@{
      endpoint = $r.'IP:Port'
      loss = [double](($r.Loss -replace '%', '').Trim())
      latencyMs = [double](($r.Latency).Trim())
    }
  }
}

if (-not $normalized -or $normalized.Count -eq 0) {
  Write-Host 'No endpoints from primary pass. Running rescue pass with relaxed thresholds...'
  $rescueIps = ($allIps + $fallbackIps) | Sort-Object -Unique
  $rescueFile = Join-Path $workDir 'ip-rescue.txt'
  $rescueIps | Set-Content -Path $rescueFile -Encoding ascii
  $rescueCsv = Join-Path $workDir 'result-rescue.csv'
  & $exe.FullName -all -n 35 -t 3 -c $rescueC -tl 1200 -tll 0 -tlr 1 -p $workerP -f $rescueFile -o $rescueCsv

  if (Test-Path $rescueCsv) {
    try {
      $rescueRows = Import-Csv -Path $rescueCsv | Where-Object { $_.'IP:Port' -and $_.Loss -and $_.Latency }
      if ($rescueRows -and $rescueRows.Count -gt 0) {
        $normalized = foreach ($r in $rescueRows) {
          [PSCustomObject]@{
            endpoint = $r.'IP:Port'
            loss = [double](($r.Loss -replace '%', '').Trim())
            latencyMs = [double](($r.Latency).Trim())
          }
        }
      }
    } catch {
      Write-Host ('Failed to parse rescue speedtest CSV: ' + $_.Exception.Message)
    }
  }
}

$qualityPassUsed = $false
if ($normalized -and $normalized.Count -gt 0) {
  Write-Host 'Primary/rescue pass returned endpoints. Running quality pass on top hosts...'
  $topCandidates = @($normalized | Sort-Object loss, latencyMs | Select-Object -First 12)
  $qualityHosts = @()
  foreach ($candidate in $topCandidates) {
    if (-not $candidate.endpoint) { continue }
    $candidateParts = $candidate.endpoint -split ':'
    if ($candidateParts.Count -lt 1) { continue }
    $candidateHostName = $candidateParts[0].Trim()
    if ($candidateHostName) { $qualityHosts += $candidateHostName }
  }
  $qualityHosts = @($qualityHosts | Sort-Object -Unique)

  if ($qualityHosts.Count -gt 0) {
    $qualityFile = Join-Path $workDir 'ip-quality.txt'
    $qualityHosts | Set-Content -Path $qualityFile -Encoding ascii
    $qualityCsv = Join-Path $workDir 'result-quality.csv'
    & $exe.FullName -all -n 90 -t 6 -c $qualityC -tl 300 -tll 0 -tlr 0.2 -p $workerP -f $qualityFile -o $qualityCsv

    if (Test-Path $qualityCsv) {
      try {
        $qualityRows = Import-Csv -Path $qualityCsv | Where-Object { $_.'IP:Port' -and $_.Loss -and $_.Latency }
        if ($qualityRows -and $qualityRows.Count -gt 0) {
          $qualityNorm = foreach ($r in $qualityRows) {
            [PSCustomObject]@{
              endpoint = $r.'IP:Port'
              loss = [double](($r.Loss -replace '%', '').Trim())
              latencyMs = [double](($r.Latency).Trim())
            }
          }
          if ($qualityNorm -and $qualityNorm.Count -gt 0) {
            $normalized = $qualityNorm
            $qualityPassUsed = $true
          }
        }
      } catch {
        Write-Host ('Failed to parse quality speedtest CSV: ' + $_.Exception.Message)
      }
    }
  }
}

if (-not $normalized -or $normalized.Count -eq 0) {
  Write-Host 'Rescue pass returned no endpoints. Trying candidate-by-candidate check...'
  foreach ($candidate in $fallbackEndpoints) {
    if (-not $candidate) { continue }
    $parts = $candidate -split ':'
    if ($parts.Count -lt 2) { continue }
    $candidateHost = $parts[0].Trim()
    $candidatePort = $parts[1].Trim()
    if (-not $candidateHost -or -not $candidatePort) { continue }

    $candidateIpFile = Join-Path $workDir ('ip-candidate-' + ($candidateHost -replace '[^a-zA-Z0-9]', '_') + '.txt')
    @($candidateHost) | Set-Content -Path $candidateIpFile -Encoding ascii
    $candidateCsv = Join-Path $workDir ('result-candidate-' + ($candidateHost -replace '[^a-zA-Z0-9]', '_') + '.csv')

    & $exe.FullName -all -n 16 -t 2 -c $candidateC -tl 2000 -tll 0 -tlr 1 -p $candidateP -f $candidateIpFile -o $candidateCsv
    if (-not (Test-Path $candidateCsv)) { continue }

    try {
      $candidateRows = Import-Csv -Path $candidateCsv | Where-Object { $_.'IP:Port' -and $_.Loss -and $_.Latency }
      if (-not $candidateRows -or $candidateRows.Count -eq 0) { continue }

      $candidateNorm = foreach ($r in $candidateRows) {
        [PSCustomObject]@{
          endpoint = $r.'IP:Port'
          loss = [double](($r.Loss -replace '%', '').Trim())
          latencyMs = [double](($r.Latency).Trim())
        }
      }

      $exactMatch = $candidateNorm | Where-Object { $_.endpoint -eq $candidate } | Sort-Object loss, latencyMs | Select-Object -First 1
      if ($exactMatch) {
        $normalized = @($exactMatch)
        Write-Host ('Found exact candidate endpoint: ' + $candidate)
        break
      }

      $bestCandidateHost = $candidateNorm | Sort-Object loss, latencyMs | Select-Object -First 1
      if ($bestCandidateHost) {
        $normalized = @($bestCandidateHost)
        Write-Host ('Found working endpoint on candidate host ' + $candidateHost + ': ' + $bestCandidateHost.endpoint)
        break
      }
    } catch {
      Write-Host ('Candidate check parse failed for ' + $candidate + ': ' + $_.Exception.Message)
    }
  }
}

} # end if (-not $dpiFirst)

$bestEndpoint = $null
$topResults = @()
$reportSource = 'windows-local-helper'
if ($normalized -and $normalized.Count -gt 0) {
  $best = $normalized | Sort-Object loss, latencyMs | Select-Object -First 1
  if ($best) {
    $bestEndpoint = $best.endpoint
    $topResults = @($normalized | Sort-Object loss, latencyMs | Select-Object -First 5)
    if ($qualityPassUsed) { $reportSource = 'windows-local-helper-quality' }
  }
}


# === [DPI BYPASS] zapret/winws — автоматический обход DPI ===
if (-not $bestEndpoint) {
  Write-Host ''
  if ($dpiFirst) {
    Write-Host '=== [DPI] Режим DPI-first: запускаем обход DPI через zapret (winws) напрямую... ==='
  } else {
    Write-Host '=== [DPI] Все прямые попытки не дали эндпоинтов. Пробуем обход DPI через zapret (winws)... ==='
  }
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) {
    Write-Host '[DPI] Для WinDivert нужны права администратора.'
    Write-Host '[DPI] Закройте это окно и запустите .bat правой кнопкой -> "Запуск от имени администратора".'
  } else {
    $winwsProcess = $null
    $winwsExe = $null
    $zapretDir = Join-Path $workDir 'zapret'

    # --- Шаг 1: скачать zapret2 (bol-van/zapret2) ---
    try {
      Write-Host '[DPI] Получаем информацию о релизе zapret2...'
      $z2Release = Invoke-RestMethod -Uri 'https://api.github.com/repos/bol-van/zapret2/releases/latest' -ErrorAction Stop
      $z2Asset = Select-WindowsArchiveAsset -Assets $z2Release.assets -Label 'zapret2'
      if ($z2Asset) {
        $z2Zip = Join-Path $workDir ('zapret2-' + $z2Asset.name)
        Write-Host ('[DPI] Скачиваем ' + $z2Asset.name + '...')
        Invoke-WebRequest -Uri $z2Asset.browser_download_url -OutFile $z2Zip -ErrorAction Stop
        $z2Checksums = Try-DownloadChecksumsAsset -Release $z2Release -TargetDir $workDir -Label 'zapret2'
        $z2HashOk = Try-VerifyByChecksums -FilePath $z2Zip -FileName $z2Asset.name -ChecksumsPath $z2Checksums -Label 'zapret2'
        if (-not $z2HashOk) {
          Write-Host '[Verify] zapret2: checksum verification skipped or unavailable.'
        }
        if (Expand-ArchiveAny -ArchivePath $z2Zip -DestinationPath $zapretDir -Label 'zapret2') {
          $winwsExe = Find-WinwsExecutable -SearchRoot $zapretDir
          if ($winwsExe) {
            Write-Host ('[DPI] Найден: ' + $winwsExe.FullName)
          } else {
            Write-Host '[DPI] zapret2 архив распакован, но winws не найден.'
          }
        }
      }
    } catch {
      Write-Host ('[DPI] zapret2 недоступен: ' + $_.Exception.Message)
    }

    # --- Шаг 2: fallback — оригинальный zapret (bol-van/zapret) ---
    if (-not $winwsExe) {
      try {
        Write-Host '[DPI] Пробуем оригинальный zapret (bol-van/zapret)...'
        $z1Release = Invoke-RestMethod -Uri 'https://api.github.com/repos/bol-van/zapret/releases/latest' -ErrorAction Stop
        $z1Asset = Select-WindowsArchiveAsset -Assets $z1Release.assets -Label 'zapret'
        if ($z1Asset) {
          $z1Zip = Join-Path $workDir ('zapret-' + $z1Asset.name)
          Write-Host ('[DPI] Скачиваем ' + $z1Asset.name + '...')
          Invoke-WebRequest -Uri $z1Asset.browser_download_url -OutFile $z1Zip -ErrorAction Stop
          $z1Checksums = Try-DownloadChecksumsAsset -Release $z1Release -TargetDir $workDir -Label 'zapret'
          $z1HashOk = Try-VerifyByChecksums -FilePath $z1Zip -FileName $z1Asset.name -ChecksumsPath $z1Checksums -Label 'zapret'
          if (-not $z1HashOk) {
            Write-Host '[Verify] zapret: checksum verification skipped or unavailable.'
          }
          if (Expand-ArchiveAny -ArchivePath $z1Zip -DestinationPath $zapretDir -Label 'zapret') {
            $winwsExe = Find-WinwsExecutable -SearchRoot $zapretDir
            if ($winwsExe) {
              Write-Host ('[DPI] Найден: ' + $winwsExe.FullName)
            } else {
              Write-Host '[DPI] zapret архив распакован, но winws не найден.'
            }
          }
        }
      } catch {
        Write-Host ('[DPI] zapret недоступен: ' + $_.Exception.Message)
      }
    }

    # --- Шаг 2.5: fallback — bol-van/zapret-win-bundle (zipball) ---
    if (-not $winwsExe) {
      try {
        Write-Host '[DPI] Пробуем fallback: bol-van/zapret-win-bundle...'
        $bundleZip = Join-Path $workDir 'zapret-win-bundle.zip'
        Invoke-WebRequest -Uri 'https://api.github.com/repos/bol-van/zapret-win-bundle/zipball' -OutFile $bundleZip -ErrorAction Stop
        if (Expand-ArchiveAny -ArchivePath $bundleZip -DestinationPath $zapretDir -Label 'zapret-win-bundle') {
          $winwsExe = Find-WinwsExecutable -SearchRoot $zapretDir
          if ($winwsExe) {
            Write-Host ('[DPI] Найден (bundle): ' + $winwsExe.FullName)
          } else {
            Write-Host '[DPI] zapret-win-bundle распакован, но winws не найден.'
          }
        }
      } catch {
        Write-Host ('[DPI] zapret-win-bundle недоступен: ' + $_.Exception.Message)
      }
    }

    # --- Шаг 3: запустить winws и повторить скан ---
    if ($winwsExe) {
      try {
        Report-AuthenticodeStatus -FilePath $winwsExe.FullName -Label 'winws' | Out-Null
        $runtimeOk = Ensure-WinwsRuntimeFiles -WinwsExe $winwsExe -SearchRoot $zapretDir
        if (-not $runtimeOk) {
          throw 'Required winws runtime files are missing (cygwin1.dll/WinDivert.dll).'
        }
        $warpPorts = '${warpPortsStr}'
        $winwsArgs = "--wf-udp=$warpPorts --udp-fake-count=6 --wf-l3=ipv4"
        Write-Host ('[DPI] Запускаем winws: ' + $winwsExe.FullName)
        Write-Host ('[DPI] Параметры: ' + $winwsArgs)
        $winwsProcess = Start-Process -FilePath $winwsExe.FullName -ArgumentList $winwsArgs -PassThru -WindowStyle Hidden -WorkingDirectory $winwsExe.DirectoryName -ErrorAction Stop
        Write-Host ('[DPI] winws запущен (PID: ' + $winwsProcess.Id + '). Ожидаем 3 сек...')
        Start-Sleep -Seconds 3

        Write-Host '[DPI] Повторный скан WARP-эндпоинтов через DPI-bypass...'
        $dpiCsvPath = Join-Path $workDir 'result-dpi-bypass.csv'
        & $exe.FullName -all -n 60 -t 5 -c $rescueC -tl 600 -tll 0 -tlr 0.5 -p $workerP -f $ipFile -o $dpiCsvPath

        if (Test-Path $dpiCsvPath) {
          try {
            $dpiRows = Import-Csv -Path $dpiCsvPath | Where-Object { $_.'IP:Port' -and $_.Loss -and $_.Latency }
            if ($dpiRows -and $dpiRows.Count -gt 0) {
              $dpiNorm = foreach ($r in $dpiRows) {
                [PSCustomObject]@{
                  endpoint  = $r.'IP:Port'
                  loss      = [double](($r.Loss -replace '%','').Trim())
                  latencyMs = [double](($r.Latency).Trim())
                }
              }
              $dpiBest = $dpiNorm | Sort-Object loss, latencyMs | Select-Object -First 1
              if ($dpiBest) {
                $bestEndpoint = $dpiBest.endpoint
                $topResults   = @($dpiNorm | Sort-Object loss, latencyMs | Select-Object -First 5)
                $reportSource = 'windows-local-helper-dpi-bypass'
                Write-Host ('[DPI] Найден эндпоинт через DPI-bypass: ' + $bestEndpoint)
              }
            } else {
              Write-Host '[DPI] DPI-bypass скан не вернул эндпоинтов.'
            }
          } catch {
            Write-Host ('[DPI] Ошибка разбора результатов DPI-bypass: ' + $_.Exception.Message)
          }
        }
      } catch {
        Write-Host ('[DPI] Ошибка запуска winws: ' + $_.Exception.Message)
      } finally {
        if ($winwsProcess -and -not $winwsProcess.HasExited) {
          Write-Host '[DPI] Останавливаем winws...'
          Stop-Process -Id $winwsProcess.Id -Force -ErrorAction SilentlyContinue
        }
      }
    } else {
      Write-Host '[DPI] winws не найден. DPI-bypass недоступен.'
    }
  }
}

if ($bestEndpoint) {
  $bestEndpoint = Normalize-EndpointForReport -Endpoint $bestEndpoint -EngageIpList $engageIps
}

if (-not $bestEndpoint) {
  $bestEndpoint = $fallbackEndpoints | Select-Object -First 1
  $reportSource = 'windows-local-helper-fallback'
  Write-Host ('No available endpoints from local speedtest. Using fallback endpoint: ' + $bestEndpoint)
}

Write-Host '[5/5] Reporting to site...'
$payload = @{
  sessionId = $sessionId
  bestEndpoint = $bestEndpoint
  topResults = $topResults
  source = $reportSource
} | ConvertTo-Json -Depth 8
Invoke-RestMethod -Uri $reportUrl -Method POST -ContentType 'application/json' -Body $payload | Out-Null

try { Set-Clipboard -Value $bestEndpoint } catch {}
Write-Host ''
Write-Host ('Best endpoint: ' + $bestEndpoint)
Write-Host 'Done. You can return to the site, endpoint will be filled automatically.'
`;
}

function buildWindowsBatchScript({ sessionId, baseUrl }) {
    const ps1Url = `${baseUrl}/api/speedtest/windows-script/${sessionId}`;
    return `@echo off
setlocal
set "PS1_URL=${ps1Url}"
set "PS1_FILE=%TEMP%\\warp-speedtest-${sessionId}.ps1"

echo WARP Endpoint Speedtest
echo ========================
echo.
echo [Info] If WARP endpoints are blocked by DPI, the script will
echo        automatically try to bypass via zapret/winws.
echo [Info] DPI-bypass requires Administrator rights.
echo        If prompted - right-click the .bat and choose
echo        "Run as administrator"
echo.

net session >nul 2>&1
if %errorLevel% equ 0 (
  echo [OK] Running as Administrator. DPI-bypass available.
) else (
  echo [Warning] Running without Administrator rights.
  echo           Re-run as Administrator if DPI-bypass is needed.
)
echo.

echo Downloading helper script...
set "ATTEMPT=0"
:download_retry
set /a ATTEMPT+=1
echo [Download] Attempt %ATTEMPT%/3
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $u = '%PS1_URL%'; if ($u -notmatch '\\?') { $u = $u + '?t=' + [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() }; Invoke-WebRequest -Uri $u -OutFile '%PS1_FILE%'; & '%PS1_FILE%' } catch { Write-Host $_; exit 1 }"
if errorlevel 1 (
  if %ATTEMPT% LSS 3 (
    echo [Download] Failed, retrying in 2 seconds...
    timeout /t 2 /nobreak >nul
    goto download_retry
  )
  echo.
  echo ERROR: WARP speedtest failed.
  pause
  exit /b 1
)

echo.
echo Done. Go back to the website.
pause
`;
}

function normalizePublicScriptBaseUrl(rawBaseUrl) {
    const base = String(rawBaseUrl || '').trim();
    if (!base) return base;
    const lower = base.toLowerCase();
    const isLocalHost =
        lower.startsWith('http://localhost') ||
        lower.startsWith('http://127.0.0.1') ||
        lower.startsWith('http://[::1]');
    if (isLocalHost) return base;
    return base.replace(/^http:\/\//i, 'https://');
}

function cleanupClashProfiles() {
    const now = Date.now();
    for (const [id, profile] of CLASH_PROFILES.entries()) {
        if (now - profile.createdAt > CLASH_PROFILE_TTL_MS) CLASH_PROFILES.delete(id);
    }
}

function enforceClashProfileLimit() {
    if (CLASH_PROFILES.size <= CLASH_PROFILE_MAX_ENTRIES) return;
    const overflow = CLASH_PROFILES.size - CLASH_PROFILE_MAX_ENTRIES;
    const oldest = Array.from(CLASH_PROFILES.entries())
        .sort((a, b) => (a[1]?.createdAt || 0) - (b[1]?.createdAt || 0))
        .slice(0, overflow)
        .map(([id]) => id);
    for (const id of oldest) CLASH_PROFILES.delete(id);
}

setInterval(cleanupSpeedtestSessions, 5 * 60 * 1000).unref();
setInterval(cleanupSpeedtestAdaptiveState, 30 * 60 * 1000).unref();
setInterval(cleanupDnsResolveCache, 10 * 60 * 1000).unref();
setInterval(cleanupClashProfiles, 10 * 60 * 1000).unref();
setInterval(cleanupRateLimitState, 60 * 1000).unref();

app.get('/api/endpoints', (req, res) => {
    res.json(WARP_ENDPOINTS);
});

app.get('/api/split-targets', (req, res) => {
    const targets = Object.entries(SPLIT_TUNNEL_TARGETS).map(([key, t]) => ({
        key,
        label: t.label,
        domainCount: (t.domains || []).length,
        cidrCount: (t.cidrs || []).length,
        hasProcesses: Array.isArray(t.processes) && t.processes.length > 0,
        processes: t.processes || [],
    }));
    res.json({ targets });
});

app.get('/api/warp-options', (req, res) => {
    res.json({
        defaultPort: 2408,
        defaultEndpoint: 'auto',
        ports: ALLOWED_WARP_PORTS,
        endpointGroups: WARP_ENDPOINT_GROUPS,
    });
});

app.post('/api/speedtest/session', (req, res) => {
    cleanupSpeedtestSessions();
    const sessionId = crypto.randomBytes(12).toString('hex');
    const session = {
        id: sessionId,
        createdAt: Date.now(),
        status: 'pending',
        clientIp: getClientIp(req),
        result: null,
        dpiFirst: Boolean(req.body?.dpiFirst),
    };
    SPEEDTEST_SESSIONS.set(sessionId, session);

    res.json({
        sessionId,
        expiresInSec: Math.floor(SPEEDTEST_SESSION_TTL_MS / 1000),
        downloadPath: `/api/speedtest/windows-script/${sessionId}`,
        downloadBatPath: `/api/speedtest/windows-bat/${sessionId}`,
        pollPath: `/api/speedtest/session/${sessionId}`,
    });
});

app.get('/api/speedtest/windows-script/:sessionId', (req, res) => {
    cleanupSpeedtestSessions();
    const sessionId = String(req.params.sessionId || '').trim();
    const session = SPEEDTEST_SESSIONS.get(sessionId);
    if (!session) return res.status(404).send('Session not found or expired.');

    const baseUrl = normalizePublicScriptBaseUrl(getRequestBaseUrl(req));
    const reportUrl = `${baseUrl}/api/speedtest/report`;
    const fallbackCandidates = getAdaptiveSpeedtestFallbackEndpoints(session.clientIp);
    const script = buildWindowsSpeedtestScript({ sessionId, reportUrl, fallbackCandidates, dpiFirst: session.dpiFirst });
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="warp-speedtest-${sessionId}.ps1"`);
    res.send(script);
});

app.get('/api/speedtest/windows-bat/:sessionId', (req, res) => {
    cleanupSpeedtestSessions();
    const sessionId = String(req.params.sessionId || '').trim();
    const session = SPEEDTEST_SESSIONS.get(sessionId);
    if (!session) return res.status(404).send('Session not found or expired.');

    const baseUrl = normalizePublicScriptBaseUrl(getRequestBaseUrl(req));
    const script = buildWindowsBatchScript({
        sessionId,
        baseUrl,
    });
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="run-warp-speedtest-${sessionId}.bat"`);
    res.send(script);
});

app.get('/api/speedtest/session/:sessionId', (req, res) => {
    cleanupSpeedtestSessions();
    const sessionId = String(req.params.sessionId || '').trim();
    const session = SPEEDTEST_SESSIONS.get(sessionId);
    if (!session) return res.status(404).json({ error: 'Session not found or expired.' });

    res.json({
        sessionId,
        status: session.status,
        result: session.result,
    });
});

app.post('/api/speedtest/report', (req, res) => {
    cleanupSpeedtestSessions();
    const sessionId = typeof req.body?.sessionId === 'string' ? req.body.sessionId.trim() : '';
    const bestEndpoint = typeof req.body?.bestEndpoint === 'string' ? req.body.bestEndpoint.trim() : '';
    const topResults = Array.isArray(req.body?.topResults) ? req.body.topResults.slice(0, 10) : [];
    const source = typeof req.body?.source === 'string' ? req.body.source.trim() : '';
    if (!sessionId || !bestEndpoint) {
        return res.status(400).json({ error: 'sessionId and bestEndpoint are required.' });
    }

    const session = SPEEDTEST_SESSIONS.get(sessionId);
    if (!session) return res.status(404).json({ error: 'Session not found or expired.' });

    const parsed = parseEndpointHostPort(bestEndpoint);
    if (!parsed || !isAllowedWarpPort(parsed.port)) {
        return res.status(400).json({ error: 'Best endpoint port is outside allowed port list.' });
    }
    const hostAllowed = isAllowedWarpResultIp(parsed.host) || isAllowedWarpResultHost(parsed.host);
    if (!hostAllowed) {
        return res.status(400).json({ error: 'Best endpoint is outside allowed endpoint/port list.' });
    }

    session.status = 'completed';
    session.result = {
        bestEndpoint: `${parsed.host}:${parsed.port}`,
        topResults,
        reportedAt: new Date().toISOString(),
        reporterIp: getClientIp(req),
        source,
    };

    if (!source.includes('fallback')) {
        recordSpeedtestEndpointStat(session.clientIp, session.result.bestEndpoint);
    }

    res.json({ ok: true, bestEndpoint: session.result.bestEndpoint });
});

app.get('/api/version', (req, res) => {
    res.json({
        version: APP_VERSION,
        build: GIT_SHA,
        display: VERSION_DISPLAY,
        commitDate: GIT_DATE,
    });
});

app.get('/api/client-downloads', (req, res) => {
    const apps = Object.entries(CLIENT_DOWNLOADS).map(([key, meta]) => ({
        key,
        title: meta.title,
        platforms: Object.keys(meta.links || {}),
    }));
    res.json({
        apps,
        platforms: ['windows', 'macos', 'linux', 'android', 'ios'],
    });
});

app.get('/api/client-download/:app', rateLimitClientDownload, async (req, res) => {
    try {
        const appKey = typeof req.params?.app === 'string' ? req.params.app.trim().toLowerCase() : '';
        const appMeta = CLIENT_DOWNLOADS[appKey];
        if (!appMeta) {
            return res.status(404).json({ error: 'Unknown app.' });
        }
        const platform = normalizeClientPlatform(req.query?.platform);
        const fallbackUrl = appMeta.links?.[platform] || appMeta.links?.windows || null;
        const resolvedUrl = await resolveClientDownloadUrl(appKey, platform);
        const primaryUrl = resolvedUrl || fallbackUrl;
        if (!primaryUrl) return res.status(404).json({ error: 'No download URL for platform.' });

        let safePrimary = null;
        let safeFallback = null;

        try {
            safePrimary = await assertSafeDownloadUrl(primaryUrl);
        } catch (primaryErr) {
            if (!fallbackUrl || fallbackUrl === primaryUrl) throw primaryErr;
            safeFallback = await assertSafeDownloadUrl(fallbackUrl);
            proxyRemoteDownload(safeFallback, res);
            return;
        }

        if (fallbackUrl && fallbackUrl !== safePrimary.url) {
            try {
                safeFallback = await assertSafeDownloadUrl(fallbackUrl);
            } catch {
                safeFallback = null;
            }
        }

        proxyRemoteDownload(safePrimary, res, 0, {
            onFail: () => {
                if (!safeFallback) return false;
                const target = safeFallback;
                safeFallback = null;
                proxyRemoteDownload(target, res);
                return true;
            },
        });
    } catch (err) {
        res.status(502).json({ error: `Failed to resolve download: ${err.message}` });
    }
});

app.get('/api/clash/options', (req, res) => {
    const cdnProviders = Object.keys(CDN_CIDRS).map((key) => ({
        key,
        label: key.toUpperCase(),
        cidrCount: CDN_CIDRS[key].length,
    }));
    res.json({
        types: ['warp', 'amnezia', 'wireguard'],
        amneziaVersions: ['1.0', '1.5', '2.0'],
        dnsModes: ['fake-ip', 'redir-host'],
        dnsTransports: CLASH_DNS_TRANSPORTS,
        dnsProviders: CLASH_DNS_PROVIDERS,
        dnsFallbackByTransport: CLASH_DNS_FALLBACK_BY_TRANSPORT,
        cdnProviders,
        domainPresets: CLASH_DOMAIN_PRESETS,
        ttlSec: Math.floor(CLASH_PROFILE_TTL_MS / 1000),
    });
});

app.post('/api/clash/import', async (req, res) => {
    try {
        const rawConfig = typeof req.body?.rawConfig === 'string' ? req.body.rawConfig : '';
        const remoteUrl = typeof req.body?.url === 'string' ? req.body.url.trim() : '';

        let sourceText = rawConfig.trim();
        if (!sourceText) {
            if (!remoteUrl) {
                return res.status(400).json({ error: 'Передайте rawConfig или url для импорта.' });
            }
            const safeUrl = await assertSafeImportUrl(remoteUrl);
            sourceText = await fetchRemoteText(safeUrl);
        }
        sourceText = normalizeImportedConfigText(sourceText);

        const imported = parseClashImportConfig(sourceText);
        res.json({ ok: true, imported });
    } catch (err) {
        const message = err?.message || 'Не удалось импортировать конфиг.';
        res.status(400).json({ error: message });
    }
});

app.post('/api/clash/profile-url', (req, res) => {
    try {
        cleanupClashProfiles();
        const profileName = sanitizeProfileName(req.body?.name, 'WarpGen Clash');
        const rawNodes = Array.isArray(req.body?.nodes) ? req.body.nodes : [];
        if (!rawNodes.length) {
            return res.status(400).json({ error: 'Добавьте хотя бы один сервер.' });
        }
        if (rawNodes.length > 20) {
            return res.status(400).json({ error: 'Максимум 20 серверов в одном профиле.' });
        }

        const nodes = rawNodes.map((node, idx) => validateClashNode(node, idx));
        const dnsMode = req.body?.dns?.mode === 'redir-host' ? 'redir-host' : 'fake-ip';
        const dnsNameservers = Array.isArray(req.body?.dns?.nameservers)
            ? req.body.dns.nameservers
                .map((x) => (typeof x === 'string' ? x.trim() : ''))
                .filter(Boolean)
                .slice(0, 10)
            : [];
        const dnsFallback = Array.isArray(req.body?.dns?.fallback)
            ? req.body.dns.fallback
                .map((x) => (typeof x === 'string' ? x.trim() : ''))
                .filter(Boolean)
                .slice(0, 10)
            : [];

        const selectedCdn = Array.isArray(req.body?.routing?.cdnProviders)
            ? req.body.routing.cdnProviders
                .map((x) => (typeof x === 'string' ? x.trim().toLowerCase() : ''))
                .filter((x) => !!CDN_CIDRS[x])
            : [];
        const cdnCidrs = Array.from(new Set(selectedCdn.flatMap((key) => CDN_CIDRS[key])));

        const proxyDomains = Array.isArray(req.body?.routing?.proxyDomains)
            ? req.body.routing.proxyDomains
                .map((x) => (typeof x === 'string' ? x.trim().toLowerCase() : ''))
                .filter(Boolean)
                .slice(0, 500)
            : [];
        const ruDirectDomains = Array.isArray(req.body?.routing?.ruDirectDomains)
            ? req.body.routing.ruDirectDomains
                .map((x) => (typeof x === 'string' ? x.trim().toLowerCase() : ''))
                .filter(Boolean)
                .slice(0, 500)
            : [];

        const token = crypto.randomBytes(16).toString('hex');
        CLASH_PROFILES.set(token, {
            createdAt: Date.now(),
            name: profileName,
            nodes,
            dns: { mode: dnsMode, nameservers: dnsNameservers, fallback: dnsFallback },
            routing: { proxyDomains, ruDirectDomains, cdnCidrs },
        });
        enforceClashProfileLimit();

        const profileUrl = `${getRequestBaseUrl(req)}/api/clash/profile/${token}`;
        res.json({
            ok: true,
            name: profileName,
            token,
            profileUrl,
            expiresInSec: Math.floor(CLASH_PROFILE_TTL_MS / 1000),
            note: 'URL можно вставить в Clash Verge как подписку (profile URL).',
        });
    } catch (err) {
        res.status(400).json({ error: err.message || 'Не удалось собрать профиль.' });
    }
});

app.get('/api/clash/profile/:token', (req, res) => {
    cleanupClashProfiles();
    const token = typeof req.params?.token === 'string' ? req.params.token.trim() : '';
    const profile = CLASH_PROFILES.get(token);
    if (!profile) return res.status(404).json({ error: 'Profile not found or expired.' });
    const yaml = buildClashYaml(profile);
    res.setHeader('Content-Type', 'text/yaml; charset=utf-8');
    res.send(yaml);
});

app.post('/api/check-license', rateLimitLicenseCheck, async (req, res) => {
    const rawKey = typeof req.body?.licenseKey === 'string' ? req.body.licenseKey.trim() : '';
    if (!rawKey) {
        return res.status(400).json({ error: 'Введите ключ WARP+ для проверки.' });
    }
    if (!isWarpLicenseFormat(rawKey)) {
        return res.status(400).json({
            error: 'Неверный формат ключа. Ожидается XXXXXXXX-XXXXXXXX-XXXXXXXX.',
        });
    }

    let userId = '';
    let token = '';
    try {
        const { pub } = await generateWireGuardKeys();
        const regResult = await cfRequest('POST', 'reg', null, {
            install_id: '',
            tos: new Date().toISOString(),
            key: pub,
            fcm_token: '',
            type: 'ios',
            locale: 'en_US',
        });
        if (regResult.status !== 200 || !regResult.body?.result?.id) {
            return res.status(502).json({
                error: `Cloudflare registration failed (HTTP ${regResult.status})`,
                details: regResult.body,
            });
        }

        userId = regResult.body.result.id;
        token = regResult.body.result.token;

        const applyResult = await cfRequest('PUT', `reg/${userId}/account`, token, { license: rawKey });
        const detailsResult = await cfRequest('GET', `reg/${userId}/account`, token, null);

        const applyBody = applyResult.body || {};
        const detailsBody = detailsResult.body || {};
        const details = detailsBody?.result || {};
        const accountType = details.account_type
            || applyBody?.result?.account_type
            || applyBody?.result?.account?.account_type
            || applyBody?.result?.type
            || (applyBody?.result?.warp_plus ? 'warp_plus' : 'free');
        const errorMessage = applyBody?.errors?.[0]?.message || applyBody?.error || null;
        const valid = !errorMessage && (accountType === 'warp_plus' || accountType === 'unlimited' || applyBody?.success === true);

        res.json({
            valid,
            accountType,
            referralCount: typeof details.referral_count === 'number' ? details.referral_count : null,
            checkedLicense: rawKey,
            effectiveLicense: details.license || null,
            message: errorMessage || (valid ? 'Ключ принят Cloudflare.' : 'Ключ не дал WARP+ статус.'),
            httpStatus: applyResult.status,
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    } finally {
        if (userId && token) {
            try {
                await cfRequest('DELETE', `reg/${userId}`, token, null);
            } catch {
                // ignore cleanup error
            }
        }
    }
});

app.post('/api/generate-test-license', rateLimitTestLicense, async (req, res) => {
    try {
        const { pub } = await generateWireGuardKeys();
        const regResult = await cfRequest('POST', 'reg', null, {
            install_id: '',
            tos: new Date().toISOString(),
            key: pub,
            fcm_token: '',
            type: 'ios',
            locale: 'en_US',
        });
        if (regResult.status !== 200 || !regResult.body?.result?.id) {
            return res.status(502).json({
                error: `Cloudflare registration failed (HTTP ${regResult.status})`,
                details: regResult.body,
            });
        }

        const result = regResult.body.result;
        const account = result.account || {};
        const accountType = account.account_type || 'free';
        const license = account.license || null;
        if (!license) {
            return res.status(500).json({
                error: 'Cloudflare не вернул license key для нового аккаунта.',
            });
        }

        res.json({
            source: 'official_cloudflare_api',
            accountType,
            license,
            id: result.id || null,
            note: 'Это легальный FREE ключ нового аккаунта. WARP+ ключи не генерируются.',
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/generate', rateLimitGenerate, async (req, res) => {
    try {
        const {
            licenseKey = '',
            configType = 'amnezia',
            obfsProfile = '1',
            endpointPort = '2408',
            endpointIp = 'auto',
            quicPreset = 'yandex',
            dnsServer = 'malw_link',
            splitMode = 'full',
            splitTargets = [],
            protocolMaskingEnabled = false,
            protocolMaskId = '',
            protocolMaskIp = 'quic',
            protocolMaskIb = 'firefox',
        } = req.body;
        const normalizedConfigType = typeof configType === 'string'
            ? configType.trim().toLowerCase()
            : 'amnezia';
        if (!['amnezia', 'wireguard', 'wiresock'].includes(normalizedConfigType)) {
            return res.status(400).json({
                error: 'Неверный тип конфига. Поддерживается: amnezia, wireguard, wiresock.',
            });
        }
        const isAmneziaConfig = normalizedConfigType === 'amnezia';
        const isWireSockConfig = normalizedConfigType === 'wiresock';
        const normalizedEndpointIp = normalizeEndpointInput(endpointIp) || 'auto';
        const normalizedEndpointPort = normalizePortInput(endpointPort);
        if (!isAllowedWarpEndpoint(normalizedEndpointIp)) {
            return res.status(400).json({
                error: 'Endpoint не входит в разрешенный список.',
            });
        }
        if (!isAllowedWarpPort(normalizedEndpointPort)) {
            return res.status(400).json({
                error: 'Порт endpoint не входит в разрешенный список.',
            });
        }

        const dnsLine = await normalizeDnsLineForConfig(DNS_SERVERS[dnsServer] || DNS_SERVERS.malw_link);
        const normalizedSplitTargets = (splitMode === 'selective' || splitMode === 'blacklist')
            ? normalizeSplitTargets(splitTargets)
            : [];
        if ((splitMode === 'selective' || splitMode === 'blacklist') && !normalizedSplitTargets.length) {
            return res.status(400).json({
                error: 'Включен split tunneling, но не выбраны сервисы/исключения.',
            });
        }
        if (splitMode === 'blacklist' && !isWireSockConfig) {
            return res.status(400).json({
                error: 'Режим blacklist/direct поддерживается только для WireSock-конфига.',
            });
        }

        const profiles = {
            '1': { jc: 4, jmin: 40, jmax: 70 },
            '2': { jc: 120, jmin: 23, jmax: 911 },
            '3': { jc: 10, jmin: 100, jmax: 300 },
        };
        const { jc, jmin, jmax } = profiles[obfsProfile] || profiles['1'];

        let i1 = '';
        if (isAmneziaConfig) {
            if (quicPreset === 'none') {
                i1 = '';
            } else if (quicPreset === 'random') {
                i1 = QUIC_PRESETS[QUIC_KEYS[Math.floor(Math.random() * QUIC_KEYS.length)]];
            } else if (QUIC_PRESETS[quicPreset]) {
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
        }

        const { priv, pub } = await generateWireGuardKeys();

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

        let accountType = 'free';
        let licenseError = null;
        if (licenseKey.trim()) {
            const licResult = await cfRequest('PUT', `reg/${id}/account`, token, { license: licenseKey.trim() });

            const body = licResult.body;
            const acType = body?.result?.account_type
                || body?.result?.account?.account_type
                || body?.result?.type
                || (body?.result?.warp_plus ? 'warp_plus' : null);

            if (acType === 'warp_plus' || acType === 'unlimited') {
                accountType = acType;
            } else {
                const rawErr = body?.errors?.[0]?.message || body?.error || '';
                if (rawErr.toLowerCase().includes('too many connected devices') || rawErr.toLowerCase().includes('too many devices')) {
                    licenseError = 'На этом ключе превышен лимит устройств (макс. 5).';
                } else if (rawErr.toLowerCase().includes('invalid') || rawErr.toLowerCase().includes('not found')) {
                    licenseError = 'Ключ WARP+ недействителен или не существует.';
                } else if (rawErr) {
                    licenseError = rawErr;
                } else {
                    if (body?.success === true) {
                        accountType = 'warp_plus';
                    } else {
                        licenseError = `Ключ принят, но тип аккаунта не распознан.`;
                    }
                }
            }
        }

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

        const epHost = normalizedEndpointIp === 'auto'
            ? 'engage.cloudflareclient.com'
            : normalizedEndpointIp;
        const ep = `${epHost}:${normalizedEndpointPort}`;

        const address = [ipv4, ipv6]
            .map(normalizeInterfaceAddress)
            .filter(Boolean)
            .join(', ');
        if (!address) {
            return res.status(502).json({
                error: 'Cloudflare не вернул корректный адрес интерфейса',
                details: cfg.interface?.addresses || null,
            });
        }
        let allowedIpsLine = '0.0.0.0/0, ::/0';
        let disallowedIpsLine = '';
        const splitTunnel = {
            mode: 'full',
            selectedTargets: [],
            resolvedAllowedIps: 2,
            unresolvedDomains: [],
        };

        if (splitMode === 'selective') {
            const splitResolved = await resolveSplitAllowedIPs(normalizedSplitTargets);
            if (!splitResolved.allowedIps.length) {
                return res.status(400).json({
                    error: 'Не удалось получить IP для выбранных сервисов.',
                });
            }

            const selectiveAllowedIps = new Set(splitResolved.allowedIps);
            for (const dnsCidr of dnsServersToCidrs(dnsLine)) {
                selectiveAllowedIps.add(dnsCidr);
            }
            const finalAllowedIps = Array.from(selectiveAllowedIps).sort((a, b) => a.localeCompare(b));

            if (finalAllowedIps.length > 512) {
                return res.status(400).json({
                    error: `Слишком много маршрутов для split tunneling (${finalAllowedIps.length}). Уменьшите количество выбранных сервисов.`,
                });
            }

            allowedIpsLine = finalAllowedIps.join(', ');
            splitTunnel.mode = 'selective';
            splitTunnel.selectedTargets = normalizedSplitTargets;
            splitTunnel.resolvedAllowedIps = finalAllowedIps.length;
            splitTunnel.unresolvedDomains = splitResolved.unresolvedDomains;
            splitTunnel.fallbackDomains = splitResolved.fallbackDomains;
            splitTunnel.sourceDomains = splitResolved.sourceDomains;
        }
        if (splitMode === 'blacklist') {
            const splitResolved = await resolveSplitAllowedIPs(normalizedSplitTargets);
            if (!splitResolved.allowedIps.length) {
                return res.status(400).json({
                    error: 'Не удалось получить IP для direct-исключений.',
                });
            }
            if (splitResolved.allowedIps.length > 512) {
                return res.status(400).json({
                    error: `Слишком много direct-исключений (${splitResolved.allowedIps.length}). Уменьшите количество выбранных сервисов.`,
                });
            }
            disallowedIpsLine = splitResolved.allowedIps.join(', ');
            splitTunnel.mode = 'blacklist';
            splitTunnel.selectedTargets = normalizedSplitTargets;
            splitTunnel.resolvedAllowedIps = splitResolved.allowedIps.length;
            splitTunnel.unresolvedDomains = splitResolved.unresolvedDomains;
            splitTunnel.sourceDomains = splitResolved.sourceDomains;
            splitTunnel.disallowedIps = splitResolved.allowedIps.length;
        }

        const maskEnabled = Boolean(protocolMaskingEnabled) && isWireSockConfig;
        const maskIdRaw = typeof protocolMaskId === 'string' ? protocolMaskId.trim() : '';
        const maskId = (maskIdRaw || 'lenta.ru').slice(0, 160);
        const maskIp = normalizeProtocolMaskField(protocolMaskIp, {
            fallback: 'quic',
            maxLength: 32,
            allowed: PROTOCOL_MASK_IP_VALUES,
        });
        const maskIb = normalizeProtocolMaskField(protocolMaskIb, {
            fallback: 'firefox',
            maxLength: 32,
            allowed: PROTOCOL_MASK_IB_VALUES,
        });

        const interfaceLines = [
            '[Interface]',
            `PrivateKey = ${priv}`,
            ...(isAmneziaConfig
                ? [
                    'S1 = 0',
                    'S2 = 0',
                    `Jc = ${jc}`,
                    `Jmin = ${jmin}`,
                    `Jmax = ${jmax}`,
                    'H1 = 1',
                    'H2 = 2',
                    'H3 = 3',
                    'H4 = 4',
                ]
                : []),
            'MTU = 1280',
            `Address = ${address}`,
            `DNS = ${dnsLine}`,
            ...(isAmneziaConfig && i1 ? [`I1 = ${i1}`] : []),
        ];
        const allProcesses = isWireSockConfig && splitMode === 'selective'
            ? [...new Set(normalizedSplitTargets.flatMap(k => SPLIT_TUNNEL_TARGETS[k]?.processes || []))]
            : [];

        const config = [
            ...interfaceLines,
            ...(maskEnabled ? [
                '',
                '# Protocol masking',
                `Id = ${maskId}`,
                `Ip = ${maskIp}`,
                `Ib = ${maskIb}`,
            ] : []),
            '',
            '[Peer]',
            `PublicKey = ${peerPub}`,
            `AllowedIPs = ${allowedIpsLine}`,
            `Endpoint = ${ep}`,
            'PersistentKeepalive = 25',
            ...(isWireSockConfig && splitMode === 'blacklist'
                ? [
                    '',
                    '[WireSock]',
                    `DisallowedIPs = ${disallowedIpsLine}`,
                ]
                : []),
            ...(isWireSockConfig && splitMode === 'selective' && allProcesses.length > 0
                ? [
                    '',
                    '[WireSock]',
                    `AllowedProcesses = ${allProcesses.join(', ')}`,
                ]
                : []),
        ].join('\n');

        res.json({ config, accountType, endpoint: ep, licenseError, splitTunnel, configType: normalizedConfigType });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`WarpGen on http://localhost:${PORT}`));
