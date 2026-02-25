const express = require('express');
const https = require('https');
const dns = require('dns').promises;
const crypto = require('crypto');
const net = require('net');
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
    // Verified real captured QUIC packet (ya.ru)
    ya_ru_capture: '<b 0x02000000450004fe00004000401124f30a08010305fffff2ff4601bb04ea3dc6cd0000000108cf372eb1c5c5fe8f000044d08974fe2db906297b34eca003e69509523d6ba0b7717b5b9fc8eb4fcb9b1c9fc0208819ab797a5be1c96a954517640d526cd85324a36c7fe1e4607f2b5e74f507533d973b7e49ca8a5f8fde34afadbd9a4a68cb72df0889d868ab4bd9e886486dc6c98aefbad367f07b6157e2ff201e80006e1a2e787414362fda9c040c4e44b0cd9a3d30283f5fe5cbbc7c687a41771f28611df08fb79852d73f9a533e515659694c00bbdf60111244d1a3c8e767dbd44d8e1b88b5fa3eb382c54ac2be0205839b85daba6d66be3713b13eb589e7ec95e898f202292410a1b279be255f20e594780ef076f1f9fed57bb4aca0c7617c0de007d83b1ad9c434adf12c48c2ad25a7fec5d0e9a15775a986e3ff3e9c64102e4eeec60e23ab668a3abbe6fbac03abc4db59adfd792545340f260ecf08ee41d4ebf991bda29e0360dbc0eb469bac14f45f3828317e892f46873da22b35fa25bf4e674bf4e7c7da0a22509f41a1aa954fafc50c2a2973a8aab4fc30a6eee9bf868bc594f904ba33cb5589deef807a8962962ec5226e6d9872aa4c396ecdbf5adbaba777837bcff86a9f7b6f847e6c067286dd2959901fa94f0acf110fed2108cac1434e57337f0aa2236d53b2fcf07063ce0e6eb6d55736b2c48096a574b384a2197e3f3e30f79daa825ef60fda14732bec2fd7c4926e7259b349bb9901eb7a2b56ecbab02f32e72d5df3541263e87ff29f064b07e28b788ead8a5e350ee4d175959a34d6464744e84f9110111e8313213713431013d8d06a15383d4203431b37ef072f7545499c81e96c694422de131723cb79cf7f760ca849cac3121442542d1d41576fea14a0f4854dc75f9a21fd7f5ef7d2c2ae9a89408ae672748910ea623a03998019b572068c70d1688f07d036c78df6e47ac7fc37e2ec736f58a18749c6eed5ed4ae58004dbec58de9040cf0579270f5a1499828024119316f0dfa81972feef9541f96ceda2c8b7965f8342798a7aa70e37885afe08b9f5d7b58f224b8afcab02b6fb126dd215de1e6906f46dfc78e2329657cf6fd340ba2cf5be5e27ea0bbc3e95323d635b4321bd2fc75e15dcd4cca794a64876942f37ec43e8636e5f1a208fc37ceadf25ca8156f4a76794ef2eacdec4d437937d0a1a24dbb84f3e8160b4d4a5e89485f5bc3443b27ba0302ea4227b1997a6be19bfbec4d4fb36f8c705c1005720afd50dc545c25b3a697d67ac4436d2a6dbf37231d6585f2eff7ee5475f60df2d7180a61901bfc7202201575dfb3263315ff10fbe1db6c9c81c9cec5501b0b271e4fbf883f74ef1e88aa3af13dcf0510981d85a223e38437b94c332f25023e39d2a7e1a99ae4a90a723a2d7de271a2cb9cee7e71fe940b9c32bd0fdea494dad65e55ec8160470bd443e7d4c0c3079ed4b66197907b9c1d59b29aea927a47bd1e5cbb6e856d50a10521e80b4d188624902b638403344bc7fc9f5e8dd6cf4b841e324eccdb22924427c17be09d36bb57cf583f2022030eaf0fa96f369cf8d8c6ee03dacf980259d109616fbd1e21c4877c25ed3c05fad32f62b21c0593a698af2e7f01063976cacf4305a93e080844a0dbab8de7760f41b451d1fdc0a921c28959832f82f1b04d640b1bb209eb17bf5501b95909831853c31e840118b99064c40667446d87edc7a38e2f03c01d0256d685260b935a76f03720e43d0a41352e34ba7987d63e05f0d124cfe3ec15ec5f7a4659a7486dc083103e4e9ed>',
    // Verified real captured QUIC packet (Cloudflare 172.64.41.3)
    cloudflare_capture: '<b 0x02000000450004fe00004000401155a10a080103ac402903f38701bb04ea63a3cc0000000108b59c7b5317dddb9d000044d0f5dc768fc8479d149c4e1640e24e07ffd673cbf381e508b09c453a34ea5a5bd2922c3e30cd4525fae8b3688810e21634edcab8e4aa8cbb848e1db5947148b843c7bdf7cb95e3ed9be3ebe0ae3866ff5b8267684dd9e27f00ff5d49098195d3d9614f1943160d795bc5c05920e6bb7297eed99272a833b8132a4c1d05de5594fa4eb098ab242868a5af025bc0e391b9fae60a9328643dcbeeb5b4672347de6ae7c67d583892ae002bdea5c5a7eee4326b90e68ecf0148a72f926583d6020a07212bb457c1fa44b010527e9e3f8b8f3f2b4ad3be45f82767b266566e10457991e38139060c5458f13cf46ddea70f703020772bc43f781ade846a44ee2ba4f2bc1c94e2eafd4966ef4c7a78edb65588fdc1f5724e1ec7e01b2b862bd243dbc4145cb28b9ec4ff92ace7c840caf80b0fbd6757f866a37439f6c576ad23a89a0953a2e3d2f7b95875cf7867f73cb15a19a00a319c6903252ff85751a9f50709301cafcbcd4cbca9a646587aa7644bf3bbf5599731c2d32c7f78ddc743b011fcd0580f93b6e9cf2048f2861387c5c4eae9a983a604c2f96e877984c6a114662f8025da49e462dfbc5891da7e2723b50547bd1171380e13d2a929aa1039f244054985ce6e4deafdd0e66781be3c57e7bc498d37266926f1a7b47875bbc38d35089742f1bbae96362dd22287d0f980d90361cc42d9619f8a43abad0bd0c5cdaa0c9c759674e1973ee5600988570c89857114981c4a129c030fc2706a2bb829ed40368b9c27665608c3f6e06c21da9b852a1edaf04f4d15df8f1010163df3f02b5aeaacf72bf2ae590b04c7e134c22834d453b3b10e0a21732d71977d12530f5299f543b2d273a8ec8c5f63d1fedba3dd2575143cbfba65dc02045b8a0662083af598eaf6b8f4b5e72bb43fa360bbf250c1a34bbd5b76acf019815f2088a266cf65ef5e2537250f2c2d57fd5221f9ba760bc7a6abe71e1bebdd3a962f367c30464ad0c0567b1d96b1831dc3503b38b60f77fb8bf9e49d960b657a2841e6c12dbc2c13f596386d9bfb7e0e8a5622ef20c5cada2266e9bc9e4f12f3a23b4ef9643d270aa3a30f0705eba691a0e662119af38a8a889105747504276063da120b809c0ce46379f4df6cd99c708021eee3175935ecddedaddf561bcd1e8a0828c7422114ef6214e2237705f3ca3f54eada9cc7c5f603522e877540aa3a57d74b48fd2cd8f8d594348300a9ed6e1094c05670aeb4c9534c655a8b7dc60180047686e58cc74cdcee57e2cb268ace7397f5ba254a26ed4a4b222f92bf5c349b13741f437118cecad9acb49bb316da6de4874d659737489d00972df8b95d621b625acc6500535e7c20fb006fb3ceb32de1282639c9229e5a7a3b8ee7778c8cbc9d38f3bea7de337a74e283b8cd4915802252e67c7855b031d05ecccb2fc1e8937e52f2283abd234fb89b52e0367fe0d0b692164d6d7a9e0d25350b91e455390c57831f8f84e469b9a7c8c99a25423b263093c939117e50fb6eddbdca9c48d7deee1ba5b40751bec923b0d18b773b0cc74392b8b874be89260d5be7d8eac4cb09e1fa0a39a58bfee5380b68d561bfbc9ec7432e608814df187165588c799857f9e10230a5becf267e0ef6b0455888d291e9bf359c7f388648e65fb32f9ad8a1be7f9d9c21ff0dffc2870f381f589b772be07a644416a1c1a409f8a1cc1f2c46cccb091fb0d350faea2d1ec057cfa1268172848a4fa02aded704>',
    // Verified real captured QUIC packet (Google 64.233.161.94)
    google_capture: '<b 0x02000000450004fe000040004011489d0a08010340e9a15ec73e01bb04ea71d1ca00000001088be83851d332138a00404600e5708422454eb06dd454d6bca529b82006cc8c8f9425357331566918bdeb5c599b2a874af15e213bce044ed2790ff29ecbb4af203aaa25dc8f4d4b372ac399af3d833098ea44898aa175aed82755a9419e269aebe607f65534fc5fea00a382151c447fb575f85d5817714e77afe5d3e76d3f9d5a886feac4bc14fd17d35aa6604893cc1444f5c26be9001202da62168c092843982f17e6ef3d291e7f7eea1797e97d6105c63516b860f0940ece34be539146baf2be2f91405dcfdeb55f9534ebccc0cc6622c5e73e0d1825d8bb19d411bdc8ac5dbbdc688da901b7b67ac3b8340d3d2248ff973fd8814a8450896f2da563bb88eb87cd6825515daa7860bd31d85e47c10e6ecdf998acc654b50954387d35e90b5a6f9f0eb731e01257ec897188b08dba2e9fa8157e7934efb7fb2f6d3928c9172bd25d83284eddd6d85849d2e40ff477e32b76fdf383d7ae4cb6ca1e11fae9d37094fa8512a98de10d585de952a82e2ee7ebdfd59a077052382b4898e36509b654851c4dc9535c9f65a6dfb447edb2d4c2342a52c2c8dafd23d2485e4f5c242b6b6f8f6f58929221a82f262d27af2b0fa1e294467bc98679eac3930edac5ce663f41a1e76f0b18374aa9bf67d2bc738591c1a6d7008d270563bf50bcbd73ba6888a18280b08a52f5ccc469d59d3b7b464692f9d720ac07eb35d2ecf2c66c608df67563bf86d8e29917b531045964366377a865c181f3f21d6d6e7391bd23ec66e9eee11f2071d7d93df7bd23358bd658cb31ac5432dc185fbe439c2f6c96307237049a80b3b704fad5a0766ffa590490f645f55d7d51dc35dfb41314a113dd2e88c1c5db683f2c0941af31ace0b57aba60376f42701fbcea42cf284261821542ddf7351a7ea5ca0dbaeb54ebb1cf3703a30d6bd9f4f5bf8cb773ecf32c1e830666a38bf9ba7f382770d3def0e22338782d796d6cefb4b347f26444ba44d2c99e69e7fe44f2a4de1f2ab9cd477d3b9dc501a7c47436acc2350eb203d2521f89f25e8550375e7e9e142bb94b1ee485fea389f2c585e25e6390fcd2bc953372d4c083a155385bc5ce3b444f76df96ae4c1362fd7c117ac9859852d94fe1e5dce08905317e10a48fc333bff1ffddcf98242c49383a0b85877d22296c2b3cb42ac0a3ae493a5d618c7779d67ddd64207aa6d2fb43c1273192b906edbf2d3ccddd3ec2cdd1f2182ebb213bec3270c7f3afa7d8d0bcf220e76c4898013d18116051ab7a59d7f046583b195c0f461a8c4c8b0a1c597293b8faf068f7bc7ca4b26731f63b54c16c20855fdc756c0b322b89b342fb097f61bb8c843e034ad71478f4521af06aff4853ee113a9202deb1c64f763c65ae47c8df54e01747137fe9111bc0122155a94abec038c1999d077853d6bd25c67ae82bbf34dcd5a6fbaeabc01a6d0d67f2f2269f42e4bc702acd38cd767bf2ed59369ba4cd81135f4aefed786a12d7dc3088c71066e233bab7b6e82bdb4022f232d9ced5a5ec9dedc54065825a3f0a77c1123fc0899b7423550fb94ad590366f659916e9b4bb60d7ddd2a24b15915883d3998ecb53f9bfe0a94d8778935027fd3d1fe113548d2e233fc03bd99d3e5d47d8a99f9261541ea746b1f5f89fcd764834ef9e1c5f76ceb771185553d34aca16b3103563331537a90197f62aa84b6d8936ccd6407453eb1987307904e2cc860ff76f07b76d44668ead78f0e6ae9a9bba766bd0c315ac0e0c72f09a82c9>',
    // Verified real captured QUIC packet (195.85.59.162)
    capture_195_85_59_162: '<b 0x02000000450004fe0000400040112bed0a080103c3553ba2fa5801bb04ea837dce0000000108e75bbe163a455fc8000044d050419383bcdee4b02a1ae12f7fdc0c77ce54baad7c5f0fd1b1272301b865bc6091ae57a11d28f63a64542022fe54a807b530f7a50abefec317140682e21cc5b215fbb68879365fd57696af9241e01faacfacb386e5724320f864b5b209b752b7f2ad0c96e528e36cc7e72b4b8847a0ee3bc9a03b351db5138bf7de3c76f3e20545d91a3e9ec107800ffb88c44192c2169832fe16ceea96af02efe5ca65ef8ec02119e099840080145f04a679a2b8497b649c75f4ed60239bc05033af91eb66953e11ac8e93306f7a5bf799f552576dee0b5883d55e78d8a6acc0f91ebd3624f9ff051820785e869d612b1c5019155835cc198c758ec5bb5bb88f93aca709b0a77b313051a3e2d3cb3ac3251b91b2a1b3fcb8844d99a84f856acd00747c665e48800425ca5ad250f45da49be11b62a2f2384fdfda66717081fab5868d4f25cdc854cd587fc0eee2dd997dd6f4b073e4b1d5d93b56e0bddde79660e0aa2eeeda0feeeb3a73a301208476c7d11664cbd6f67e07dd167763ec8e7236af42bb80c9e2ed999992b78d8fdce14dcc5c43fb45b37915da30d5c1c2c08475a6e899a611054c2c0d0995071a0ea5c7746089984022328a1168badeca79ef47422c360f32223f6e33355f0211f1445b99e18cbc4271db7b3c843f01203ad15a932c9ebd403829b1f1aeb9291a4c4e069df0dc4c88a8cb14dfa4cde33ea69dc5dba26c1c1727072d2b1b8966bc275353f3a1b4e63bbf338ae3b131e7a5e687782d69b3a766d1d297d1f346faf6eb3d5ab471d18f2d371f6244229db58b8fe445a23232e68cd42c92061e4f6e729498be9d83959afa542bc57a7ad61cfbe91cd316a5b4cebb9beb5f86ec74ec5198ce5d78c47bdeaea510775661d7bd4a7d127ef9f62acb224c19ca8dd86a8df16154dda9691dcc0edd8e0b866201a46c46c5a2ac1efd9c7559f77a5065ed9ac3df6acd79ebcb0132e29ad5bb7d28a7be350a3deea4062b811eb0e9d40bb7846e7adaae47ba2adface6187879c0cc7269e0978c9b365fc8350f2043fd74dc0bec77874d13c3c624e4272cb13003928736d0736b4e22e766ecbb512145b82be2b222ece3c651353f86ce0cd7de89f2f7f89d479f16dc3035a958dae982d2c82ef3b67a3ec1c57132fddd82a38518e94370fa045eff42df52b87b4d3b0c96d75545d362cdb3edfbe4f1711d79f4499efb7a3888b339a4387fb33ca21d32f2af8eae646418e62f4dbd041d721d7e1be49394c9a871658dca7df36d46c0a354925c4f6a04592bc195fb27b362e64f644e615a235359d9957b6a2cb33613dd284d95af0e33100a80d7bd6a9806b03facffb0ee5172cab44af43e37e3baa8e955da08b8019300ecde0d04a1933a432ec80fb58ef1e316e6ce858134119dd72e2c3f670a24538e9985f319877ae50f7ce4ab1304a761a90b58595c870123a1f7c67df27a29a07dd007f52c98d1437b954926e9f59e6645a5f796a2cfe9874456010ab626529a9cc54b6457d532c48ded16adf5a846b71de14913854b1365e810fec5b202874cd54fab0ef89549be8352cef3ce2f029730d01ff81d6521c0230f9fdffed0dfd4ded780a1f2e410acba61f7a7a5f155b382a40bdd127efa8c16a2c09a41bf4373d79fb8ac742325c8850bb98c5513ab52e5f738bc458fb5c6d050b94cbc2b86a077353f0f25be928b9b32f9585ba84aff7926ff0796922ae64a397e70dc88e7757d1388051839cb>',
    // Verified real captured QUIC packet (87.245.197.142)
    capture_87_245_197_142: '<b 0x02000000450004fe0000400040110d610a08010357f5c58eefac01bb04ea1598c4000000010852f2fdb53a46781c000044d004d25e2fb615972a1d53d8dd5c4c9e478b2c0e373e254e89193779fc59ab1ad91100721e2ed2fbed95f05cdfcad08f0a664f0d4a2873585a68ba2bea4509ef72bed9ec6e768ed2b948bd6885293f690aa6104a25a652ed5dcc65bc29ddb62b7aab411ac8f9fe293473d15070f77878de54dfb628949049144af2a4f51ef8760ca9b183a3cba948c113104c1953d2458430dc8d6f773e69ed8c124824042ee37b0aa1a18f22bc42cb008c0a95c246a93ffcde653da47ab32bc779d360af3a90db8f12a6ade988a29e8107843ced66b173ad2525c8771886f08c0aea9f3354a58050ab71f88476b445b174220bfe87fb4a4ac6dc49ad9fdbdfad1b0d6417913167df741b7bdef8c9bfec114e621dfe11eae9d3dbb890ae7c8df2c985c4bd3666323c386b62815eed2fb504314e9f020021dfeb44a7db4e13630674a83a51417af6c2c0a168fbe86254f4cdb691a60679fe651470bed37974f75f7246fa2a3a3b5b64fc0afc91c445924921e909dd0f9893bf14c56c8c7b9020506e68ca734e187affd96b67004eef6643d6d53ccce416aec032e3c4106fb44159c7bf72dea3ccf1f4e47232ccde706327fdb6044223eb42dd414fd7c316ab5fa6b479ba191014124142c018ff3ab545d599c9028e470d56d256b8baf19f1a5ed80a9377cc9604b3e1c36271a6a88714e0c6340d6e828e55e2b332673e92c344e76afaa6a435ff8f729e9e21707cd9242fe568cf121a7a3955a60a38ffe3b3850b60a280e6db50af3ccf3e3f4982eb9a0ced349813bd1c4b2e6f531c71a9d338921af2f824b23bf3bed336f01951719cdf409252d0abf476028019760ff11288d61c99a6026da4d34ea4930bf929f082d4659df1a6b8585270fec919f67b692b4d7dcb320401206b716530a9479ae838442fa39b7cfb000661350a7fc1b652cc31a5cb4b4154151ac9d9d02113c8df79bd73d258f49d64f97a6ee36e48561a21098879fae12d0bed5dc4dc7075ccd3ab8dc11333e6b4d282f357cd848e753b95bbe16b0a42998d53f5d8ef0ccb8f7e6fb37d2d889d44ec7dbf789c903f7cfb7a0ef6325f530531d7c7e5601dbdcfeeb13655c498cbaba070fe301a11fdca27d7fe75ace8a1c07119c0f2a0a900930feb7193d7fcfbb04f13c0cf4d7b101043a253cb8e5d7cf7c58cb2b878dab118dc09d2e4f1dcb29895dacc61267abc5dda271b094154d218e50f9826f8c4badcb7be3b67bae33a40d4c290e9de48f060b3a39846f73fa13d133ace35faef1eddedc4a51a57848c04943a85da62236a700006b54cad929de6d95efc54b89252d92e5a1b4b57bd2e181e442fcf05ae111f9615fedd6614de8203b2e9d02dc34bc4cb8df4fa03363a5b18cc78b71103b28662dd28dbff0608511cde742706fd476e8cdecf96540c85c2c3b86edd28898a2a58221bd75eb93b3ef1bc64d4510222aab46ec43a6f5964b4e311dedb10c3222723c301cd34441f8dae12edc0718ec3e0628e6eafbe0946689501dc7ee01fd458d02c5bb7ddf4978bdddd9c2eb7b2b7c4a5220783733a86d47ecb505100c445a126b17a1dbc42d7a9565b90971c9deae29a3f83e69316d2242d6b52de52971936cf33c26464ecbade3405bbdbf911bae1670ff3959ccb76fb63ba91fa6be1b799ea275818d833e165b6dba06b19c62bff570a0f601806408f9e8da5afee6190b06d5732acc1dc032cd98e60e16fc5c11cde9374894e61798bdca8>',
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

// ─────────────── Split tunneling targets ───────────────
// Important: domain-based split routing is best-effort.
// CDNs and game backends can change IPs frequently.
const SPLIT_TUNNEL_TARGETS = {
    discord: {
        label: 'Discord',
        domains: ['discord.com', 'discord.gg', 'discordapp.com', 'discordapp.net'],
    },
    youtube: {
        label: 'YouTube',
        domains: ['youtube.com', 'youtu.be', 'ytimg.com', 'googlevideo.com'],
    },
    x_com: {
        label: 'X.com',
        domains: ['x.com', 'twitter.com', 't.co', 'twimg.com'],
    },
    instagram: {
        label: 'Instagram',
        domains: ['instagram.com', 'cdninstagram.com', 'ig.me'],
    },
    twitch: {
        label: 'Twitch',
        domains: ['twitch.tv', 'ttvnw.net', 'jtvnw.net'],
    },
    telegram: {
        label: 'Telegram',
        domains: ['telegram.org', 't.me', 'telegram.me', 'tdesktop.com'],
    },
    steam: {
        label: 'Steam',
        domains: ['steampowered.com', 'steamcommunity.com', 'steamstatic.com', 'steamcontent.com', 'steam-chat.com'],
    },
    faceit: {
        label: 'FACEIT',
        domains: ['faceit.com', 'cdn.faceit.com'],
    },
    whatsapp: {
        label: 'WhatsApp',
        domains: ['whatsapp.com', 'whatsapp.net'],
    },
    viber: {
        label: 'Viber',
        domains: ['viber.com', 'vibercdn.com'],
    },
    jetbrains: {
        label: 'JetBrains',
        domains: ['jetbrains.com', 'download.jetbrains.com', 'plugins.jetbrains.com', 'account.jetbrains.com'],
    },
    tiktok: {
        label: 'TikTok',
        domains: ['tiktok.com', 'tiktokv.com', 'tiktokcdn.com', 'byteoversea.com'],
    },
    apex_legends: {
        label: 'Apex Legends',
        domains: ['apexlegends.com', 'ea.com', 'origin.com'],
    },
    ea_app: {
        label: 'EA App',
        domains: ['ea.com', 'origin.com', 'eaassets-a.akamaihd.net'],
    },
    battle_net: {
        label: 'Battle.net',
        domains: ['battle.net', 'blizzard.com', 'blzstatic.com'],
    },
    cs2: {
        label: 'CS2',
        domains: ['steampowered.com', 'steamcommunity.com', 'steamstatic.com', 'valve.net'],
    },
    hearthstone: {
        label: 'Hearthstone',
        domains: ['battle.net', 'blizzard.com', 'blzstatic.com'],
    },
    pubg: {
        label: 'PUBG',
        domains: ['pubg.com', 'krafton.com', 'pubgmobile.com'],
    },
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
    if (!host || net.isIP(host)) return host || '162.159.192.1';
    try {
        const addrs = await dns.resolve4(host);
        return addrs[0] || '162.159.192.1';
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

    await Promise.all(Array.from(domains).map(async (domain) => {
        const ipType = net.isIP(domain);
        if (ipType === 4) {
            cidrs.add(`${domain}/32`);
            return;
        }
        if (ipType === 6) {
            cidrs.add(`${domain}/128`);
            return;
        }

        const [a4, a6] = await Promise.allSettled([dns.resolve4(domain), dns.resolve6(domain)]);
        let resolved = false;

        if (a4.status === 'fulfilled') {
            for (const ip of a4.value) {
                cidrs.add(`${ip}/32`);
                resolved = true;
            }
        }
        if (a6.status === 'fulfilled') {
            for (const ip of a6.value) {
                cidrs.add(`${ip}/128`);
                resolved = true;
            }
        }
        if (!resolved) unresolvedDomains.push(domain);
    }));

    return {
        allowedIps: Array.from(cidrs).sort((a, b) => a.localeCompare(b)),
        unresolvedDomains: unresolvedDomains.sort((a, b) => a.localeCompare(b)),
        sourceDomains: domains.size,
    };
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
            splitMode = 'full',
            splitTargets = [],
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
        const normalizedSplitTargets = splitMode === 'selective'
            ? normalizeSplitTargets(splitTargets)
            : [];
        if (splitMode === 'selective' && !normalizedSplitTargets.length) {
            return res.status(400).json({
                error: 'Включен split tunneling, но не выбраны сервисы.',
            });
        }

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
                    error: 'Не удалось получить IP для выбранных сервисов. Выберите другие сервисы или попробуйте позже.',
                });
            }

            // Keep config size under control for clients with strict parser limits.
            if (splitResolved.allowedIps.length > 512) {
                return res.status(400).json({
                    error: `Слишком много маршрутов для split tunneling (${splitResolved.allowedIps.length}). Уменьшите количество выбранных сервисов.`,
                });
            }

            allowedIpsLine = splitResolved.allowedIps.join(', ');
            splitTunnel.mode = 'selective';
            splitTunnel.selectedTargets = normalizedSplitTargets;
            splitTunnel.resolvedAllowedIps = splitResolved.allowedIps.length;
            splitTunnel.unresolvedDomains = splitResolved.unresolvedDomains;
            splitTunnel.sourceDomains = splitResolved.sourceDomains;
        }

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
            `AllowedIPs = ${allowedIpsLine}`,
            `Endpoint = ${ep}`,
            'PersistentKeepalive = 25',
        ].join('\n');

        res.json({ config, accountType, endpoint: ep, licenseError, splitTunnel });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`WarpGen on http://localhost:${PORT}`));
