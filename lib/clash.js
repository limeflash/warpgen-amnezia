const zlib = require('zlib');
const net = require('net');

function createClashUtils({
    warpWireguardPublicKey,
    normalizeInterfaceAddress,
    isDnsHostname,
} = {}) {
    if (typeof warpWireguardPublicKey !== 'string' || !warpWireguardPublicKey.trim()) {
        throw new Error('createClashUtils requires warpWireguardPublicKey');
    }
    if (typeof normalizeInterfaceAddress !== 'function') {
        throw new Error('createClashUtils requires normalizeInterfaceAddress');
    }
    if (typeof isDnsHostname !== 'function') {
        throw new Error('createClashUtils requires isDnsHostname');
    }

    function splitCsvValue(rawValue) {
        return String(rawValue || '')
            .split(',')
            .map((x) => x.trim())
            .filter(Boolean);
    }

    function parseWgEndpoint(rawValue) {
        if (typeof rawValue !== 'string') return null;
        const value = rawValue.trim();
        if (!value) return null;
        let match = value.match(/^\[([^\]]+)\]:(\d{1,5})$/);
        if (!match) match = value.match(/^([^:]+):(\d{1,5})$/);
        if (!match) return null;
        const host = match[1].trim();
        const port = Number.parseInt(match[2], 10);
        if (!host || !Number.isInteger(port) || port < 1 || port > 65535) return null;
        return { host, port };
    }

    function parseIniWireGuardConfig(rawConfig) {
        const lines = String(rawConfig || '').replace(/\u0000/g, '').split(/\r?\n/);
        const cfg = { interface: {}, peer: {} };
        let section = '';

        for (const rawLine of lines) {
            const line = rawLine.trim();
            if (!line || line.startsWith('#') || line.startsWith(';')) continue;

            const sectionMatch = line.match(/^\[([^\]]+)\]$/);
            if (sectionMatch) {
                section = sectionMatch[1].trim().toLowerCase();
                continue;
            }

            const eq = line.indexOf('=');
            if (eq < 1) continue;
            const key = line.slice(0, eq).trim().toLowerCase();
            const value = line.slice(eq + 1).trim();
            if (!key) continue;

            if (section === 'interface') cfg.interface[key] = value;
            if (section === 'peer') cfg.peer[key] = value;
        }

        return cfg;
    }

    function pickPrimaryAddress(addressValue) {
        const addresses = splitCsvValue(addressValue);
        if (!addresses.length) return '172.16.0.2/32';
        const ipv4WithCidr = addresses.find((addr) => addr.includes('.') && addr.includes('/'));
        if (ipv4WithCidr) return ipv4WithCidr;
        const anyWithCidr = addresses.find((addr) => addr.includes('/'));
        return anyWithCidr || addresses[0];
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

    function detectImportedNodeType(server, publicKey, iface) {
        const hasAmneziaFields = ['s1', 's2', 'jc', 'jmin', 'jmax', 'h1', 'h2', 'h3', 'h4', 'i1']
            .some((key) => typeof iface?.[key] === 'string' && iface[key].trim());
        if (hasAmneziaFields) return 'amnezia';

        const host = String(server || '').trim().toLowerCase();
        if (publicKey === warpWireguardPublicKey) return 'warp';
        if (host === 'engage.cloudflareclient.com') return 'warp';
        if (isAllowedWarpResultIp(host)) return 'warp';
        if (host.includes('cloudflareclient.com')) return 'warp';
        return 'wireguard';
    }

    function parseClashImportConfig(rawConfig) {
        const raw = String(rawConfig || '').trim();
        if (!raw) throw new Error('Пустой конфиг.');
        const parsed = parseIniWireGuardConfig(raw);
        const iface = parsed.interface || {};
        const peer = parsed.peer || {};

        const privateKey = typeof iface.privatekey === 'string' ? iface.privatekey.trim() : '';
        if (!privateKey) throw new Error('В конфиге не найден Interface.PrivateKey.');

        const endpoint = parseWgEndpoint(peer.endpoint || '');
        if (!endpoint) throw new Error('В конфиге не найден корректный Peer.Endpoint (host:port).');

        const publicKey = typeof peer.publickey === 'string' && peer.publickey.trim()
            ? peer.publickey.trim()
            : warpWireguardPublicKey;
        const type = detectImportedNodeType(endpoint.host, publicKey, iface);
        const safeHost = endpoint.host.replace(/[^a-zA-Z0-9.-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
        const nodeName = `${type}-${safeHost || 'imported'}`.slice(0, 64);
        const dnsNameservers = splitCsvValue(iface.dns);

        return {
            profileName: `Imported ${type.toUpperCase()}`,
            node: {
                name: nodeName,
                type,
                server: endpoint.host,
                port: endpoint.port,
                address: pickPrimaryAddress(iface.address),
                privateKey,
                publicKey,
            },
            dns: {
                nameservers: dnsNameservers,
            },
            meta: {
                endpoint: `${endpoint.host}:${endpoint.port}`,
                detectedType: type,
                hasAmneziaFields: type === 'amnezia',
            },
        };
    }

    function base64UrlToBuffer(value) {
        const raw = String(value || '').trim();
        if (!raw) throw new Error('Пустой payload vpn://.');
        const normalized = raw.replace(/-/g, '+').replace(/_/g, '/');
        const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
        return Buffer.from(padded, 'base64');
    }

    function decodeAmneziaVpnLink(vpnLink) {
        const raw = String(vpnLink || '').trim();
        if (!raw.toLowerCase().startsWith('vpn://')) {
            throw new Error('Некорректная vpn:// ссылка.');
        }
        const payload = raw.slice('vpn://'.length);
        const compressed = base64UrlToBuffer(payload);
        if (compressed.length <= 4) {
            throw new Error('Поврежденный vpn:// payload.');
        }

        let decoded;
        try {
            decoded = zlib.inflateSync(compressed.subarray(4)).toString('utf8');
        } catch {
            throw new Error('Не удалось распаковать vpn:// payload.');
        }

        let root;
        try {
            root = JSON.parse(decoded);
        } catch {
            throw new Error('Некорректный JSON внутри vpn:// payload.');
        }

        const container = Array.isArray(root?.containers) ? root.containers[0] : null;
        if (!container?.awg?.last_config) {
            throw new Error('В vpn:// payload отсутствует awg.last_config.');
        }

        let nested;
        try {
            nested = JSON.parse(String(container.awg.last_config || '{}'));
        } catch {
            throw new Error('Некорректный формат awg.last_config.');
        }

        const configTextRaw = typeof nested?.config === 'string' ? nested.config : '';
        if (!configTextRaw.trim()) {
            throw new Error('В awg.last_config отсутствует поле config.');
        }

        const dns1 = typeof root?.dns1 === 'string' && root.dns1.trim() ? root.dns1.trim() : '1.1.1.1';
        const dns2 = typeof root?.dns2 === 'string' && root.dns2.trim() ? root.dns2.trim() : '1.0.0.1';
        return configTextRaw
            .replace(/\$PRIMARY_DNS/g, dns1)
            .replace(/\$SECONDARY_DNS/g, dns2);
    }

    function normalizeImportedConfigText(rawInput) {
        const text = String(rawInput || '').trim();
        if (!text) throw new Error('Пустой конфиг.');
        if (text.toLowerCase().startsWith('vpn://')) {
            return decodeAmneziaVpnLink(text);
        }
        return text;
    }

    function sanitizeProfileName(value, fallback) {
        const raw = typeof value === 'string' ? value.trim() : '';
        if (!raw) return fallback;
        return raw.replace(/\s+/g, ' ').slice(0, 64);
    }

    function normalizeClashNodeType(value) {
        const raw = typeof value === 'string' ? value.trim().toLowerCase() : '';
        if (raw === 'warp' || raw === 'amnezia' || raw === 'wireguard') return raw;
        return 'wireguard';
    }

    function isValidHostOrIp(value) {
        const host = String(value || '').trim().toLowerCase();
        if (!host) return false;
        if (net.isIP(host)) return true;
        if (isDnsHostname(host)) return true;
        return /^[a-z0-9-]+$/i.test(host);
    }

    function isValidCidrAddress(value) {
        const raw = String(value || '').trim();
        const parts = raw.split('/');
        if (parts.length !== 2) return false;
        const ip = parts[0].trim();
        const prefix = Number.parseInt(parts[1], 10);
        const family = net.isIP(ip);
        if (family === 4) return Number.isInteger(prefix) && prefix >= 0 && prefix <= 32;
        if (family === 6) return Number.isInteger(prefix) && prefix >= 0 && prefix <= 128;
        return false;
    }

    function isValidWireGuardKey(value) {
        const raw = String(value || '').trim();
        if (!/^[A-Za-z0-9+/=]+$/.test(raw)) return false;
        try {
            return Buffer.from(raw, 'base64').length === 32;
        } catch {
            return false;
        }
    }

    function validateClashNode(node, idx) {
        const name = sanitizeProfileName(node?.name, `node-${idx + 1}`);
        const type = normalizeClashNodeType(node?.type);
        const server = typeof node?.server === 'string' ? node.server.trim() : '';
        const port = Number.parseInt(String(node?.port || ''), 10);
        const privateKey = typeof node?.privateKey === 'string' ? node.privateKey.trim() : '';
        const publicKey = typeof node?.publicKey === 'string' && node.publicKey.trim()
            ? node.publicKey.trim()
            : warpWireguardPublicKey;
        const addressRaw = typeof node?.address === 'string' && node.address.trim()
            ? node.address.trim()
            : '172.16.0.2/32';
        const address = normalizeInterfaceAddress(addressRaw);

        if (!server) throw new Error(`Узел #${idx + 1}: server обязателен.`);
        if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`Узел #${idx + 1}: некорректный port.`);
        if (!privateKey) throw new Error(`Узел #${idx + 1}: privateKey обязателен.`);
        if (!isValidHostOrIp(server)) throw new Error(`Узел #${idx + 1}: некорректный server.`);
        if (!isValidWireGuardKey(privateKey)) throw new Error(`Узел #${idx + 1}: некорректный privateKey.`);
        if (!isValidWireGuardKey(publicKey)) throw new Error(`Узел #${idx + 1}: некорректный publicKey.`);
        if (!isValidCidrAddress(address)) throw new Error(`Узел #${idx + 1}: address должен быть в формате IP/CIDR.`);

        const reserved = Array.isArray(node?.reserved)
            ? node.reserved.slice(0, 3).map((n) => Number.parseInt(n, 10) || 0)
            : null;
        if (reserved && (reserved.length !== 3 || reserved.some((n) => n < 0 || n > 255))) {
            throw new Error(`Узел #${idx + 1}: reserved должен содержать 3 байта (0..255).`);
        }

        return {
            name,
            type,
            server,
            port,
            privateKey,
            publicKey,
            address,
            reserved,
        };
    }

    function toYamlValue(value) {
        if (typeof value === 'number' || typeof value === 'boolean') return String(value);
        if (value === null || value === undefined) return '""';
        const str = String(value);
        const escaped = str
            .replace(/\\/g, '\\\\')
            .replace(/\r/g, '\\r')
            .replace(/\n/g, '\\n')
            .replace(/"/g, '\\"');
        if (/^[a-zA-Z0-9._:@/+-]+$/.test(str) && !/^(true|false|null|~|yes|no|on|off)$/i.test(str)) return str;
        return `"${escaped}"`;
    }

    function buildClashYaml(profile) {
        const proxyNames = profile.nodes.map((node) => node.name);
        const dnsNameservers = Array.isArray(profile.dns.nameservers) && profile.dns.nameservers.length
            ? profile.dns.nameservers
            : ['https://dns.malw.link/dns-query'];
        const dnsFallback = Array.isArray(profile.dns.fallback) && profile.dns.fallback.length
            ? profile.dns.fallback
            : ['https://1.1.1.1/dns-query', 'tls://1.1.1.1'];
        const rules = [];
        for (const domain of profile.routing.ruDirectDomains) rules.push(`DOMAIN-SUFFIX,${domain},DIRECT`);
        for (const domain of profile.routing.proxyDomains) rules.push(`DOMAIN-SUFFIX,${domain},WARP Auto`);
        for (const cidr of profile.routing.cdnCidrs) rules.push(`IP-CIDR,${cidr},WARP Auto,no-resolve`);
        rules.push('MATCH,DIRECT');
        const lines = [
            'mixed_port: 7890',
            'allow_lan: true',
            'mode: rule',
            'log-level: info',
            'ipv6: true',
            'proxies:',
        ];

        for (const node of profile.nodes) {
            lines.push(`  - name: ${toYamlValue(node.name)}`);
            lines.push('    type: wireguard');
            lines.push(`    server: ${toYamlValue(node.server)}`);
            lines.push(`    port: ${node.port}`);
            lines.push(`    ip: ${toYamlValue(node.address)}`);
            lines.push(`    private-key: ${toYamlValue(node.privateKey)}`);
            lines.push(`    public-key: ${toYamlValue(node.publicKey)}`);
            lines.push('    udp: true');
            lines.push('    remote-dns-resolve: true');
            lines.push('    mtu: 1280');
            if (Array.isArray(node.reserved) && node.reserved.length === 3) {
                lines.push(`    reserved: [${node.reserved.map((n) => Number.parseInt(n, 10) || 0).join(', ')}]`);
            }
            if (node.type === 'amnezia') {
                lines.push('    x-note: amnezia-metadata-only');
            }
        }

        lines.push('proxy-groups:');
        lines.push('  - name: "WARP Auto"');
        lines.push('    type: url-test');
        lines.push('    proxies:');
        for (const name of proxyNames) lines.push(`      - ${toYamlValue(name)}`);
        lines.push('    url: http://www.gstatic.com/generate_204');
        lines.push('    interval: 300');
        lines.push('    tolerance: 80');
        lines.push('  - name: "WARP Manual"');
        lines.push('    type: select');
        lines.push('    proxies:');
        for (const name of [...proxyNames, 'WARP Auto', 'DIRECT']) lines.push(`      - ${toYamlValue(name)}`);

        lines.push('dns:');
        lines.push('  enable: true');
        lines.push('  listen: 0.0.0.0:1053');
        lines.push('  ipv6: true');
        lines.push(`  enhanced-mode: ${profile.dns.mode === 'redir-host' ? 'redir-host' : 'fake-ip'}`);
        lines.push('  fake-ip-range: 198.18.0.1/16');
        lines.push('  nameserver:');
        for (const value of dnsNameservers) lines.push(`    - ${toYamlValue(value)}`);
        lines.push('  fallback:');
        for (const value of dnsFallback) lines.push(`    - ${toYamlValue(value)}`);

        lines.push('rules:');
        for (const rule of rules) lines.push(`  - ${toYamlValue(rule)}`);
        return `${lines.join('\n')}\n`;
    }

    return {
        normalizeImportedConfigText,
        parseClashImportConfig,
        sanitizeProfileName,
        validateClashNode,
        buildClashYaml,
    };
}

module.exports = {
    createClashUtils,
};
