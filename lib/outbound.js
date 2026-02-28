const https = require('https');
const http = require('http');
const dns = require('dns').promises;
const net = require('net');

function defaultRetryableStatus(statusCode) {
    return [408, 429, 500, 502, 503, 504].includes(Number(statusCode) || 0);
}

function defaultRetryableNetworkError(err) {
    const code = String(err?.code || '').toUpperCase();
    return ['ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'EAI_AGAIN', 'ENOTFOUND', 'EPIPE'].includes(code);
}

function defaultSleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function defaultIsDnsHostname(value) {
    const host = String(value || '').trim();
    if (!host) return false;
    if (net.isIP(host)) return false;
    return /^[a-z0-9.-]+$/i.test(host) && host.includes('.');
}

function isPrivateOrSpecialIpv4(ip) {
    const parts = ip.split('.').map((x) => Number.parseInt(x, 10));
    if (parts.length !== 4 || parts.some((x) => Number.isNaN(x) || x < 0 || x > 255)) return true;
    if (parts[0] === 0 || parts[0] === 10 || parts[0] === 127) return true;
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 192 && parts[1] === 0 && parts[2] === 0) return true;
    if (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19)) return true;
    if (parts[0] >= 224) return true;
    return false;
}

function isPrivateOrSpecialIpv6(ip) {
    const normalized = String(ip || '').toLowerCase();
    if (!normalized) return true;
    if (normalized === '::' || normalized === '::1') return true;
    if (normalized.startsWith('fe80:')) return true;
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;
    if (normalized.startsWith('ff')) return true;
    return false;
}

function isPublicRoutableIp(ip) {
    const family = net.isIP(ip);
    if (!family) return false;
    if (family === 4) return !isPrivateOrSpecialIpv4(ip);
    return !isPrivateOrSpecialIpv6(ip);
}

function createOutboundUtils({
    trustProxyEnabled = false,
    publicBaseUrl = '',
    outboundRequestTimeoutMs = 12000,
    outboundRequestRetries = 2,
    outboundRequestRetryBaseMs = 350,
    downloadProxyTimeoutMs = 30000,
    downloadProxyMaxBytes = 1_500_000_000,
    isRetryableStatus = defaultRetryableStatus,
    isRetryableNetworkError = defaultRetryableNetworkError,
    sleep = defaultSleep,
    isDnsHostname = defaultIsDnsHostname,
} = {}) {
    function normalizeIpCandidate(rawValue) {
        const value = String(rawValue || '').trim();
        if (!value) return '';
        if (net.isIP(value)) return value;
        const mapped = value.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
        if (mapped && net.isIP(mapped[1]) === 4) return mapped[1];
        return '';
    }

    function isPrivatePeerAddress(rawValue) {
        const ip = normalizeIpCandidate(rawValue);
        if (!ip) return false;
        return !isPublicRoutableIp(ip);
    }

    function sanitizeForwardedProto(value) {
        const raw = String(value || '').split(',')[0].trim().toLowerCase();
        if (raw === 'http' || raw === 'https') return raw;
        return '';
    }

    function sanitizeForwardedHost(value) {
        const raw = String(value || '').split(',')[0].trim();
        if (!raw || /[\s\\/@]/.test(raw)) return '';
        try {
            const parsed = new URL(`http://${raw}`);
            const hostRaw = String(parsed.hostname || '').toLowerCase();
            const host = hostRaw.startsWith('[') && hostRaw.endsWith(']')
                ? hostRaw.slice(1, -1)
                : hostRaw;
            if (!host) return '';
            const family = net.isIP(host);
            if (!(family || isDnsHostname(host) || /^[a-z0-9-]+$/i.test(host))) return '';
            if (parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) return '';
            const port = parsed.port ? Number.parseInt(parsed.port, 10) : null;
            if (port !== null && (!Number.isInteger(port) || port < 1 || port > 65535)) return '';
            const printableHost = family === 6 ? `[${host}]` : host;
            return port ? `${printableHost}:${port}` : printableHost;
        } catch {
            return '';
        }
    }

    function normalizePublicBaseUrl(rawUrl) {
        if (!rawUrl) return '';
        try {
            const parsed = new URL(rawUrl);
            const proto = sanitizeForwardedProto(parsed.protocol.replace(':', ''));
            const host = sanitizeForwardedHost(parsed.host);
            if (!proto || !host) return '';
            return `${proto}://${host}`;
        } catch {
            return '';
        }
    }

    const publicBaseUrlNormalized = normalizePublicBaseUrl(publicBaseUrl);

    function getRequestBaseUrl(req) {
        if (publicBaseUrlNormalized) return publicBaseUrlNormalized;

        const protoCandidates = [];
        const hostCandidates = [];
        const viaPrivateHop = isPrivatePeerAddress(req?.socket?.remoteAddress) || isPrivatePeerAddress(req?.ip);
        const trustForwarded = trustProxyEnabled || viaPrivateHop;
        if (trustForwarded) {
            protoCandidates.push(req.headers['x-forwarded-proto']);
            hostCandidates.push(req.headers['x-forwarded-host']);
        }
        protoCandidates.push(req.protocol);
        hostCandidates.push(req.get('host'));
        hostCandidates.push(req.hostname);

        const proto = protoCandidates
            .map((value) => sanitizeForwardedProto(value))
            .find(Boolean) || 'http';
        const host = hostCandidates
            .map((value) => sanitizeForwardedHost(value))
            .find(Boolean) || 'localhost';
        return `${proto}://${host}`;
    }

    async function assertSafeOutboundUrl(rawUrl, { allowHttp = true, allowHttps = true, context = 'URL' } = {}) {
        let parsed;
        try {
            parsed = new URL(String(rawUrl || '').trim());
        } catch {
            throw new Error(`Некорректный ${context}.`);
        }

        const protocolAllowed = (parsed.protocol === 'http:' && allowHttp) || (parsed.protocol === 'https:' && allowHttps);
        if (!protocolAllowed) {
            throw new Error(allowHttp && allowHttps
                ? 'Разрешены только http/https ссылки.'
                : 'Разрешены только https ссылки.');
        }
        if (parsed.username || parsed.password) {
            throw new Error('Ссылки с логином/паролем не поддерживаются.');
        }

        const host = String(parsed.hostname || '').trim();
        const hostLower = host.toLowerCase();
        if (!host) throw new Error('URL не содержит хост.');
        if (hostLower === 'localhost' || hostLower.endsWith('.local') || hostLower.endsWith('.internal')) {
            throw new Error(`${context} указывает на локальный хост, запрос запрещен.`);
        }

        const ipFamily = net.isIP(host);
        if (ipFamily) {
            if (!isPublicRoutableIp(host)) {
                throw new Error(`${context} указывает на приватный/локальный IP, запрос запрещен.`);
            }
            return {
                url: parsed.toString(),
                host,
                allowedAddresses: [host],
            };
        }

        let resolved = [];
        try {
            resolved = await dns.lookup(host, { all: true, verbatim: true });
        } catch {
            throw new Error(`Не удалось резолвить домен для ${context}.`);
        }
        if (!Array.isArray(resolved) || !resolved.length) {
            throw new Error(`Не удалось получить IP для ${context}.`);
        }
        const addresses = resolved
            .map((item) => String(item?.address || '').trim())
            .filter((ip) => isPublicRoutableIp(ip));
        if (!addresses.length || addresses.length !== resolved.length) {
            throw new Error(`${context} резолвится в приватный/локальный IP, запрос запрещен.`);
        }
        return {
            url: parsed.toString(),
            host,
            allowedAddresses: Array.from(new Set(addresses)),
        };
    }

    async function assertSafeImportUrl(rawUrl) {
        return assertSafeOutboundUrl(rawUrl, { allowHttp: true, allowHttps: true, context: 'URL для импорта' });
    }

    async function assertSafeDownloadUrl(rawUrl) {
        return assertSafeOutboundUrl(rawUrl, { allowHttp: false, allowHttps: true, context: 'URL загрузки' });
    }

    function createPinnedLookup(allowedAddresses) {
        const pool = Array.from(new Set(
            (Array.isArray(allowedAddresses) ? allowedAddresses : [])
                .map((ip) => String(ip || '').trim())
                .filter((ip) => isPublicRoutableIp(ip)),
        ));
        let cursor = 0;
        return (hostname, options, callback) => {
            const cb = typeof options === 'function' ? options : callback;
            const opts = (typeof options === 'object' && options !== null) ? options : {};
            const familyHint = typeof options === 'number'
                ? options
                : Number.parseInt(String(opts.family || 0), 10) || 0;
            const wantsAll = Boolean(opts.all);
            if (!pool.length) {
                cb(Object.assign(new Error(`No pinned IPs for ${hostname}`), { code: 'ENOTFOUND' }));
                return;
            }
            const filtered = (familyHint === 4 || familyHint === 6)
                ? pool.filter((ip) => net.isIP(ip) === familyHint)
                : pool;
            const candidates = filtered.length ? filtered : pool;
            if (!candidates.length) {
                cb(Object.assign(new Error(`No compatible pinned IPs for ${hostname}`), { code: 'ENOTFOUND' }));
                return;
            }

            if (wantsAll) {
                const start = cursor % candidates.length;
                const ordered = candidates.slice(start).concat(candidates.slice(0, start));
                cursor += 1;
                cb(null, ordered.map((ip) => ({ address: ip, family: net.isIP(ip) })));
                return;
            }

            const ip = candidates[cursor % candidates.length];
            cursor += 1;
            cb(null, ip, net.isIP(ip));
        };
    }

    function normalizeSafeOutboundTarget(rawTarget) {
        if (typeof rawTarget === 'string') {
            throw new Error('Unsafe outbound target: expected validated URL object.');
        }
        if (rawTarget && typeof rawTarget === 'object' && typeof rawTarget.url === 'string') {
            return {
                url: rawTarget.url,
                allowedAddresses: Array.isArray(rawTarget.allowedAddresses) ? rawTarget.allowedAddresses : [],
            };
        }
        throw new Error('Некорректный target для исходящего запроса.');
    }

    function fetchRemoteText(remoteTarget, depth = 0, maxBytes = 512 * 1024) {
        if (depth > 5) return Promise.reject(new Error('Слишком много редиректов при импорте.'));
        return new Promise((resolve, reject) => {
            const safeTarget = normalizeSafeOutboundTarget(remoteTarget);
            let parsed;
            try {
                parsed = new URL(safeTarget.url);
            } catch {
                reject(new Error('Некорректный URL для загрузки.'));
                return;
            }
            const client = parsed.protocol === 'https:' ? https : (parsed.protocol === 'http:' ? http : null);
            if (!client) {
                reject(new Error('Поддерживаются только http/https ссылки.'));
                return;
            }

            const req = client.request({
                method: 'GET',
                hostname: parsed.hostname,
                port: parsed.port || undefined,
                path: `${parsed.pathname}${parsed.search}`,
                headers: {
                    'User-Agent': 'WarpGen-Config-Importer/1.0',
                    'Accept': 'text/plain,application/octet-stream,*/*',
                },
                lookup: createPinnedLookup(safeTarget.allowedAddresses),
                timeout: outboundRequestTimeoutMs,
            }, (remoteRes) => {
                const statusCode = remoteRes.statusCode || 500;
                const location = remoteRes.headers.location;
                if (statusCode >= 300 && statusCode < 400 && location) {
                    remoteRes.resume();
                    const nextUrl = new URL(location, safeTarget.url).toString();
                    assertSafeImportUrl(nextUrl)
                        .then((safeNextTarget) => fetchRemoteText(safeNextTarget, depth + 1, maxBytes))
                        .then(resolve)
                        .catch(reject);
                    return;
                }
                if (statusCode >= 400) {
                    remoteRes.resume();
                    reject(new Error(`Сервер вернул HTTP ${statusCode}.`));
                    return;
                }
                const contentLength = Number.parseInt(String(remoteRes.headers['content-length'] || ''), 10);
                if (Number.isFinite(contentLength) && contentLength > maxBytes) {
                    remoteRes.resume();
                    reject(new Error('Файл слишком большой для импорта.'));
                    return;
                }

                const chunks = [];
                let total = 0;
                remoteRes.on('data', (chunk) => {
                    total += chunk.length;
                    if (total > maxBytes) {
                        remoteRes.destroy(new Error('Файл слишком большой для импорта.'));
                        return;
                    }
                    chunks.push(chunk);
                });
                remoteRes.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
                remoteRes.on('error', (err) => reject(err));
            });

            req.on('timeout', () => {
                req.destroy(new Error('Таймаут загрузки конфига.'));
            });
            req.on('error', (err) => reject(err));
            req.end();
        });
    }

    function proxyRemoteDownload(remoteTarget, res, depth = 0, options = {}) {
        const onFail = typeof options?.onFail === 'function' ? options.onFail : null;
        if (depth > 5) {
            res.status(502).json({ error: 'Too many redirects.' });
            return;
        }
        const safeTarget = normalizeSafeOutboundTarget(remoteTarget);
        const parsed = new URL(safeTarget.url);
        const client = parsed.protocol === 'https:' ? https : null;
        if (!client) {
            res.status(400).json({ error: 'Only https downloads are supported.' });
            return;
        }
        let finished = false;
        const fail = (statusCode, message) => {
            if (finished) return;
            if (onFail && !res.headersSent) {
                try {
                    const handled = onFail({ statusCode, message, depth });
                    if (handled) {
                        finished = true;
                        return;
                    }
                } catch {
                    // fallback to default error response
                }
            }
            finished = true;
            if (!res.headersSent) {
                res.status(statusCode).json({ error: message });
            } else {
                res.destroy(new Error(message));
            }
        };

        const req = client.request({
            method: 'GET',
            hostname: parsed.hostname,
            port: parsed.port || undefined,
            path: `${parsed.pathname}${parsed.search}`,
            headers: { 'User-Agent': 'WarpGen-Download-Proxy/1.0' },
            lookup: createPinnedLookup(safeTarget.allowedAddresses),
            timeout: downloadProxyTimeoutMs,
        }, (remoteRes) => {
            const code = remoteRes.statusCode || 500;
            const location = remoteRes.headers.location;
            if (code >= 300 && code < 400 && location) {
                remoteRes.resume();
                const nextUrl = new URL(location, safeTarget.url).toString();
                assertSafeDownloadUrl(nextUrl)
                    .then((safeNextTarget) => proxyRemoteDownload(safeNextTarget, res, depth + 1, options))
                    .catch((err) => fail(502, `Download redirect blocked: ${err.message}`));
                return;
            }
            const contentLength = Number.parseInt(String(remoteRes.headers['content-length'] || ''), 10);
            if (Number.isFinite(contentLength) && contentLength > downloadProxyMaxBytes) {
                remoteRes.resume();
                fail(413, 'Remote file is too large.');
                return;
            }
            res.status(code);
            const passHeaders = ['content-type', 'content-length', 'content-disposition', 'last-modified', 'etag'];
            for (const header of passHeaders) {
                const val = remoteRes.headers[header];
                if (val) res.setHeader(header, val);
            }
            let streamedBytes = 0;
            remoteRes.on('data', (chunk) => {
                streamedBytes += chunk.length;
                if (streamedBytes > downloadProxyMaxBytes) {
                    remoteRes.destroy(new Error('Remote file exceeds max allowed size.'));
                }
            });
            remoteRes.on('error', (err) => {
                fail(502, `Download proxy failed: ${err.message}`);
            });
            remoteRes.pipe(res);
        });
        req.on('timeout', () => {
            req.destroy(Object.assign(new Error('Upstream download timeout.'), { code: 'ETIMEDOUT' }));
        });
        req.on('error', (err) => {
            fail(502, `Download proxy failed: ${err.message}`);
        });
        req.end();
    }

    function githubApiJson(pathname) {
        const requestOnce = () => new Promise((resolve, reject) => {
            const req = https.request({
                method: 'GET',
                hostname: 'api.github.com',
                path: pathname,
                timeout: outboundRequestTimeoutMs,
                headers: {
                    'User-Agent': 'WarpGen-Download-Proxy/1.0',
                    'Accept': 'application/vnd.github+json',
                },
            }, (apiRes) => {
                let raw = '';
                apiRes.on('data', (chunk) => { raw += chunk; });
                apiRes.on('end', () => {
                    if ((apiRes.statusCode || 500) >= 400) {
                        reject(Object.assign(new Error(`GitHub API ${apiRes.statusCode}`), {
                            statusCode: apiRes.statusCode || 500,
                        }));
                        return;
                    }
                    try { resolve(JSON.parse(raw)); }
                    catch { reject(new Error('Invalid GitHub JSON')); }
                });
            });
            req.on('timeout', () => {
                req.destroy(Object.assign(new Error('GitHub API timeout'), { code: 'ETIMEDOUT' }));
            });
            req.on('error', reject);
            req.end();
        });

        return (async () => {
            let attempt = 0;
            while (true) {
                try {
                    return await requestOnce();
                } catch (err) {
                    const statusCode = Number.parseInt(String(err?.statusCode || 0), 10);
                    const retryable = isRetryableNetworkError(err) || isRetryableStatus(statusCode);
                    if (attempt >= outboundRequestRetries || !retryable) throw err;
                    attempt += 1;
                    await sleep(outboundRequestRetryBaseMs * attempt);
                }
            }
        })();
    }

    return {
        getRequestBaseUrl,
        assertSafeOutboundUrl,
        assertSafeImportUrl,
        assertSafeDownloadUrl,
        fetchRemoteText,
        proxyRemoteDownload,
        githubApiJson,
    };
}

module.exports = {
    createOutboundUtils,
};
