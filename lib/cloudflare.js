const https = require('https');
const crypto = require('crypto');

function isWarpLicenseFormat(licenseKey) {
    if (typeof licenseKey !== 'string') return false;
    return /^[A-Za-z0-9]{8}-[A-Za-z0-9]{8}-[A-Za-z0-9]{8}$/.test(licenseKey.trim());
}

function isIdempotentHttpMethod(method) {
    const upper = String(method || '').trim().toUpperCase();
    return ['GET', 'HEAD', 'OPTIONS', 'DELETE', 'TRACE'].includes(upper);
}

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

function createCloudflareApi({
    requestTimeoutMs = 12000,
    retries = 2,
    retryBaseMs = 350,
    isRetryableStatus = defaultRetryableStatus,
    isRetryableNetworkError = defaultRetryableNetworkError,
    sleep = defaultSleep,
    hostname = 'api.cloudflareclient.com',
    apiVersionPath = '/v0i1909051800',
} = {}) {
    async function generateWireGuardKeys() {
        const pair = await new Promise((resolve, reject) => {
            crypto.generateKeyPair('x25519', (err, publicKey, privateKey) => {
                if (err) reject(err);
                else resolve({ privateKey, publicKey });
            });
        });

        const privBytes = pair.privateKey.export({ type: 'pkcs8', format: 'der' });
        const pubBytes = pair.publicKey.export({ type: 'spki', format: 'der' });
        return {
            priv: Buffer.from(privBytes).slice(-32).toString('base64'),
            pub: Buffer.from(pubBytes).slice(-32).toString('base64'),
        };
    }

    function cfRequest(method, urlPath, token, body, { retryNonIdempotent = false } = {}) {
        const methodUpper = String(method || '').trim().toUpperCase();
        const retryAllowed = retryNonIdempotent || isIdempotentHttpMethod(methodUpper);

        const requestOnce = () => new Promise((resolve, reject) => {
            const data = body ? JSON.stringify(body) : null;
            const options = {
                hostname,
                port: 443,
                path: `${apiVersionPath}/${urlPath}`,
                method: methodUpper,
                timeout: requestTimeoutMs,
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
                    catch { resolve({ status: res.statusCode, body: { _raw: raw } }); }
                });
            });
            req.on('timeout', () => {
                req.destroy(Object.assign(new Error('Cloudflare request timeout'), { code: 'ETIMEDOUT' }));
            });
            req.on('error', reject);
            if (data) req.write(data);
            req.end();
        });

        return (async () => {
            let attempt = 0;
            while (true) {
                try {
                    const result = await requestOnce();
                    if (retryAllowed && isRetryableStatus(result.status) && attempt < retries) {
                        attempt += 1;
                        await sleep(retryBaseMs * attempt);
                        continue;
                    }
                    return result;
                } catch (err) {
                    if (!retryAllowed || attempt >= retries || !isRetryableNetworkError(err)) throw err;
                    attempt += 1;
                    await sleep(retryBaseMs * attempt);
                }
            }
        })();
    }

    return {
        isWarpLicenseFormat,
        generateWireGuardKeys,
        cfRequest,
    };
}

module.exports = {
    createCloudflareApi,
};
