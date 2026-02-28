function createRateLimitManager({
    getClientIp,
    defaultWindowMs = 60_000,
    maxEntries = 100_000,
} = {}) {
    if (typeof getClientIp !== 'function') {
        throw new Error('createRateLimitManager requires getClientIp function');
    }

    const state = new Map();

    function cleanupRateLimitState() {
        const now = Date.now();
        for (const [key, entry] of state.entries()) {
            if (!entry || (entry.resetAt || 0) <= now) state.delete(key);
        }
        if (state.size <= maxEntries) return;
        const overflow = state.size - maxEntries;
        const oldest = Array.from(state.entries())
            .sort((a, b) => (a[1]?.resetAt || 0) - (b[1]?.resetAt || 0))
            .slice(0, overflow)
            .map(([key]) => key);
        for (const key of oldest) state.delete(key);
    }

    function createRateLimitMiddleware({ key, maxPerWindow, windowMs = defaultWindowMs }) {
        const safeKey = typeof key === 'string' && key.trim() ? key.trim() : 'default';
        const safeMax = Number.isInteger(maxPerWindow) && maxPerWindow > 0 ? maxPerWindow : 1;

        return (req, res, next) => {
            cleanupRateLimitState();
            const ip = getClientIp(req) || 'unknown';
            const bucketKey = `${safeKey}:${ip}`;
            const now = Date.now();
            const current = state.get(bucketKey);
            const active = current && current.resetAt > now
                ? current
                : { count: 0, resetAt: now + windowMs };
            active.count += 1;
            state.set(bucketKey, active);

            const remaining = Math.max(0, safeMax - active.count);
            const retryAfterSec = Math.max(1, Math.ceil((active.resetAt - now) / 1000));
            res.setHeader('X-RateLimit-Limit', String(safeMax));
            res.setHeader('X-RateLimit-Remaining', String(remaining));
            res.setHeader('X-RateLimit-Reset', String(Math.floor(active.resetAt / 1000)));

            if (active.count > safeMax) {
                res.setHeader('Retry-After', String(retryAfterSec));
                return res.status(429).json({
                    error: 'Too many requests, try again later.',
                    retryAfterSec,
                });
            }
            return next();
        };
    }

    return {
        createRateLimitMiddleware,
        cleanupRateLimitState,
    };
}

module.exports = {
    createRateLimitManager,
};
