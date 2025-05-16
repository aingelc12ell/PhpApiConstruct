// apiClient.js
// ES module client for PHP APIHandler with token login, auto-renew, and roles

const API_BASE = 'https://your-domain.com/path/to/api.php'; // adjust

let token = null;
let expiresAt = 0;
let roles = [];

/**
 * Log in with username/password, store token, expiry, and roles
 * @param {string} username
 * @param {string} password
 */
export async function login(username, password) {
    const url = `${API_BASE}?endpoint=login`;
    const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || resp.statusText);

    token = data.token;
    expiresAt = data.expiresAt * 1000; // PHP sends UNIX timestamp
    roles = data.roles;
    return { token, expiresAt, roles };
}

/**
 * Internal fetch wrapper handling token, renewal headers, and errors
 * @param {string} endpoint
 * @param {object} options
 */
async function authFetch(endpoint, options = {}) {
    if (!token) throw new Error('Not authenticated. Call login() first.');

    // Refresh logic: if we're past expiry, but we rely on renewal headers
    const url = `${API_BASE}?endpoint=${encodeURIComponent(endpoint)}`;
    const headers = new Headers(options.headers || {});
    headers.set('Content-Type', 'application/json');
    headers.set('Authorization', `Bearer ${token}`);

    const resp = await fetch(url, { ...options, headers });
    // Check renewal headers
    if (resp.headers.get('X-Token-Renewed') === 'true') {
        const newExpiry = parseInt(resp.headers.get('X-Token-Expires-At'), 10) * 1000;
        expiresAt = newExpiry;
        console.info('Token renewed until', new Date(expiresAt));
    }

    const text = await resp.text();
    let data;
    try { data = text ? JSON.parse(text) : null; }
    catch (err) { throw new Error('Invalid JSON response: ' + err.message); }

    if (!resp.ok) {
        throw new Error(data.error || resp.statusText);
    }
    return data;
}

/**
 * GET example endpoint
 */
export async function getExample() {
    return authFetch('example', { method: 'GET' });
}

/**
 * POST example endpoint
 * @param {object} payload
 */
export async function postExample(payload) {
    return authFetch('example', {
        method: 'POST',
        body: JSON.stringify(payload)
    });
}

// Optional: monitor token expiry client-side
export function isTokenExpired() {
    return Date.now() > expiresAt;
}

export function getRoles() {
    return roles;
}
