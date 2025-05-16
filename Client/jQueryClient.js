
// jQuery-based client for PHP APIHandler with login, auto-renew, and roles

const API_BASE = 'https://your-domain.com/path/to/api.php'; // adjust as needed
let token = null;
let expiresAt = 0; // UNIX timestamp in seconds
let roles = [];

/**
 * Log in to the API
 * @param {string} username
 * @param {string} password
 * @returns {Promise<object>} Resolves with {token, expiresAt, roles}
 */
function login(username, password) {
    return $.ajax({
        url: `${API_BASE}?endpoint=login`,
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ username, password }),
        dataType: 'json'
    }).then(data => {
        token = data.token;
        expiresAt = data.expiresAt;
        roles = data.roles;
        return { token, expiresAt, roles };
    });
}

/**
 * Internal AJAX wrapper with token header and renewal logic
 * @param {string} endpoint
 * @param {object} options  jQuery ajax settings (method, data, etc.)
 * @returns {Promise<object>} Resolves with response JSON
 */
function authRequest(endpoint, options = {}) {
    if (!token) {
        return $.Deferred().reject(new Error('Not authenticated. Please login first.')).promise();
    }

    const settings = Object.assign({}, options, {
        url: `${API_BASE}?endpoint=${encodeURIComponent(endpoint)}`,
        beforeSend: jqXHR => {
            jqXHR.setRequestHeader('Authorization', `Bearer ${token}`);
        },
        dataType: 'json'
    });

    return $.ajax(settings).then((data, textStatus, jqXHR) => {
        // Check renewal headers
        const renewed = jqXHR.getResponseHeader('X-Token-Renewed');
        const newExpiry = jqXHR.getResponseHeader('X-Token-Expires-At');
        if (renewed === 'true' && newExpiry) {
            expiresAt = parseInt(newExpiry, 10);
            console.info('Token renewed until', new Date(expiresAt * 1000));
        }
        return data;
    }).catch((jqXHR, textStatus, errorThrown) => {
        const errMsg = jqXHR.responseJSON && jqXHR.responseJSON.error
            ? jqXHR.responseJSON.error
            : errorThrown;
        return $.Deferred().reject(new Error(errMsg)).promise();
    });
}

/** GET example endpoint */
function getExample() {
    return authRequest('example', { method: 'GET' });
}

/** POST example endpoint */
function postExample(payload) {
    return authRequest('example', {
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(payload)
    });
}

/** Check if token is expired client-side */
function isTokenExpired() {
    return Date.now() / 1000 > expiresAt;
}

/** Get current roles */
function getRoles() {
    return roles;
}

// Export for module systems or attach to window
window.apiClientJQuery = {
    login,
    getExample,
    postExample,
    isTokenExpired,
    getRoles
};
