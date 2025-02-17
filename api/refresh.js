import fetch from 'node-fetch';

export default async function handler(req, res) {
    if (req.method !== 'GET') return res.status(405).json({ error: 'Method Not Allowed' });

    const cookie = req.query.cookie;
    if (!cookie) return res.status(403).json({ error: 'Missing cookie parameter' });

    try {
        const nonce = await getNonce(cookie);
        const csrf = await getCsrf(cookie);
        const epoch = await getEpoch(cookie);

        if (!nonce || !csrf || !epoch) return res.status(403).json({ error: 'Failed to fetch required data' });

        const refreshed = await refreshSession(cookie, nonce, csrf, epoch);
        res.status(200).json({ refreshed });
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error', details: error.message });
    }
}

async function getCsrf(cookie) {
    const response = await fetch("https://auth.roblox.com/v2/login", {
        method: "POST",
        headers: {
            "User-Agent": "Mozilla/5.0",
            "Cookie": `.ROBLOSECURITY=${cookie}`,
            "Content-Type": "application/json"
        }
    });

    const headers = response.headers.raw();
    const csrfToken = headers["x-csrf-token"];
    return csrfToken;
}

async function getNonce(cookie) {
    const response = await fetch("https://apis.roblox.com/hba-service/v1/getServerNonce", {
        method: "GET",
        headers: {
            "User-Agent": "Mozilla/5.0",
            "Cookie": `.ROBLOSECURITY=${cookie}`,
            "Content-Type": "application/json"
        }
    });
    const json = await response.json();
    return json.nonce;
}

async function getEpoch(cookie) {
    const response = await fetch("https://apis.roblox.com/token-metadata-service/v1/sessions?nextCursor=&desiredLimit=25", {
        method: "GET",
        headers: {
            "User-Agent": "Mozilla/5.0",
            "Cookie": `.ROBLOSECURITY=${cookie}`,
            "Content-Type": "application/json"
        }
    });
    const json = await response.json();
    return json.sessions[0].lastAccessedTimestampEpochMilliseconds;
}

async function refreshSession(cookie, nonce, csrf, epoch) {
    const payload = JSON.stringify({
        "secureAuthenticationIntent": {
            "clientEpochTimestamp": epoch,
            "clientPublicKey": null,
            "saiSignature": null,
            "serverNonce": nonce
        }
    });

    const response = await fetch("https://auth.roblox.com/v1/logoutfromallsessionsandreauthenticate", {
        method: "POST",
        headers: {
            "User-Agent": "Mozilla/5.0",
            "Cookie": `.ROBLOSECURITY=${cookie}`,
            "Origin": "https://roblox.com",
            "Referer": "https://roblox.com",
            "Accept": "application/json",
            "X-Csrf-Token": csrf
        },
        body: payload
    });

    const result = await response.json();
    return result;
}
