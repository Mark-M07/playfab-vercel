// api/verifyoculuslogin.js
import fetch from 'node-fetch';
import querystring from 'node:querystring';
import crypto from 'crypto';

const ENFORCE_ATTESTATION = false; // ← FLIP TO TRUE WHEN READY

let cachedJWKS = null;
let lastJWKSFetch = 0;
const JWKS_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours

async function getOculusJWKS() {
    const now = Date.now();

    if (cachedJWKS && (now - lastJWKSFetch) < JWKS_TTL_MS) {
        return cachedJWKS;
    }

    console.log("Refreshing Oculus JWKS...");

    const jwksResp = await fetch("https://www.oculus.com/platform_integrity/jwks");
    if (!jwksResp.ok) {
        throw new Error("Failed to fetch Oculus JWKS");
    }

    const jwks = await jwksResp.json();
    cachedJWKS = jwks;
    lastJWKSFetch = now;

    return jwks;
}

async function verifyMetaAttestationToken(token) {
    try {
        if (!token) return false;

        const [headerB64, payloadB64, signatureB64] = token.split('.');
        if (!headerB64 || !payloadB64 || !signatureB64) return false;

        // Decode header to get kid
        const header = JSON.parse(Buffer.from(headerB64.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString());
        if (header.alg !== "RS256") return false;

        const kid = header.kid;
        if (!kid) return false;

        // Meta's public JWKS (never changes)
        const jwks = await getOculusJWKS();

        const key = jwks.keys.find(k => k.kid === kid);
        if (!key) return false;

        // Build PEM
        const pem = 
            "-----BEGIN PUBLIC KEY-----\n" +
            key.x5c[0].match(/.{1,64}/g).join("\n") +
            "\n-----END PUBLIC KEY-----";

        // Verify signature (Node.js built-in)
        const verifier = crypto.createVerify('RSA-SHA256');
        verifier.update(`${headerB64}.${payloadB64}`);
        const signature = signatureB64.replace(/-/g, '+').replace(/_/g, '/');
        const validSignature = verifier.verify(pem, signature, 'base64');

        if (!validSignature) return false;

        // Decode and validate claims
        const payload = JSON.parse(Buffer.from(payloadB64.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString());

        // Standard JWT claims
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp && payload.exp < now) return false;
        if (payload.iat && payload.iat > now + 300) return false;
        if (payload.iss !== "https://www.oculus.com") return false;
        if (!payload.aud?.includes("com.ContinuumXR.UG")) return false;

        return payload; // Verified + valid
    } catch (e) {
        console.error("[JWT VERIFY ERROR]", e.message);
        return false;
    }
}

export default async function handler(req, res) {
    // Config
    const titleId = process.env.PLAYFAB_TITLE_ID;
    const secretKey = process.env.PLAYFAB_DEV_SECRET_KEY;
    const appId = process.env.OCULUS_APP_ID;
    const appSecret = process.env.OCULUS_APP_SECRET;
    const oculusAccessToken = `OC|${appId}|${appSecret}`;

    if (!titleId || !secretKey || !appId || !appSecret) {
        return res.status(500).json({ success: false, error: 'Server misconfigured' });
    }

    try {
        if (req.method !== 'POST') {
            return res.status(405).json({ success: false, error: 'Method Not Allowed' });
        }

        // === Parse body ===
        let bodyData;
        const contentType = req.headers['content-type'] || '';
        if (contentType.includes('application/x-www-form-urlencoded')) {
            const rawBody = await new Promise((resolve, reject) => {
                let data = '';
                req.on('data', chunk => data += chunk);
                req.on('end', () => resolve(data));
                req.on('error', reject);
            });
            bodyData = querystring.parse(rawBody);
        } else {
            bodyData = req.body;
        }

        const { userId: receivedUserId, nonce, attestationToken } = bodyData;
        if (!receivedUserId || !nonce) {
            return res.status(400).json({ success: false, error: 'Authentication failed' });
        }

        // === Extract Meta ID (strip legacy appInstanceHash if present) ===
        const metaId = receivedUserId.includes('|') ? receivedUserId.split('|')[0] : receivedUserId;
        if (!/^\d+$/.test(metaId)) {
            return res.status(400).json({ success: false, error: 'Authentication failed' });
        }

        // === Oculus Nonce Validation ===
        const oculusResp = await fetch(
            "https://graph.oculus.com/user_nonce_validate",
            {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${oculusAccessToken}`,
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: querystring.stringify({
                    nonce,
                    user_id: metaId
                })
            }
        );

        const oculusBody = await oculusResp.text();
        if (!oculusResp.ok || !JSON.parse(oculusBody).is_valid) {
            return res.status(400).json({ success: false, error: 'Authentication failed' });
        }

        // === META ATTESTATION VALIDATION ===
        let attestation = {
            valid: false,
            reason: "no_token",
            app_integrity: null,
            device_integrity: null,
            unique_id: null,
            device_ban: null
        };

        if (attestationToken) {
            console.log("========== ATTESTATION DEBUG START ==========");
            console.log("Raw token type:", typeof attestationToken);
            console.log("Raw token length:", attestationToken.length);

            const tokenPreview = attestationToken.slice(0, 60);
            console.log("Token preview (first 60 chars):", tokenPreview);

            const tokenParts = attestationToken.split(".");
            console.log("JWT part count:", tokenParts.length);

            if (tokenParts.length === 3) {
                try {
                    const headerJson = Buffer.from(
                        tokenParts[0].replace(/-/g, '+').replace(/_/g, '/'),
                        'base64'
                    ).toString();

                    console.log("JWT header JSON:", headerJson);

                    const header = JSON.parse(headerJson);
                    console.log("JWT header.alg:", header.alg);
                    console.log("JWT header.kid:", header.kid);

                } catch (e) {
                    console.error("JWT header decode failed:", e.message);
                }
            } else {
                console.warn("Token is NOT a valid JWT format (not 3 parts)");
            }

            console.log("========== ATTESTATION DEBUG END ==========");

            const verifiedPayload = await verifyMetaAttestationToken(attestationToken);

            if (!verifiedPayload) {
                attestation.valid = false;
                attestation.reason = "invalid_signature_or_claims";
                console.warn(`[ATTESTATION FORGED] User:${metaId} attempted token forgery`);

                if (ENFORCE_ATTESTATION) {
                    return res.status(403).json({
                        success: false,
                        error: "AccountBanned",
                        errorCode: 1002,
                        errorMessage: "Unable to authenticate. Please try again later.",
                        banInfo: { reason: "Security violation", expiry: "Indefinite" }
                    });
                }
            } else {
                const payload = verifiedPayload;

                const rawApp = payload.app_state?.app_integrity_state || "unknown";
                const rawDevice = payload.device_state?.device_integrity_state || "unknown";

                attestation.app_integrity = rawApp;
                attestation.device_integrity = rawDevice;
                attestation.unique_id = payload.device_state?.unique_id || null;
                attestation.device_ban = payload.device_ban || null;

                // Meta device ban check
                if (attestation.device_ban?.is_banned === true) {
                    console.warn(`[META DEVICE BANNED] UniqueId:${attestation.unique_id}`);
                    return res.status(403).json({
                        success: false,
                        error: "AccountBanned",
                        errorCode: 1002,
                        errorMessage: "This device is permanently banned.",
                        banInfo: { reason: "Device banned by Meta", expiry: "Permanent" }
                    });
                }

                const expectedNonce = crypto.createHash('sha256')
                    .update(nonce)
                    .digest('base64')
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_')
                    .replace(/=+$/, '');

                const valid = 
                    payload.request_details?.nonce === expectedNonce &&
                    payload.app_state?.package_id === "com.ContinuumXR.UG" &&
                    rawApp === "StoreRecognized" &&
                    rawDevice === "Advanced" &&
                    Math.abs(Date.now() / 1000 - (payload.request_details?.timestamp || 0)) < 300;

                attestation.valid = valid;
                attestation.reason = valid ? "ok" : "strict_validation_failed";

                if (!valid) {
                    console.warn(`[ATTESTATION FAILED] User:${metaId} | App:${rawApp} | Device:${rawDevice}`);
                }
            }
        }

        // === PlayFab Login ===
        const playfabResp = await fetch(`https://${titleId}.playfabapi.com/Server/LoginWithCustomID`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
            body: JSON.stringify({
                CustomId: metaId,
                CreateAccount: true,
                InfoRequestParameters: {
                    GetUserAccountInfo: true,
                    GetPlayerProfile: true,
                    GetUserData: true,
                    GetEntityToken: true,
                    ProfileConstraints: { ShowDisplayName: true }
                }
            })
        });

        const playfabData = await playfabResp.json();

        if (!playfabResp.ok) {
            if (
                playfabData.errorCode === 1002 && 
                attestation.valid === false &&
                attestation.reason !== "invalid_signature_or_claims" &&
                attestation.unique_id
            ) {
                await banDeviceViaMeta(attestation.unique_id, oculusAccessToken);
            }
            return res.status(playfabData.errorCode === 1002 ? 403 : 400).json({
                success: false,
                error: playfabData.errorCode === 1002 ? "AccountBanned" : "Authentication failed",
                errorCode: playfabData.errorCode || 0,
                errorMessage: "Unable to authenticate. Please try again later.",
                banInfo: playfabData.errorCode === 1002 ? { reason: "Security violation", expiry: "Indefinite" } : undefined
            });
        }

        const playFabId = playfabData.data.PlayFabId;

        // === FINAL ENFORCEMENT ===
        if (ENFORCE_ATTESTATION) {
            if (!attestationToken) {
                return res.status(403).json({
                    success: false,
                    error: "UpdateRequired",
                    errorMessage: "A new game update is required to play."
                });
            }

            if (!attestation.valid) {
                let allow = false;

                // === DEVELOPER BYPASS: Only for NotEvaluated ===
                if (attestation.app_integrity === "NotEvaluated") {
                    const isDev = await isDeveloper(playFabId, titleId, secretKey);
                    if (isDev) {
                        console.log(`[DEV BYPASS] Allowing NotEvaluated for developer: ${metaId}`);
                        allow = true;
                    }
                }

                if (!allow) {
                    console.warn(`[ATTESTATION BAN] Banning PlayFabId:${playFabId} | MetaId:${metaId} | App:${attestation.app_integrity} | Device:${attestation.device_integrity}`);

                    // 1. PlayFab Account Ban
                    try {
                        await fetch(`https://${titleId}.playfabapi.com/Server/BanUsers`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
                            body: JSON.stringify({
                                Bans: [{ PlayFabId: playFabId, Reason: "Security violation – tampered client" }]
                            })
                        });
                    } catch (e) { console.error("[PLAYFAB BAN FAILED]", e); }

                    // 2. Meta Hardware Ban (survives factory reset)
                    if (attestation.unique_id) {
                        const result = await banDeviceViaMeta(attestation.unique_id, oculusAccessToken);
                        if (result.success) {
                            await fetch(`https://${titleId}.playfabapi.com/Server/UpdateUserInternalData`, {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
                                body: JSON.stringify({
                                    PlayFabId: playFabId,
                                    Data: { MetaBanId: result.banId, MetaBanTime: new Date().toISOString() },
                                    Permission: "Private"
                                })
                            });
                        }
                    }

                    return res.status(403).json({
                        success: false,
                        error: "AccountBanned",
                        errorCode: 1002,
                        errorMessage: "Unable to authenticate. Please try again later.",
                        banInfo: { reason: "Security violation", expiry: "Indefinite" }
                    });
                }
            }
        }

        // === Forensic Logging (ONLY on failure) ===
        if (attestationToken && !attestation.valid) {
            const now = new Date().toISOString();
            const currentResp = await fetch(`https://${titleId}.playfabapi.com/Server/GetUserInternalData`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
                body: JSON.stringify({
                    PlayFabId: playFabId,
                    Keys: [
                        "DeviceIntegrity_FirstFail", "DeviceIntegrity_LastFail", "DeviceIntegrity_FailCount",
                        "DeviceIntegrity_EverFailed", "DeviceIntegrity_WorstAppState", "DeviceIntegrity_WorstDeviceState",
                        "DeviceIntegrity_FailReasons", "DeviceIntegrity_MetaUniqueId"
                    ]
                })
            });

            const current = currentResp.ok ? (await currentResp.json()).data?.Data || {} : {};
            const updates = {};

            if (!current.DeviceIntegrity_FirstFail?.Value) updates.DeviceIntegrity_FirstFail = now;
            updates.DeviceIntegrity_LastFail = now;
            updates.DeviceIntegrity_FailCount = String((parseInt(current.DeviceIntegrity_FailCount?.Value) || 0) + 1);
            updates.DeviceIntegrity_EverFailed = "true";

            const worstApp = worstState(current.DeviceIntegrity_WorstAppState?.Value, attestation.app_integrity,
                ["unknown", "error", "NotRecognized", "NotEvaluated", "StoreRecognized"]);
            const worstDevice = worstState(current.DeviceIntegrity_WorstDeviceState?.Value, attestation.device_integrity,
                ["unknown", "error", "NotTrusted", "Basic", "Advanced"]);

            if (worstApp) updates.DeviceIntegrity_WorstAppState = worstApp;
            if (worstDevice) updates.DeviceIntegrity_WorstDeviceState = worstDevice;

            const existing = (current.DeviceIntegrity_FailReasons?.Value || "").split("|").filter(Boolean);
            const newReasons = attestation.reason.split("|").filter(r => !existing.includes(r));
            if (newReasons.length) {
                updates.DeviceIntegrity_FailReasons = [...existing, ...newReasons].join("|");
            }

            if (attestation.unique_id) {
                updates.DeviceIntegrity_MetaUniqueId = attestation.unique_id;
            }

            if (Object.keys(updates).length > 0) {
                await fetch(`https://${titleId}.playfabapi.com/Server/UpdateUserInternalData`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
                    body: JSON.stringify({ PlayFabId: playFabId, Data: updates, Permission: "Private" })
                });
            }
        }

        // === Success ===
        const tokenResp = await fetch(`https://${titleId}.playfabapi.com/Admin/GetTitleInternalData`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
            body: JSON.stringify({ Keys: ['ValidationToken'] })
        });
        const validationToken = tokenResp.ok ? (await tokenResp.json()).data?.Data?.ValidationToken : null;

        return res.status(200).json({
            success: true,
            sessionTicket: playfabData.data.SessionTicket,
            playFabId: playfabData.data.PlayFabId,
            newlyCreated: playfabData.data.NewlyCreated,
            infoPayload: JSON.stringify(playfabData.data.InfoResultPayload),
            entityToken: playfabData.data.EntityToken.EntityToken,
            entityId: playfabData.data.EntityToken.Entity.Id,
            entityType: playfabData.data.EntityToken.Entity.Type,
            token: validationToken
        });

    } catch (err) {
        console.error('Unhandled error:', err);
        return res.status(500).json({ success: false, error: 'Internal Server Error' });
    }
}

// === HELPERS ===
function worstState(current, candidate, order) {
    const scores = Object.fromEntries(order.map((s, i) => [s, i]));
    const curScore = current ? (scores[current] ?? 999) : 999;
    const candScore = scores[candidate] ?? 999;
    return candScore < curScore ? candidate : null;
}

async function isDeveloper(playFabId, titleId, secretKey) {
    try {
        const resp = await fetch(`https://${titleId}.playfabapi.com/Server/GetUserInternalData`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
            body: JSON.stringify({ PlayFabId: playFabId, Keys: ["IsDeveloper"] })
        });
        if (resp.ok) {
            const data = await resp.json();
            return data.data?.Data?.IsDeveloper?.Value === "true";
        }
    } catch (e) {
        console.error('[isDeveloper failed]', e);
    }
    return false;
}

async function banDeviceViaMeta(uniqueId, accessToken) {
    try {
        const url = `https://graph.oculus.com/platform_integrity/device_ban`;

        const resp = await fetch(url, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                unique_id: uniqueId,
                is_banned: true,
                remaining_time_in_minute: 52560000 // 100 years
            })
        });

        const data = await resp.json();

        if (data.message === "Success" && data.ban_id) {
            console.log(`[META DEVICE BAN] Success | UniqueId:${uniqueId} | BanId:${data.ban_id}`);
            return { success: true, banId: data.ban_id };
        } else {
            console.error(`[META DEVICE BAN FAILED]`, data);
            return { success: false, error: data };
        }
    } catch (e) {
        console.error(`[META DEVICE BAN ERROR]`, e);
        return { success: false, error: e.message };
    }
}