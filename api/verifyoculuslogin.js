// api/verifyoculuslogin.js
import fetch from 'node-fetch';
import querystring from 'node:querystring';
import crypto from 'crypto';

const ENFORCE_ATTESTATION = false; // ← FLIP TO TRUE WHEN READY

// Verify attestation token with Meta's server-to-server API
// Returns verified payload if valid, null if verification fails
// Note: Meta only supports GET with query params (POST tested and rejected)
async function verifyAttestationWithMeta(token, accessToken) {
    try {
        if (!token) return null;

        // Add timeout to prevent hanging requests
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

        try {
            const verifyResp = await fetch(
                `https://graph.oculus.com/platform_integrity/verify?token=${encodeURIComponent(token)}&access_token=${encodeURIComponent(accessToken)}`,
                { signal: controller.signal }
            );
            clearTimeout(timeoutId);

            if (!verifyResp.ok) {
                const errorText = await verifyResp.text();
                console.error(`[ATTESTATION VERIFY] Meta API error: ${verifyResp.status} - ${errorText.slice(0, 200)}`);
                return null;
            }

            // Safely parse response
            let verifiedClaims;
            try {
                verifiedClaims = await verifyResp.json();
            } catch {
                console.error("[ATTESTATION VERIFY] Non-JSON response from Meta");
                return null;
            }

            // Check for error response from Meta
            if (verifiedClaims.error) {
                console.error(`[ATTESTATION VERIFY] Meta returned error:`, verifiedClaims.error);
                return null;
            }

            // DEBUG: Log full response to understand Alpha/Dev build states
            console.log(`[ATTESTATION VERIFY] Meta response:`, JSON.stringify(verifiedClaims, null, 2));

            return verifiedClaims;
        } catch (e) {
            clearTimeout(timeoutId);
            if (e.name === 'AbortError') {
                console.error("[ATTESTATION VERIFY] Request timed out after 10s");
            } else {
                throw e;
            }
            return null;
        }
    } catch (e) {
        console.error("[ATTESTATION VERIFY ERROR]", e.message);
        return null;
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
        const nonceController = new AbortController();
        const nonceTimeoutId = setTimeout(() => nonceController.abort(), 10000); // 10 second timeout
        
        let oculusResp;
        let oculusBody;
        try {
            oculusResp = await fetch(
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
                    }),
                    signal: nonceController.signal
                }
            );
            clearTimeout(nonceTimeoutId);
            oculusBody = await oculusResp.text();
        } catch (e) {
            clearTimeout(nonceTimeoutId);
            if (e.name === 'AbortError') {
                console.error("[NONCE VALIDATE] Request timed out after 10s");
            } else {
                console.error("[NONCE VALIDATE] Request failed:", e.message);
            }
            return res.status(503).json({ success: false, error: 'Service temporarily unavailable' });
        }
        
        // 5.3: Safer parse of oculusBody
        let nonceValidateResult;
        try {
            nonceValidateResult = JSON.parse(oculusBody);
        } catch {
            console.error("[NONCE VALIDATE] Non-JSON response:", oculusBody.slice(0, 200));
            return res.status(400).json({ success: false, error: 'Authentication failed' });
        }

        if (!oculusResp.ok || !nonceValidateResult.is_valid) {
            return res.status(400).json({ success: false, error: 'Authentication failed' });
        }

        // === META ATTESTATION VALIDATION (Server-to-Server with Meta) ===
        let attestation = {
            valid: false,
            reason: "no_token",
            app_integrity: null,
            device_integrity: null,
            unique_id: null,
            device_ban: null
        };

        if (attestationToken) {
            // Call Meta's verification API - this is the ONLY secure way
            const payload = await verifyAttestationWithMeta(attestationToken, oculusAccessToken);

            if (!payload) {
                // Meta couldn't verify the token - could be forged, expired, or API error
                attestation.reason = "verification_failed";
                console.warn(`[ATTESTATION] Meta verification failed for user: ${metaId}`);
                
                // 5.2: Treat verification failures softly - don't call it "AccountBanned"
                // This could be a Meta outage or misconfiguration, not necessarily cheating
                if (ENFORCE_ATTESTATION) {
                    return res.status(403).json({
                        success: false,
                        error: "VerificationFailed",
                        errorCode: 1003, // Different from 1002 (AccountBanned)
                        errorMessage: "Unable to verify device. Please try again later."
                    });
                }
            } else {
                // Meta verified the token - now we can trust the claims
                const rawApp = payload.app_state?.app_integrity_state || "unknown";
                const rawDevice = payload.device_state?.device_integrity_state || "unknown";

                attestation.app_integrity = rawApp;
                attestation.device_integrity = rawDevice;
                attestation.unique_id = payload.device_state?.unique_id || null;
                attestation.device_ban = payload.device_ban || null;

                // Meta device ban check
                if (attestation.device_ban?.is_banned === true) {
                    console.warn(`[META DEVICE BANNED] User:${metaId} | UniqueId:${attestation.unique_id}`);
                    return res.status(403).json({
                        success: false,
                        error: "AccountBanned",
                        errorCode: 1002,
                        errorMessage: "This device is permanently banned.",
                        banInfo: { reason: "Device banned", expiry: attestation.device_ban.remaining_ban_time || "Permanent" }
                    });
                }

                // Compute expected nonce
                const expectedNonce = crypto.createHash('sha256')
                    .update(nonce)
                    .digest('base64')
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_')
                    .replace(/=+$/, '');

                // Validate claims - NOW these checks are meaningful because Meta verified the signature
                const nonceOk = payload.request_details?.nonce === expectedNonce;
                const packageOk = payload.app_state?.package_id === "com.ContinuumXR.UG";
                const fresh = Math.abs(Date.now() / 1000 - (payload.request_details?.timestamp || 0)) < 300;
                const strictAppOk = rawApp === "StoreRecognized";
                const strictDeviceOk = rawDevice === "Advanced";

                attestation.valid = nonceOk && packageOk && fresh && strictAppOk && strictDeviceOk;

                if (!attestation.valid) {
                    const failReasons = [];
                    if (!nonceOk) failReasons.push("nonce_mismatch");
                    if (!packageOk) failReasons.push("package_mismatch");
                    if (!fresh) failReasons.push("token_stale");
                    if (!strictAppOk) failReasons.push(`app_${rawApp}`);
                    if (!strictDeviceOk) failReasons.push(`device_${rawDevice}`);
                    attestation.reason = failReasons.join("|") || "unknown";
                    console.warn(`[ATTESTATION FAILED] User:${metaId} | Reasons:${attestation.reason}`);
                } else {
                    attestation.reason = "ok";
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
            // 5.1: Cleaned up - removed dead "invalid_signature_or_claims" check
            // Only apply Meta device ban if we have a verified unique_id and user is PlayFab banned
            if (playfabData.errorCode === 1002 && attestation.unique_id) {
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

            // Only enforce on claims failures, not verification_failed (handled above)
            if (!attestation.valid && attestation.reason !== "verification_failed") {
                let allow = false;

                // === DEVELOPER BYPASS: Only for Meta-verified NotEvaluated ===
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
                                Bans: [{ PlayFabId: playFabId, Reason: `Attestation: ${attestation.reason}` }]
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

        // === Forensic Logging (only on integrity failures, not verification_failed) ===
        // verification_failed is logged separately to avoid conflating infra issues with cheating
        if (attestationToken && !attestation.valid && attestation.reason !== "verification_failed") {
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

        // Log verification failures separately (infra issues, not client misbehaviour)
        if (attestation.reason === "verification_failed") {
            try {
                const currentResp = await fetch(`https://${titleId}.playfabapi.com/Server/GetUserInternalData`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
                    body: JSON.stringify({
                        PlayFabId: playFabId,
                        Keys: ["DeviceIntegrity_LastVerifyError", "DeviceIntegrity_VerifyErrorCount"]
                    })
                });
                const current = currentResp.ok ? (await currentResp.json()).data?.Data || {} : {};
                
                await fetch(`https://${titleId}.playfabapi.com/Server/UpdateUserInternalData`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
                    body: JSON.stringify({
                        PlayFabId: playFabId,
                        Data: {
                            DeviceIntegrity_LastVerifyError: new Date().toISOString(),
                            DeviceIntegrity_VerifyErrorCount: String((parseInt(current.DeviceIntegrity_VerifyErrorCount?.Value) || 0) + 1)
                        },
                        Permission: "Private"
                    })
                });
            } catch (e) {
                console.error("[VERIFY ERROR LOGGING FAILED]", e);
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
    if (!candidate) return null;
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