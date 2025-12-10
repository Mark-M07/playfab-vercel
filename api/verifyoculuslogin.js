// api/verifyoculuslogin.js
import fetch from 'node-fetch';
import querystring from 'node:querystring';
import crypto from 'crypto';

export default async function handler(req, res) {
    const ENFORCE_ATTESTATION = false; // ← Flip to true when ready

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

        // === Parse userId + appInstanceHash ===
        let metaId = receivedUserId;
        let appInstanceHash = null;
        if (receivedUserId.includes('|')) {
            const parts = receivedUserId.split('|');
            if (parts.length === 2 && /^[A-Za-z0-9+/=]+$/.test(parts[1]) && parts[1].length === 44) {
                metaId = parts[0];
                appInstanceHash = parts[1];
            }
        }
        if (!/^\d+$/.test(metaId)) {
            return res.status(400).json({ success: false, error: 'Authentication failed' });
        }

        // === Oculus Nonce Validation ===
        const appId = process.env.OCULUS_APP_ID;
        const appSecret = process.env.OCULUS_APP_SECRET;
        if (!appId || !appSecret) return res.status(500).json({ success: false, error: 'Internal Server Error' });

        const accessToken = `OC|${appId}|${appSecret}`;
        const oculusResponse = await fetch(
            `https://graph.oculus.com/user_nonce_validate?nonce=${nonce}&user_id=${metaId}&access_token=${accessToken}`,
            { method: 'POST' }
        );
        const oculusBody = await oculusResponse.text();

        if (!oculusResponse.ok || !JSON.parse(oculusBody).is_valid) {
            return res.status(400).json({ success: false, error: 'Authentication failed' });
        }

        // === App Instance Hash Ban ===
        if (appInstanceHash) {
            const titleId = process.env.PLAYFAB_TITLE_ID;
            const secretKey = process.env.PLAYFAB_DEV_SECRET_KEY;

            const internalResp = await fetch(`https://${titleId}.playfabapi.com/Admin/GetTitleInternalData`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
                body: JSON.stringify({ Keys: ['BannedDevices'] })
            });

            if (internalResp.ok) {
                const data = await internalResp.json();
                const list = JSON.parse(data.data?.Data?.BannedDevices || '[]');
                if (list.includes(appInstanceHash)) {
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

        // === Attestation Validation ===
        let attestationResult = {
            valid: true,
            reason: "no_token",
            app_integrity: "unknown",
            device_integrity: "unknown"
        };

        if (attestationToken) {
            try {
                const parts = attestationToken.split('.');
                if (parts.length !== 3) throw new Error("Malformed JWT");

                const payloadRaw = Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf-8');
                const payload = JSON.parse(payloadRaw);

                // === Extract raw values for logging/forensics ===
                const rawAppState = payload.app_state?.app_integrity_state || "unknown";
                const rawDeviceState = payload.device_state?.device_integrity_state || "unknown";

                // === Nonce verification (anti-replay) ===
                const expectedNonce = crypto.createHash('sha256')
                    .update(nonce)
                    .digest('base64')
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_')
                    .replace(/=+$/, '');

                const nonceOk = payload.request_details?.nonce === expectedNonce;
                const packageOk = payload.app_state?.package_id === "com.ContinuumXR.UG";
                const fresh = Math.abs(Date.now() / 1000 - (payload.request_details?.timestamp || 0)) < 300;

                // === STRICT PRODUCTION RULES ===
                const strictAppOk = rawAppState === "StoreRecognized";
                const strictDeviceOk = rawDeviceState === "Advanced";

                // Final validity
                attestationResult.valid = nonceOk && packageOk && strictAppOk && strictDeviceOk && fresh;
                attestationResult.reason = attestationResult.valid ? "ok" : "strict_validation_failed";
                attestationResult.app_integrity = rawAppState;
                attestationResult.device_integrity = rawDeviceState;

                if (!attestationResult.valid) {
                    console.warn(`[ATTESTATION FAILED] User:${metaId} | Reason:${attestationResult.reason} | RawApp:${rawAppState} | RawDevice:${rawDeviceState}`);
                }

            } catch (e) {
                console.error(`[ATTESTATION PARSE ERROR] User:${metaId} | Error: ${e.message}`);
                attestationResult = {
                    valid: false,
                    reason: "parse_error",
                    app_integrity: "error",
                    device_integrity: "error"
                };
            }
        }

        // === PlayFab Login ===
        const titleId = process.env.PLAYFAB_TITLE_ID;
        const secretKey = process.env.PLAYFAB_DEV_SECRET_KEY;

        let validationToken = null;
        const tokenResp = await fetch(`https://${titleId}.playfabapi.com/Admin/GetTitleInternalData`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
            body: JSON.stringify({ Keys: ['ValidationToken'] })
        });
        if (tokenResp.ok) {
            const data = await tokenResp.json();
            validationToken = data.data?.Data?.ValidationToken;
        }

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
            if (playfabData.errorCode === 1002) {
                return res.status(403).json({
                    success: false,
                    error: "AccountBanned",
                    errorCode: 1002,
                    errorMessage: "Unable to authenticate. Please try again later.",
                    banInfo: { reason: "Security violation", expiry: "Indefinite" }
                });
            }
            return res.status(400).json({ success: false, error: 'Authentication failed' });
        }

        // === ENFORCEMENT: PERMA-BAN ON ATTESTATION FAILURE (with Developer Bypass) ===
        if (ENFORCE_ATTESTATION) {
            if (!attestationToken) {
                return res.status(403).json({
                    success: false,
                    error: "UpdateRequired",
                    errorMessage: "A new game update is required to play."
                });
            }

            if (!attestationResult.valid) {
                // === DEVELOPER BYPASS: Allow NotEvaluated only for flagged devs ===
                if (attestationResult.app_integrity === "NotEvaluated") {
                    const devResp = await fetch(`https://${titleId}.playfabapi.com/Server/GetUserInternalData`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
                        body: JSON.stringify({
                            PlayFabId: playfabData.data.PlayFabId,
                            Keys: ["IsDeveloper"]
                        })
                    });

                    if (devResp.ok) {
                        const data = await devResp.json();
                        if (data.data?.Data?.IsDeveloper === "true") {
                            console.log(`[DEVELOPER BYPASS] Allowing NotEvaluated for dev account: ${metaId}`);
                            // → Allow login, skip ban
                            // Continue to success path
                        } else {
                            // Not a dev → pirated/sideloaded → BAN
                            console.warn(`[ATTESTATION BAN] Non-dev with NotEvaluated: ${metaId}`);
                            // → fall through to ban
                        }
                    }
                }

                // === ALL OTHER FAILURES = PERMA-BAN ===
                if (attestationResult.app_integrity !== "NotEvaluated" || 
                    !(await isDeveloper(playfabData.data.PlayFabId))) {  // helper or inline check

                    console.warn(`[ATTESTATION BAN] Banning PlayFabId:${playfabData.data.PlayFabId} | App:${attestationResult.app_integrity} | Device:${attestationResult.device_integrity}`);

                    try {
                        await fetch(`https://${titleId}.playfabapi.com/Server/BanUsers`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
                            body: JSON.stringify({
                                Bans: [{
                                    PlayFabId: playfabData.data.PlayFabId,
                                    Reason: "Security violation – tampered client",
                                    Hours: 0
                                }]
                            })
                        });
                    } catch (e) {
                        console.error("[BAN FAILED]", e);
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

        // === Forensic Logging (append-only) ===
        if (attestationToken || !attestationResult.valid) {
            const now = new Date().toISOString();
            const playFabId = playfabData.data.PlayFabId;

            const currentResp = await fetch(`https://${titleId}.playfabapi.com/Server/GetUserInternalData`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
                body: JSON.stringify({
                    PlayFabId: playFabId,
                    Keys: [
                        "DeviceIntegrity_FirstFail", "DeviceIntegrity_LastFail", "DeviceIntegrity_FailCount",
                        "DeviceIntegrity_EverFailed", "DeviceIntegrity_WorstAppState", "DeviceIntegrity_WorstDeviceState",
                        "DeviceIntegrity_FailReasons", "DeviceIntegrity_LastGood"
                    ]
                })
            });

            const current = currentResp.ok ? (await currentResp.json()).data.Data || {} : {};
            const updates = {};

            if (!attestationResult.valid) {
                if (!current.DeviceIntegrity_FirstFail) updates.DeviceIntegrity_FirstFail = now;
                updates.DeviceIntegrity_LastFail = now;
                updates.DeviceIntegrity_FailCount = (parseInt(current.DeviceIntegrity_FailCount) || 0) + 1;
                updates.DeviceIntegrity_EverFailed = true;

                const worstApp = worstState(current.DeviceIntegrity_WorstAppState, attestationResult.app_integrity, ["Tampered", "NotEvaluated", "StoreRecognized"]);
                const worstDevice = worstState(current.DeviceIntegrity_WorstDeviceState, attestationResult.device_integrity, ["Basic", "Advanced"]);

                if (worstApp) updates.DeviceIntegrity_WorstAppState = worstApp;
                if (worstDevice) updates.DeviceIntegrity_WorstDeviceState = worstDevice;

                const reasons = (current.DeviceIntegrity_FailReasons || "").split("|").filter(Boolean);
                if (!reasons.includes(attestationResult.reason)) {
                    updates.DeviceIntegrity_FailReasons = reasons.length ? `${current.DeviceIntegrity_FailReasons}|${attestationResult.reason}` : attestationResult.reason;
                }
            } else {
                updates.DeviceIntegrity_LastGood = now;
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

// Helper: track worst state
function worstState(current, candidate, order) {
    const scores = Object.fromEntries(order.map((s, i) => [s, i]));
    const currentScore = current ? scores[current] ?? -1 : -1;
    const candidateScore = scores[candidate] ?? -1;
    return candidateScore > currentScore ? candidate : null;
}