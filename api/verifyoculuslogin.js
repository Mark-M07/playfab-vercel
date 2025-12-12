// api/verifyoculuslogin.js
// Updated with:
// - package_cert_sha256_digest validation (single hash, monitoring mode)
// - Proper ban info extraction from PlayFab error response
// - Meta ban duration matching PlayFab ban duration
import fetch from 'node-fetch';
import querystring from 'node:querystring';
import crypto from 'crypto';

const KNOWN_APP_STATES = ["NotRecognized", "NotEvaluated", "StoreRecognized"];
const KNOWN_DEVICE_STATES = ["NotTrusted", "Basic", "Advanced"];
const ENFORCE_ATTESTATION = false; // ← FLIP TO TRUE WHEN READY

// APK Certificate Validation Config
// SHA256 hash of your release signing certificate (lowercase, no colons)
// Get this from your first successful attestation log or from your keystore
// Leave empty to monitor without validation (will log all cert hashes)
const VALID_CERT_HASH = (process.env.VALID_CERT_HASH || "").trim().toLowerCase();

// Verify attestation token with Meta's server-to-server API
async function verifyAttestationWithMeta(token, accessToken) {
    try {
        if (!token) return null;

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000);

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

            let response;
            try {
                response = await verifyResp.json();
            } catch {
                console.error("[ATTESTATION VERIFY] Non-JSON response from Meta");
                return null;
            }

            if (response.error) {
                console.error(`[ATTESTATION VERIFY] Meta returned error:`, response.error);
                return null;
            }

            const claimsB64 = response.data?.[0]?.claims;
            if (!claimsB64) {
                console.error("[ATTESTATION VERIFY] No claims in Meta response:", JSON.stringify(response));
                return null;
            }

            let claims;
            try {
                const claimsJson = Buffer.from(claimsB64, 'base64').toString('utf-8');
                claims = JSON.parse(claimsJson);
            } catch (e) {
                console.error("[ATTESTATION VERIFY] Failed to decode claims:", e.message);
                return null;
            }

            return claims;
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

/**
 * Validates the APK signing certificate hash against the expected hash.
 */
function validateCertificate(certHashes) {
    const result = {
        valid: true,
        reason: "ok",
        clientHash: null
    };

    if (!certHashes || !Array.isArray(certHashes) || certHashes.length === 0) {
        result.valid = false;
        result.reason = "no_cert_in_payload";
        return result;
    }

    result.clientHash = certHashes[0].toLowerCase();

    if (!VALID_CERT_HASH) {
        result.reason = "no_expected_hash_configured";
        console.log(`[CERT CHECK] No expected hash configured. Client cert: ${result.clientHash}`);
        return result;
    }

    if (result.clientHash !== VALID_CERT_HASH) {
        result.valid = false;
        result.reason = "cert_mismatch";
    }

    return result;
}

/**
 * Extracts ban info from PlayFab error response.
 * PlayFab format: { errorDetails: { "BanReason": ["ExpiryDateOrIndefinite"] } }
 * Returns { reason, expiry, durationMinutes }
 */
function extractBanInfo(playfabErrorResponse) {
    const result = {
        reason: "Account suspended",
        expiry: "Indefinite",
        durationMinutes: 52560000 // 100 years (permanent)
    };

    try {
        // PlayFab errorDetails format: { "ReasonString": ["ExpiryValue"] }
        // The KEY is the ban reason, the VALUE array contains the expiry
        const errorDetails = playfabErrorResponse.errorDetails;
        
        if (errorDetails && typeof errorDetails === 'object') {
            const reasons = Object.keys(errorDetails);
            if (reasons.length > 0) {
                result.reason = reasons[0]; // The key IS the reason
                
                const expiryArray = errorDetails[reasons[0]];
                if (Array.isArray(expiryArray) && expiryArray.length > 0) {
                    result.expiry = expiryArray[0]; // First element is expiry
                }
            }
        }

        // Calculate duration in minutes for Meta API
        if (result.expiry && result.expiry !== "Indefinite") {
            try {
                const expiryDate = new Date(result.expiry);
                const now = new Date();
                const diffMs = expiryDate.getTime() - now.getTime();
                
                if (diffMs > 0) {
                    result.durationMinutes = Math.min(
                        Math.ceil(diffMs / (1000 * 60)),
                        52560000 // Cap at 100 years
                    );
                } else {
                    // Ban already expired
                    result.durationMinutes = 1;
                }
            } catch (e) {
                console.error('[extractBanInfo] Failed to parse expiry date:', result.expiry);
                // Keep permanent duration if parsing fails
            }
        }

        return result;
    } catch (e) {
        console.error('[extractBanInfo] Error:', e);
        return result;
    }
}

/**
 * Bans a device via Meta's API with specified duration.
 */
async function banDeviceViaMeta(uniqueId, accessToken, durationMinutes = 52560000) {
    try {
        const resp = await fetch('https://graph.oculus.com/platform_integrity/device_ban', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                unique_id: uniqueId,
                is_banned: true,
                remaining_time_in_minute: durationMinutes
            })
        });

        const data = await resp.json();

        if (data.message === "Success" && data.ban_id) {
            const durationDisplay = durationMinutes >= 52560000 ? 'PERMANENT' : `${durationMinutes} minutes`;
            console.log(`[META DEVICE BAN] Success | UniqueId:${uniqueId} | Duration:${durationDisplay} | BanId:${data.ban_id}`);
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

export default async function handler(req, res) {
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
            return res.status(400).json({ success: false, error: "Unable to authenticate. Please try again." });
        }

        // === Extract Meta ID ===
        const metaId = receivedUserId.includes('|') ? receivedUserId.split('|')[0] : receivedUserId;
        if (!/^\d+$/.test(metaId)) {
            return res.status(400).json({ success: false, error: "Unable to authenticate. Please try again." });
        }

        // === Oculus Nonce Validation ===
        const nonceController = new AbortController();
        const nonceTimeoutId = setTimeout(() => nonceController.abort(), 10000);
        
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
        
        let nonceValidateResult;
        try {
            nonceValidateResult = JSON.parse(oculusBody);
        } catch {
            console.error("[NONCE VALIDATE] Non-JSON response:", oculusBody.slice(0, 200));
            return res.status(400).json({ success: false, error: "Unable to authenticate. Please try again." });
        }

        if (!oculusResp.ok || !nonceValidateResult.is_valid) {
            return res.status(400).json({ success: false, error: "Unable to authenticate. Please try again." });
        }

        // === META ATTESTATION VALIDATION ===
        let attestation = {
            valid: false,
            reason: "no_token",
            app_integrity: null,
            device_integrity: null,
            unique_id: null,
            device_ban: null,
            cert_check: null
        };

        if (attestationToken) {
            const payload = await verifyAttestationWithMeta(attestationToken, oculusAccessToken);

            if (!payload) {
                attestation.reason = "verification_failed";
                console.warn(`[ATTESTATION] Meta verification failed for user: ${metaId}`);
                
                if (ENFORCE_ATTESTATION) {
                    return res.status(403).json({
                        success: false,
                        error: "VerificationFailed",
                        errorCode: 1003,
                        errorMessage: "Unable to verify device. Please try again later."
                    });
                }
            } else {
                const rawApp = payload.app_state?.app_integrity_state || "unknown";
                const rawDevice = payload.device_state?.device_integrity_state || "unknown";

                attestation.app_integrity = rawApp;
                attestation.device_integrity = rawDevice;
                attestation.unique_id = payload.device_state?.unique_id || null;
                attestation.device_ban = payload.device_ban || null;

                // Certificate validation
                attestation.cert_check = validateCertificate(
                    payload.app_state?.package_cert_sha256_digest
                );

                if (!KNOWN_APP_STATES.includes(rawApp) || !KNOWN_DEVICE_STATES.includes(rawDevice)) {
                    console.warn(`[ATTESTATION] UNKNOWN INTEGRITY STATE → App:${rawApp} Device:${rawDevice} MetaId:${metaId}`);
                }

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

                const nonceOk = payload.request_details?.nonce === expectedNonce;
                const packageOk = payload.app_state?.package_id === "com.ContinuumXR.UG";
                const fresh = Math.abs(Date.now() / 1000 - (payload.request_details?.timestamp || 0)) < 300;
                const strictAppOk = rawApp === "StoreRecognized";
                const strictDeviceOk = rawDevice === "Advanced";
                const certOk = attestation.cert_check.valid;

                const certCheckApplies = !!VALID_CERT_HASH;
                attestation.valid = nonceOk && packageOk && fresh && strictAppOk && strictDeviceOk && 
                                   (certCheckApplies ? certOk : true);

                if (!attestation.valid) {
                    const failReasons = [];
                    if (!nonceOk) failReasons.push("nonce_mismatch");
                    if (!packageOk) failReasons.push("package_mismatch");
                    if (!fresh) failReasons.push("token_stale");
                    if (!strictAppOk) failReasons.push(`app_${rawApp}`);
                    if (!strictDeviceOk) failReasons.push(`device_${rawDevice}`);
                    if (certCheckApplies && !certOk) failReasons.push(`cert_${attestation.cert_check.reason}`);
                    attestation.reason = failReasons.join("|") || "unknown";
                    console.warn(`[ATTESTATION FAILED] User:${metaId} | Reasons:${attestation.reason}`);
                } else {
                    attestation.reason = "ok";
                }

                if (!attestation.cert_check.valid && attestation.cert_check.reason === "cert_mismatch") {
                    console.warn(`[CERT MISMATCH] User:${metaId} | ClientCert:${attestation.cert_check.clientHash} | Expected:${VALID_CERT_HASH}`);
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
            if (playfabData.errorCode === 1002) {
                // User is banned - extract ban info from PlayFab response
                const banInfo = extractBanInfo(playfabData);
                
                console.warn(`[BANNED USER LOGIN] MetaId:${metaId} | Reason:${banInfo.reason} | Expiry:${banInfo.expiry} | Duration:${banInfo.durationMinutes} minutes`);

                // Apply Meta device ban with matching duration
                if (attestation.unique_id) {
                    await banDeviceViaMeta(attestation.unique_id, oculusAccessToken, banInfo.durationMinutes);
                }

                return res.status(403).json({
                    success: false,
                    error: "AccountBanned",
                    errorCode: 1002,
                    errorMessage: "Account is banned.",
                    banInfo: { 
                        reason: banInfo.reason, 
                        expiry: banInfo.expiry 
                    }
                });
            }

            // Non-ban error
            return res.status(400).json({
                success: false,
                error: "Authentication failed",
                errorCode: playfabData.errorCode || 0,
                errorMessage: playfabData.errorMessage || "Unable to authenticate. Please try again."
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

            if (!attestation.valid && attestation.reason !== "verification_failed") {
                let allow = false;

                if (attestation.app_integrity === "NotEvaluated") {
                    const isDev = await isDeveloper(playFabId, titleId, secretKey);
                    if (isDev) {
                        console.log(`[DEV BYPASS] Allowing NotEvaluated for developer: ${metaId}`);
                        allow = true;
                    }
                }

                if (!allow) {
                    console.warn(`[ATTESTATION BAN] PlayFabId:${playFabId} | MetaId:${metaId} | App:${attestation.app_integrity} | Device:${attestation.device_integrity} | Cert:${attestation.cert_check?.reason || 'n/a'}`);

                    // PlayFab permanent ban for attestation failures
                    try {
                        await fetch(`https://${titleId}.playfabapi.com/Server/BanUsers`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
                            body: JSON.stringify({
                                Bans: [{ PlayFabId: playFabId, Reason: `Attestation: ${attestation.reason}` }]
                            })
                        });
                    } catch (e) { console.error("[PLAYFAB BAN FAILED]", e); }

                    // Meta permanent hardware ban for attestation failures
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
                        errorMessage: "Unable to authenticate. Please try again.",
                        banInfo: { reason: "Security violation", expiry: "Indefinite" }
                    });
                }
            }
        }

        // === Forensic Logging ===
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
                        "DeviceIntegrity_FailReasons", "DeviceIntegrity_MetaUniqueId",
                        "DeviceIntegrity_CertHash", "DeviceIntegrity_CertMismatchCount", "DeviceIntegrity_FirstCertMismatch"
                    ]
                })
            });

            const current = currentResp.ok ? (await currentResp.json()).data?.Data || {} : {};
            const updates = {};

            if (!current.DeviceIntegrity_FirstFail?.Value) updates.DeviceIntegrity_FirstFail = now;
            updates.DeviceIntegrity_LastFail = now;
            updates.DeviceIntegrity_FailCount = String((parseInt(current.DeviceIntegrity_FailCount?.Value) || 0) + 1);
            updates.DeviceIntegrity_EverFailed = "true";

            const appOrder = KNOWN_APP_STATES;
            const deviceOrder = KNOWN_DEVICE_STATES;

            const severityApp = appOrder.includes(attestation.app_integrity) ? attestation.app_integrity : "NotRecognized";
            const severityDevice = deviceOrder.includes(attestation.device_integrity) ? attestation.device_integrity : "NotTrusted";

            const worstApp = worstState(current.DeviceIntegrity_WorstAppState?.Value, severityApp, appOrder);
            const worstDevice = worstState(current.DeviceIntegrity_WorstDeviceState?.Value, severityDevice, deviceOrder);

            if (worstApp) updates.DeviceIntegrity_WorstAppState = worstApp;
            if (worstDevice) updates.DeviceIntegrity_WorstDeviceState = worstDevice;

            const existing = (current.DeviceIntegrity_FailReasons?.Value || "").split("|").filter(Boolean);
            const newReasons = attestation.reason.split("|").filter(r => !existing.includes(r));
            if (newReasons.length) {
                updates.DeviceIntegrity_FailReasons = [...existing, ...newReasons].join("|");
            }

            if (attestation.unique_id) updates.DeviceIntegrity_MetaUniqueId = attestation.unique_id;
            if (attestation.cert_check?.clientHash) updates.DeviceIntegrity_CertHash = attestation.cert_check.clientHash;
            
            if (attestation.cert_check?.reason === "cert_mismatch") {
                updates.DeviceIntegrity_CertMismatchCount = String((parseInt(current.DeviceIntegrity_CertMismatchCount?.Value) || 0) + 1);
                if (!current.DeviceIntegrity_FirstCertMismatch?.Value) {
                    updates.DeviceIntegrity_FirstCertMismatch = now;
                }
            }

            if (Object.keys(updates).length > 0) {
                await fetch(`https://${titleId}.playfabapi.com/Server/UpdateUserInternalData`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
                    body: JSON.stringify({ PlayFabId: playFabId, Data: updates, Permission: "Private" })
                });
            }
        }

        // Log verification failures separately
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