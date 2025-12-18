// api/verifyoculuslogin.js
import fetch from 'node-fetch';
import querystring from 'node:querystring';
import crypto from 'crypto';

const KNOWN_APP_STATES = ["NotRecognized", "NotEvaluated", "StoreRecognized"];
const KNOWN_DEVICE_STATES = ["NotTrusted", "Basic", "Advanced"];

// === ENFORCEMENT CONFIGURATION ===
// Action types: "allow" | "block" | "ban"
//   - allow: Let login proceed (monitoring only)
//   - block: Reject this login attempt but don't ban
//   - ban:   Reject login AND issue permanent PlayFab + Meta device ban
const ENFORCEMENT_CONFIG = {
  enabled: true, // Master switch - set to true to enable enforcement
  
  // Device integrity failures
  device_NotTrusted: "ban",     // Worst - definitely compromised
  device_Basic: "ban",          // Bad - rooted/modified device
  
  // Token/timing issues  
  token_stale: "block",         // Block login but don't ban (could be clock issues)
  
  // App integrity failures
  app_NotRecognized: "ban",     // Sideloaded/pirated APK
  app_NotEvaluated: "ban",      // Ban non-devs (isDeveloper check handles legitimate devs)
  
  // Certificate mismatch
  cert_mismatch: "ban",         // Modified APK
  cert_missing: "ban",          // Missing cert data
  
  // Nonce/package issues (likely tampering)
  nonce_mismatch: "ban",
  package_mismatch: "ban",
  
  // Meta API couldn't verify token
  verification_failed: "block", // Block but don't ban (could be API issue)
  
  // No attestation token provided (old client)
  no_token: "block",            // Require updated client
};

// Helper to determine action for a given failure
function getEnforcementAction(failReasons) {
  if (!ENFORCEMENT_CONFIG.enabled) return "allow";
  
  const reasons = failReasons.split("|");
  let action = "allow";
  
  for (const reason of reasons) {
    // Map reason to config key
    let configKey = reason;
    
    // Handle device_X and app_X patterns
    if (reason.startsWith("device_")) configKey = reason;
    else if (reason.startsWith("app_")) configKey = reason;
    else if (reason.startsWith("cert_")) configKey = reason;
    
    const reasonAction = ENFORCEMENT_CONFIG[configKey];
    
    // Escalate: ban > block > allow
    if (reasonAction === "ban") return "ban"; // Immediate escalation
    if (reasonAction === "block" && action !== "ban") action = "block";
  }
  
  return action;
}

// APK Certificate Validation Config
// SHA256 hash of your release signing certificate (lowercase, no colons)
// Get this from your first successful attestation log or from your keystore
// Leave empty to monitor without validation (will log all cert hashes)
const VALID_CERT_HASH = (process.env.VALID_CERT_HASH || "").trim().toLowerCase();

async function readJson(resp, label, { maxLog = 400 } = {}) {
  const text = await resp.text().catch(() => "");
  if (!text) {
    console.error(`[${label}] Empty response body`, resp.status);
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    console.error(`[${label}] Non-JSON:`, resp.status, text.slice(0, maxLog));
    return null;
  }
}

// === SECURITY BLOB HELPERS ===
// Single key in PlayerInternalData: "Security"
function safeParseJson(str, fallback) {
  try { return str ? JSON.parse(str) : fallback; } catch { return fallback; }
}

async function loadSecurityBlob(titleId, secretKey, playFabId) {
  const resp = await fetch(`https://${titleId}.playfabapi.com/Server/GetUserInternalData`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
    body: JSON.stringify({ PlayFabId: playFabId, Keys: ["Security"] })
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    console.error("[LOAD SECURITY] HTTP error:", resp.status, text.slice(0, 400));
    return null;
  }

  const json = await readJson(resp, "LOAD SECURITY");
  if (!json) return null;

  const cur = json?.data?.Data?.Security?.Value;
  const blob = safeParseJson(cur, { v: 2 });

  if (!blob.v) blob.v = 2;
  if (!blob.di) blob.di = {};
  return blob;
}

async function saveSecurityBlob(titleId, secretKey, playFabId, blob) {
  try {
    const resp = await fetch(`https://${titleId}.playfabapi.com/Server/UpdateUserInternalData`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
      body: JSON.stringify({
        PlayFabId: playFabId,
        Data: { Security: JSON.stringify(blob) }
      })
    });

    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      console.error("[SECURITY BLOB SAVE FAILED]", resp.status, text.slice(0, 400));
    }
  } catch (e) {
    console.error("[SECURITY BLOB SAVE EXCEPTION]", e);
  }
}

function applyMetaBanToBlob(blob, { uniqueId, banId, issuedAt, reason, durationMinutes }) {
  if (!blob) return;
  if (!blob.mb) blob.mb = {};
  Object.assign(blob.mb, {
    uid: uniqueId ?? blob.mb.uid ?? null,
    bid: banId ?? blob.mb.bid ?? null,
    ia: issuedAt ?? blob.mb.ia ?? new Date().toISOString(),
    r: reason ?? blob.mb.r ?? "Security violation",
    dm: typeof durationMinutes === "number" ? durationMinutes : (blob.mb.dm ?? 52560000),
  });
}

// === REASON FLAGS (bitmask) ===
const FLAGS = {
  NONCE_MISMATCH:      1 << 0,  // 1
  PACKAGE_MISMATCH:    1 << 1,  // 2
  TOKEN_STALE:         1 << 2,  // 4
  APP_NOT_RECOGNIZED:  1 << 3,  // 8
  APP_NOT_EVALUATED:   1 << 4,  // 16
  DEVICE_NOT_TRUSTED:  1 << 5,  // 32
  DEVICE_BASIC:        1 << 6,  // 64
  CERT_MISMATCH:       1 << 7,  // 128
  CERT_MISSING:        1 << 8,  // 256
};

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
        const errorText = await verifyResp.text().catch(() => "");
        console.error(`[ATTESTATION VERIFY] Meta API error: ${verifyResp.status} - ${errorText.slice(0, 200)}`);
        return null;
      }

      const response = await readJson(verifyResp, "ATTESTATION VERIFY");
      if (!response) return null;

      if (response.error) {
        console.error("[ATTESTATION VERIFY] Meta returned error:", response.error);
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
  const result = { valid: true, reason: "ok", clientHash: null };

  if (!certHashes || !Array.isArray(certHashes) || certHashes.length === 0) {
    result.valid = false;
    result.reason = "no_cert_in_payload";
    return result;
  }

  result.clientHash = String(certHashes[0] || "").toLowerCase();

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
    const errorDetails = playfabErrorResponse?.errorDetails;
    if (errorDetails && typeof errorDetails === 'object') {
      const reasons = Object.keys(errorDetails);
      if (reasons.length > 0) {
        result.reason = reasons[0];
        const expiryArray = errorDetails[reasons[0]];
        if (Array.isArray(expiryArray) && expiryArray.length > 0) {
          result.expiry = expiryArray[0];
        }
      }
    }

    if (result.expiry && result.expiry !== "Indefinite") {
      try {
        const expiryDate = new Date(result.expiry);
        const now = new Date();
        const diffMs = expiryDate.getTime() - now.getTime();

        if (diffMs > 0) {
          result.durationMinutes = Math.min(
            Math.ceil(diffMs / (1000 * 60)),
            52560000
          );
        } else {
          result.durationMinutes = 1;
        }
      } catch {
        console.error('[extractBanInfo] Failed to parse expiry date:', result.expiry);
      }
    }

    return result;
  } catch (e) {
    console.error('[extractBanInfo] Error:', e);
    return result;
  }
}

async function getPlayFabIdFromCustomId(metaId, titleId, secretKey) {
  try {
    const resp = await fetch(`https://${titleId}.playfabapi.com/Server/GetPlayFabIDsFromGenericIDs`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-SecretKey": secretKey },
      body: JSON.stringify({
        GenericIDs: [{ ServiceName: "CustomId", UserId: metaId }]
      })
    });

    if (!resp.ok) return null;
    const data = await readJson(resp, "PF LOOKUP");
    if (!data) return null;
    return data.data?.Data?.[0]?.PlayFabId ?? null;
  } catch (e) {
    console.error("[PF LOOKUP] Exception:", e);
    return null;
  }
}

/**
 * Bans a device via Meta's API.
 */
async function banDevice(uniqueId, accessToken, durationMinutes = 52560000, options = {}) {
  const { banReason = "Security violation", metaId = "unknown" } = options;

  if (!uniqueId) {
    console.warn('[META DEVICE BAN] No unique_id available - cannot ban device');
    return { success: false, error: 'No unique_id' };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000);

  try {
    const resp = await fetch('https://graph.oculus.com/platform_integrity/device_ban', {
      method: 'POST',
      signal: controller.signal,
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

    const data = (await readJson(resp, "META DEVICE BAN")) || {};

    if (data.message === "Success" && data.ban_id) {
      const durationDisplay = durationMinutes >= 52560000 ? 'PERMANENT' : `${durationMinutes} minutes`;
      console.log(`[META DEVICE BAN] Success | MetaId:${metaId} | UniqueId:${uniqueId} | Duration:${durationDisplay} | BanId:${data.ban_id}`);
      return { success: true, banId: data.ban_id, issuedAt: new Date().toISOString(), reason: banReason, durationMinutes, uniqueId };
    } else {
      console.error(`[META DEVICE BAN FAILED]`, data);
      return { success: false, error: data };
    }
  } catch (e) {
    if (e?.name === "AbortError") {
      console.error("[META DEVICE BAN] Request timed out after 10s");
      return { success: false, error: "timeout" };
    }
    console.error(`[META DEVICE BAN ERROR]`, e);
    return { success: false, error: e.message };
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Convenience wrapper: ban device via Meta API AND (optionally) record into Security blob.
 * - If a mutable `blob` is provided, we mutate it (caller should persist once).
 * - Otherwise, if PlayFab context is provided, we load+save Security immediately.
 */
async function banDeviceAndRecord(uniqueId, accessToken, durationMinutes, options = {}) {
  const { titleId, secretKey, playFabId, blob, banReason = "Security violation", metaId = "unknown" } = options;

  const metaBan = await banDevice(uniqueId, accessToken, durationMinutes, { banReason, metaId });

  if (!metaBan?.success) return metaBan;

  if (blob) {
    applyMetaBanToBlob(blob, metaBan);
    return { ...metaBan, recorded: true };
  }

  if (titleId && secretKey && playFabId) {
    try {
      const b = await loadSecurityBlob(titleId, secretKey, playFabId);
      if (!b) {
        console.error(`[META BAN RECORD FAILED] Could not load Security blob. PlayFabId:${playFabId} | MetaId:${metaId}`);
        return { ...metaBan, recorded: false };
      }
      applyMetaBanToBlob(b, metaBan);
      // Optional last-updated marker
      const now = new Date().toISOString();
      b.lua = now;
      await saveSecurityBlob(titleId, secretKey, playFabId, b);
      return { ...metaBan, recorded: true };
    } catch (e) {
      console.error(`[META BAN RECORD FAILED] PlayFabId:${playFabId} | MetaId:${metaId} | Error:`, e?.message || e);
      return { ...metaBan, recorded: false };
    }
  }

  return { ...metaBan, recorded: false };
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

  if (req.method === "GET" || req.method === "HEAD") {
    return res.status(204).end();
  }
  if (req.method !== "POST") {
    return res.status(405).json({ success: false, error: "Method Not Allowed" });
  }

  try {
    // === Parse body ===
    let bodyData;
    const contentType = req.headers['content-type'] || '';
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const rawBody = await new Promise((resolve, reject) => {
        let data = '';
        req.on('data', chunk => (data += chunk));
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
      oculusResp = await fetch("https://graph.oculus.com/user_nonce_validate", {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${oculusAccessToken}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: querystring.stringify({ nonce, user_id: metaId }),
        signal: nonceController.signal
      });
      clearTimeout(nonceTimeoutId);
      oculusBody = await oculusResp.text();
    } catch (e) {
      clearTimeout(nonceTimeoutId);
      if (e.name === 'AbortError') console.error("[NONCE VALIDATE] Request timed out after 10s");
      else console.error("[NONCE VALIDATE] Request failed:", e.message);
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
    // Hoist computed checks so they can be used later (forensics/event logging)
    let nonceOk = false;
    let packageOk = false;
    let fresh = false;
    let strictAppOk = false;
    let strictDeviceOk = false;
    let certOk = true;
    const certCheckApplies = !!VALID_CERT_HASH;

    let attestation = {
      valid: false,
      reason: "no_token",
      app_integrity: null,
      device_integrity: null,
      unique_id: null,
      device_ban: null,
      cert_check: null
    };

    let payload = null;
    if (attestationToken) {
      payload = await verifyAttestationWithMeta(attestationToken, oculusAccessToken);

      if (!payload) {
        attestation.reason = "verification_failed";
        console.warn(`[ATTESTATION] Meta verification failed for user: ${metaId}`);
      } else {
        const rawApp = payload.app_state?.app_integrity_state || "unknown";
        const rawDevice = payload.device_state?.device_integrity_state || "unknown";

        attestation.app_integrity = rawApp;
        attestation.device_integrity = rawDevice;
        attestation.unique_id = payload.device_state?.unique_id || null;
        attestation.device_ban = payload.device_ban || null;

        // Certificate validation
        attestation.cert_check = validateCertificate(payload.app_state?.package_cert_sha256_digest);

        if (!KNOWN_APP_STATES.includes(rawApp) || !KNOWN_DEVICE_STATES.includes(rawDevice)) {
          console.warn(`[ATTESTATION] UNKNOWN INTEGRITY STATE → App:${rawApp} Device:${rawDevice} MetaId:${metaId}`);
        }

        // Meta device ban check
        if (attestation.device_ban?.is_banned === true) {
          console.warn(`[META DEVICE BANNED] User:${metaId}`);
          return res.status(403).json({
            success: false,
            error: "AccountBanned",
            errorCode: 1002,
            errorMessage: "This device is banned.",
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

        nonceOk = payload.request_details?.nonce === expectedNonce;
        packageOk = payload.app_state?.package_id === "com.ContinuumXR.UG";
        fresh = Math.abs(Date.now() / 1000 - (payload.request_details?.timestamp || 0)) < 300;
        strictAppOk = rawApp === "StoreRecognized";
        strictDeviceOk = rawDevice === "Advanced";
        certOk = attestation.cert_check?.valid ?? true;

        attestation.valid =
          nonceOk &&
          packageOk &&
          fresh &&
          strictAppOk &&
          strictDeviceOk &&
          (certCheckApplies ? certOk : true);

        if (!attestation.valid) {
          const failReasons = [];
          if (!nonceOk) failReasons.push("nonce_mismatch");
          if (!packageOk) failReasons.push("package_mismatch");
          if (!fresh) failReasons.push("token_stale");
          if (!strictAppOk) failReasons.push(`app_${rawApp}`);
          if (!strictDeviceOk) failReasons.push(`device_${rawDevice}`);
          if (certCheckApplies && !certOk) failReasons.push(`cert_${attestation.cert_check?.reason || "bad_cert"}`);
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

    const playfabData = await readJson(playfabResp, "PLAYFAB LOGIN");
    if (!playfabData) {
      return res.status(503).json({ success: false, error: "Service temporarily unavailable" });
    }

    if (!playfabResp.ok) {
      if (playfabData.errorCode === 1002) {
        // User is banned - extract ban info from PlayFab response
        const banInfo = extractBanInfo(playfabData);
        console.warn(`[BANNED USER LOGIN] MetaId:${metaId} | Reason:${banInfo.reason} | Expiry:${banInfo.expiry}`);

        const masterPlayFabId = await getPlayFabIdFromCustomId(metaId, titleId, secretKey);

        if (attestation.unique_id && masterPlayFabId) {
          await banDeviceAndRecord(attestation.unique_id, oculusAccessToken, banInfo.durationMinutes, {
            titleId,
            secretKey,
            playFabId: masterPlayFabId,
            banReason: `PlayFab ban: ${banInfo.reason}`,
            metaId
          });
        } else if (!masterPlayFabId) {
          console.error(`[CRITICAL] Failed to resolve MasterPlayFabId for banned MetaId:${metaId} — Meta ban NOT stored!`);
        }

        return res.status(403).json({
          success: false,
          error: "AccountBanned",
          errorCode: 1002,
          errorMessage: "Account is banned.",
          banInfo: { reason: banInfo.reason, expiry: banInfo.expiry }
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

    const masterPlayFabId = playfabData.data.PlayFabId;

    // === SECURITY BLOB (load once, save once) ===
    let securityBlob; // undefined = not loaded yet
    let securityDirty = false;

    async function ensureBlob() {
      // If we already tried and failed, don't keep retrying in this request
      if (securityBlob === null) return null;

      // First attempt
      if (securityBlob === undefined) {
        const loaded = await loadSecurityBlob(titleId, secretKey, masterPlayFabId);
        securityBlob = loaded || null; // null marks a failed load
      }

      return securityBlob; // either object or null
    }

    // === FINAL ENFORCEMENT ===
    if (ENFORCEMENT_CONFIG.enabled) {
      // Handle missing attestation token
      if (!attestationToken) {
        const noTokenAction = getEnforcementAction("no_token");
        if (noTokenAction !== "allow") {
          console.warn(`[ATTESTATION BLOCKED] No token | MetaId:${metaId} | Action:${noTokenAction}`);
          return res.status(403).json({
            success: false,
            error: "UpdateRequired",
            errorMessage: "A new game update is required to play."
          });
        }
      }

      // Handle verification failures (Meta API couldn't verify)
      if (attestation.reason === "verification_failed") {
        const verifyAction = getEnforcementAction("verification_failed");
        if (verifyAction !== "allow") {
          console.warn(`[ATTESTATION BLOCKED] Verification failed | MetaId:${metaId} | Action:${verifyAction}`);
          return res.status(403).json({
            success: false,
            error: "VerificationFailed",
            errorCode: 1003,
            errorMessage: "Unable to verify device. Please try again later."
          });
        }
      }

      // Handle attestation failures with tiered enforcement
      if (!attestation.valid && attestation.reason !== "verification_failed") {
        const action = getEnforcementAction(attestation.reason);
        
        // Developer bypass for NotEvaluated
        let allow = action === "allow";
        if (!allow && attestation.app_integrity === "NotEvaluated") {
          const isDev = await isDeveloper(masterPlayFabId, titleId, secretKey);
          if (isDev) {
            console.log(`[DEV BYPASS] Allowing NotEvaluated for developer: ${metaId}`);
            allow = true;
          }
        }

        if (!allow) {
          console.warn(`[ATTESTATION ${action.toUpperCase()}] PlayFabId:${masterPlayFabId} | MetaId:${metaId} | App:${attestation.app_integrity} | Device:${attestation.device_integrity} | Reasons:${attestation.reason} | Action:${action}`);

          // Only ban if action is "ban" (not "block")
          if (action === "ban") {
            // PlayFab permanent ban
            try {
              await fetch(`https://${titleId}.playfabapi.com/Server/BanUsers`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
                body: JSON.stringify({
                  Bans: [{ PlayFabId: masterPlayFabId, Reason: "Security violation" }]
                })
              });
            } catch (e) {
              console.error("[PLAYFAB BAN FAILED]", e);
            }

            // Meta permanent hardware ban (store in Security blob)
            if (attestation.unique_id) {
              const blob = await ensureBlob();
              const metaBan = await banDeviceAndRecord(attestation.unique_id, oculusAccessToken, 52560000, {
                titleId,
                secretKey,
                playFabId: masterPlayFabId,
                blob,
                banReason: `Attestation: ${attestation.reason}`,
                metaId
              });
              if (metaBan.success && metaBan.recorded) securityDirty = true;
            }
          }

          // Record enforcement in blob for investigators (both block and ban)
          {
            const blob = await ensureBlob();
            if (blob) {
              const now = new Date().toISOString();
              const di = blob.di || (blob.di = {});
              di.lastEnforce = now;
              di.lastAction = action; // Record whether it was block or ban
              blob.lua = now;
              securityDirty = true;
            } else {
              console.error(`[SECURITY BLOB] Failed to load — cannot record lastEnforce. PlayFabId:${masterPlayFabId}`);
            }
          }

          if (securityDirty && securityBlob) {
            try { await saveSecurityBlob(titleId, secretKey, masterPlayFabId, securityBlob); } catch {}
          }

          // Return appropriate error based on action type
          if (action === "ban") {
            return res.status(403).json({
              success: false,
              error: "AccountBanned",
              errorCode: 1002,
              errorMessage: "Unable to authenticate. Please try again.",
              banInfo: { reason: "Security violation", expiry: "Indefinite" }
            });
          } else {
            // action === "block" - reject but don't ban
            return res.status(403).json({
              success: false,
              error: "AuthenticationBlocked",
              errorCode: 1004,
              errorMessage: "Unable to authenticate. Please try again later."
            });
          }
        }
      }
    }

    // === FORENSIC LOGGING ===
    if (attestationToken && !attestation.valid && attestation.reason !== "verification_failed") {
      const now = new Date().toISOString();
      const blob = await ensureBlob();
      if (!blob) {
        console.error(`[SECURITY BLOB] Failed to load — skipping forensic logging. PlayFabId:${masterPlayFabId}`);
      } else {
        const di = blob.di || (blob.di = {});

        // Core counters
        if (!di.ff) di.ff = now;
        di.lf = now;
        di.c = (di.c || 0) + 1;

        // Worst states
        const worstApp = worstState(di.wa, attestation.app_integrity, KNOWN_APP_STATES);
        const worstDev = worstState(di.wd, attestation.device_integrity, KNOWN_DEVICE_STATES);
        if (worstApp) di.wa = worstApp;
        if (worstDev) di.wd = worstDev;

        // Re-compute checks safely (payload may be null)
        const expectedNonce = crypto.createHash('sha256')
          .update(nonce)
          .digest('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, '');

        const nonceOk = payload?.request_details?.nonce === expectedNonce;
        const packageOk = payload?.app_state?.package_id === "com.ContinuumXR.UG";
        const fresh = payload?.request_details?.timestamp 
          ? Math.abs(Date.now() / 1000 - payload.request_details.timestamp) < 300 
          : false;
        const strictAppOk = attestation.app_integrity === "StoreRecognized";
        const strictDeviceOk = attestation.device_integrity === "Advanced";
        const certOk = !certCheckApplies || attestation.cert_check?.valid;

        const certOkEffective = !certCheckApplies || certOk;

        // Reason mask
        let rm = di.rm || 0;
        if (!nonceOk)        rm |= FLAGS.NONCE_MISMATCH;
        if (!packageOk)      rm |= FLAGS.PACKAGE_MISMATCH;
        if (!fresh)          rm |= FLAGS.TOKEN_STALE;
        if (!strictAppOk)    rm |= attestation.app_integrity === "NotEvaluated" ? FLAGS.APP_NOT_EVALUATED : FLAGS.APP_NOT_RECOGNIZED;
        if (!strictDeviceOk) rm |= attestation.device_integrity === "Basic" ? FLAGS.DEVICE_BASIC : FLAGS.DEVICE_NOT_TRUSTED;

        if (certCheckApplies && !certOkEffective) {
          rm |= attestation.cert_check?.reason === "cert_mismatch" ? FLAGS.CERT_MISMATCH : FLAGS.CERT_MISSING;
        }
        di.rm = rm;

        // Rest of your existing code (unique_id, cert, etc.) is safe
        if (attestation.unique_id) di.uid = attestation.unique_id;
        if (attestation.cert_check?.clientHash) di.ch = attestation.cert_check.clientHash;
        if (attestation.cert_check?.reason === "cert_mismatch") {
          di.cmc = (di.cmc || 0) + 1;
          if (!di.fcm) di.fcm = now;
        }

        blob.lua = now;
        securityDirty = true;

        // Event logging (safe — uses only attestation fields)
        try {
          await fetch(`https://${titleId}.playfabapi.com/Server/WritePlayerEvent`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
            body: JSON.stringify({
              PlayFabId: masterPlayFabId,
              EventName: "device_integrity_failure",
              Body: {
                ts: now,
                app: attestation.app_integrity,
                dev: attestation.device_integrity,
                rm,
                uid: attestation.unique_id?.slice(0, 12) || null,
                cert: attestation.cert_check?.clientHash || null,
                reason: attestation.reason
              }
            })
          });
        } catch (e) {
          console.warn("[EVENT LOG FAILED]", e);
        }
      }
    }

    // Log verification failures in Security blob (no extra keys)
    if (attestation.reason === "verification_failed") {
      const now = new Date().toISOString();
      const blob = await ensureBlob();
      if (blob) {
        const di = blob.di || (blob.di = {});
        di.vfe = (di.vfe || 0) + 1;
        di.vfl = now;
        blob.lua = now;
        securityDirty = true;
      } else {
          console.error(`[SECURITY BLOB] Failed to load — cannot record verify failure. PlayFabId:${masterPlayFabId}`);
      }
    }

    // Save security blob once at end of request if mutated
    if (securityDirty && securityBlob) {
      try { await saveSecurityBlob(titleId, secretKey, masterPlayFabId, securityBlob); }
      catch (e) { console.error("[SECURITY BLOB SAVE FAILED]", e); }
    }

    // Newly created: add Generic ID mapping (one-time)
    if (playfabData.data.NewlyCreated) {
      try {
        await fetch(`https://${titleId}.playfabapi.com/Server/AddGenericID`, {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-SecretKey": secretKey },
          body: JSON.stringify({
            PlayFabId: masterPlayFabId,
            GenericId: { ServiceName: "CustomId", UserId: metaId }
          })
        });
      } catch (e) {
        console.error("[GENERIC ID ADD FAILED]", e);
      }
    }

    return res.status(200).json({
      success: true,
      sessionTicket: playfabData.data.SessionTicket,
      playFabId: playfabData.data.PlayFabId,
      newlyCreated: playfabData.data.NewlyCreated,
      infoPayload: JSON.stringify(playfabData.data.InfoResultPayload),
      entityToken: playfabData.data.EntityToken.EntityToken,
      entityId: playfabData.data.EntityToken.Entity.Id,
      entityType: playfabData.data.EntityToken.Entity.Type
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
      const data = await readJson(resp, "IS DEVELOPER");
      if (!data) return false;
      return data.data?.Data?.IsDeveloper?.Value === "true";
    }
  } catch (e) {
    console.error('[isDeveloper failed]', e);
  }
  return false;
}