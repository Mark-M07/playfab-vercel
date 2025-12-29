// api/verifyoculuslogin.js
import fetch from 'node-fetch';
import querystring from 'node:querystring';
import crypto from 'crypto';

// === CONFIGURATION ===
const KNOWN_APP_STATES = ["NotRecognized", "NotEvaluated", "StoreRecognized"];
const KNOWN_DEVICE_STATES = ["NotTrusted", "Basic", "Advanced"];

// Expected package ID (optional environment variable override)
const EXPECTED_PACKAGE_ID = process.env.EXPECTED_PACKAGE_ID || "com.ContinuumXR.UG";

// APK Certificate Validation Config
// SHA256 hash of release signing certificate (lowercase, no colons)
// Leave empty to monitor without validation (will log all cert hashes)
const VALID_CERT_HASH = (process.env.VALID_CERT_HASH || "").trim().toLowerCase();

// Token freshness threshold in seconds
const TOKEN_FRESHNESS_THRESHOLD = 300;

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
  app_NotEvaluated: "ban",      // Not in any Meta release channel
  
  // Certificate mismatch
  cert_mismatch: "ban",         // Modified APK
  cert_missing: "ban",          // Missing cert data
  
  // Nonce/package issues (likely tampering)
  nonce_mismatch: "ban",
  package_mismatch: "ban",
  
  // Meta API couldn't verify token
  verification_failed: "block", // Block but don't ban (could be API issue)
  
  // No attestation token provided
  no_token: "block",            // Modified client
};

// ============================================================================
// TEMPORARY: SECURITY BREACH AUTO-REMEDIATION (December 2025)
// Remove this section after January 2026 when all affected users have logged in
// ============================================================================
const BREACH_REMEDIATION = {
  enabled: true,  // Master switch for auto-remediation
  
  // Fraudulent ban reasons from the attack - exact match required
  fraudReasons: new Set([
    "PlayFab ban: Toxic behavior in game.",
    // Add any other discovered fraudulent reasons here
  ]),
  
  // Attack time window (UTC) - with buffer for safety
  // Actual attack: 2025-12-19 02:39 to 03:14 UTC
  // Adding 24hr buffer on each side to catch any we might have missed
  window: {
    start: new Date("2025-12-18T00:00:00Z"),
    end: new Date("2025-12-20T23:59:59Z"),
  },
  
  // Set to false to remediate regardless of time window
  enforceTimeWindow: false,
};

/**
 * TEMPORARY: Check if a Security blob contains a fraudulent ban from the breach
 * @param {object} blob - The Security blob
 * @returns {object|null} - Ban details if fraudulent, null otherwise
 */
function detectFraudulentBan(blob) {
  if (!BREACH_REMEDIATION.enabled) return null;
  if (!blob?.mb) return null;
  
  const { bid, r: reason, ia: issuedAt, uid } = blob.mb;
  
  if (!bid || !reason) return null;
  
  // Check if reason matches known fraudulent patterns
  if (!BREACH_REMEDIATION.fraudReasons.has(reason)) return null;
  
  // Optional: Check if ban was issued during the breach window
  if (BREACH_REMEDIATION.enforceTimeWindow && issuedAt) {
    try {
      const banDate = new Date(issuedAt);
      if (banDate < BREACH_REMEDIATION.window.start || banDate > BREACH_REMEDIATION.window.end) {
        console.log(`[BREACH-REMEDIATE] Ban outside time window, skipping. IssuedAt: ${issuedAt}`);
        return null;
      }
    } catch (e) {
      // If we can't parse the date, proceed with remediation anyway
    }
  }
  
  return { banId: bid, reason, issuedAt, uniqueId: uid };
}

/**
 * TEMPORARY: Unban a device that was fraudulently banned during the breach
 * @param {string} banId - The Meta ban ID
 * @param {string} accessToken - Meta API access token
 * @returns {Promise<{success: boolean, error?: string}>}
 */
async function remediateFraudulentBan(banId, accessToken) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);
    
    const resp = await fetch('https://graph.oculus.com/platform_integrity/device_ban', {
      method: 'POST',
      signal: controller.signal,
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        ban_id: banId,
        is_banned: false,
        remaining_time_in_minute: 0
      })
    });
    
    clearTimeout(timeoutId);
    const data = await resp.json().catch(() => ({}));
    
    if (resp.ok && data.message === "Success") {
      return { success: true };
    } else {
      return { success: false, error: data.error?.message || `HTTP ${resp.status}` };
    }
  } catch (e) {
    if (e.name === 'AbortError') {
      return { success: false, error: 'timeout' };
    }
    return { success: false, error: e.message };
  }
}

/**
 * TEMPORARY: Clear fraudulent ban from Security blob and add audit trail
 * @param {object} blob - The Security blob (will be mutated)
 * @param {object} fraudBan - The fraudulent ban details
 */
function clearFraudulentBanFromBlob(blob, fraudBan) {
  if (!blob) return;
  
  const now = new Date().toISOString();
  
  // Store audit trail in di (device integrity) section
  if (!blob.di) blob.di = {};
  blob.di.breach_remediated = now;
  blob.di.fraud_ban_id = fraudBan.banId;
  blob.di.fraud_ban_reason = fraudBan.reason;
  blob.di.fraud_ban_issued = fraudBan.issuedAt;
  
  // Remove the fraudulent ban data
  delete blob.mb;
  
  // Update timestamp
  blob.lua = now;
}
// ============================================================================
// END TEMPORARY BREACH REMEDIATION
// ============================================================================

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

// === HELPERS ===

/**
 * Helper to determine action for a given failure
 */
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
    
    // Warn on unknown config keys (typos, new Meta states, etc.)
    if (reasonAction === undefined) {
      console.warn(`[ENFORCEMENT] Unknown reason key: ${configKey} — defaulting to allow`);
    }
    
    // Escalate: ban > block > allow
    if (reasonAction === "ban") return "ban"; // Immediate escalation
    if (reasonAction === "block" && action !== "ban") action = "block";
  }
  
  return action;
}

/**
 * Safe JSON parser with fallback
 */
function safeParseJson(str, fallback) {
  try { return str ? JSON.parse(str) : fallback; } catch { return fallback; }
}

/**
 * Read JSON from response with error handling
 */
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
 * Analyzes attestation payload and returns consolidated check results.
 * Single source of truth for all attestation checks - used by both enforcement and forensics.
 */
function analyzeAttestationPayload(payload, nonce, certCheck) {
  const certCheckApplies = !!VALID_CERT_HASH;
  
  // Compute expected nonce hash
  const expectedNonce = crypto.createHash('sha256')
    .update(nonce)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  // All checks in one place
  const checks = {
    nonceOk: payload?.request_details?.nonce === expectedNonce,
    packageOk: payload?.app_state?.package_id === EXPECTED_PACKAGE_ID,
    fresh: payload?.request_details?.timestamp 
      ? Math.abs(Date.now() / 1000 - payload.request_details.timestamp) < TOKEN_FRESHNESS_THRESHOLD 
      : false,
    strictAppOk: payload?.app_state?.app_integrity_state === "StoreRecognized",
    strictDeviceOk: payload?.device_state?.device_integrity_state === "Advanced",
    certOk: certCheck?.valid ?? true,
  };

  // Determine overall validity
  const isValid = checks.nonceOk &&
    checks.packageOk &&
    checks.fresh &&
    checks.strictAppOk &&
    checks.strictDeviceOk &&
    (certCheckApplies ? checks.certOk : true);

  // Build fail reasons list
  // Normalise unknown states to prevent log pollution if Meta introduces new states
  const rawAppState = payload?.app_state?.app_integrity_state || "unknown";
  const rawDeviceState = payload?.device_state?.device_integrity_state || "unknown";
  const normalisedAppState = KNOWN_APP_STATES.includes(rawAppState) ? rawAppState : "Unknown";
  const normalisedDeviceState = KNOWN_DEVICE_STATES.includes(rawDeviceState) ? rawDeviceState : "Unknown";

  const failReasons = [];
  if (!checks.nonceOk) failReasons.push("nonce_mismatch");
  if (!checks.packageOk) failReasons.push("package_mismatch");
  if (!checks.fresh) failReasons.push("token_stale");
  if (!checks.strictAppOk) failReasons.push(`app_${normalisedAppState}`);
  if (!checks.strictDeviceOk) failReasons.push(`device_${normalisedDeviceState}`);
  if (certCheckApplies && !checks.certOk) {
    failReasons.push(`cert_${certCheck?.reason || "bad_cert"}`);
  }

  // Compute reason bitmask for forensics (using normalised states)
  let reasonMask = 0;
  if (!checks.nonceOk) reasonMask |= FLAGS.NONCE_MISMATCH;
  if (!checks.packageOk) reasonMask |= FLAGS.PACKAGE_MISMATCH;
  if (!checks.fresh) reasonMask |= FLAGS.TOKEN_STALE;
  if (!checks.strictAppOk) {
    reasonMask |= normalisedAppState === "NotEvaluated" ? FLAGS.APP_NOT_EVALUATED : FLAGS.APP_NOT_RECOGNIZED;
  }
  if (!checks.strictDeviceOk) {
    reasonMask |= normalisedDeviceState === "Basic" ? FLAGS.DEVICE_BASIC : FLAGS.DEVICE_NOT_TRUSTED;
  }
  if (certCheckApplies && !checks.certOk) {
    reasonMask |= certCheck?.reason === "cert_mismatch" ? FLAGS.CERT_MISMATCH : FLAGS.CERT_MISSING;
  }

  return {
    checks,
    isValid,
    failReasons,
    reasonString: failReasons.join("|") || "ok",
    reasonMask,
    certCheckApplies,
  };
}

/**
 * Determine worst state between current and candidate
 */
function worstState(current, candidate, order) {
  if (!candidate) return null;
  const scores = Object.fromEntries(order.map((s, i) => [s, i]));
  const curScore = current ? (scores[current] ?? 999) : 999;
  const candScore = scores[candidate] ?? 999;
  return candScore < curScore ? candidate : null;
}

// === SECURITY BLOB HELPERS ===

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

// === META API HELPERS ===

/**
 * Verify attestation token with Meta's server-to-server API
 */
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
      b.lua = new Date().toISOString();
      await saveSecurityBlob(titleId, secretKey, playFabId, b);
      return { ...metaBan, recorded: true };
    } catch (e) {
      console.error(`[META BAN RECORD FAILED] PlayFabId:${playFabId} | MetaId:${metaId} | Error:`, e?.message || e);
      return { ...metaBan, recorded: false };
    }
  }

  return { ...metaBan, recorded: false };
}

// === PLAYFAB HELPERS ===

/**
 * Extracts ban info from PlayFab error response.
 * PlayFab format: { errorDetails: { "BanReason": ["ExpiryDateOrIndefinite"] } }
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

// === MAIN HANDLER ===

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
      try {
        bodyData = req.body;
      } catch (e) {
        console.warn(`[PROBE] Malformed JSON | UA: ${req.headers['user-agent'] || 'unknown'} | IP: ${req.headers['x-forwarded-for'] || 'unknown'}`);
        return res.status(400).json({ success: false, error: "Unable to authenticate. Please try again." });
      }
    }

    if (!bodyData) {
      console.warn(`[PROBE] Empty body | UA: ${req.headers['user-agent'] || 'unknown'} | IP: ${req.headers['x-forwarded-for'] || 'unknown'}`);
      return res.status(400).json({ success: false, error: "Unable to authenticate. Please try again." });
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
      if (e.name === 'AbortError') {
        console.error("[NONCE VALIDATE] Request timed out after 10s");
        console.warn(`[ATTESTATION BLOCKED] Verification failed | MetaId:${metaId} | Action:block`);
      } else {
        console.error("[NONCE VALIDATE] Request failed:", e.message);
        console.warn(`[ATTESTATION BLOCKED] Verification failed | MetaId:${metaId} | Action:block`);
      }
      return res.status(403).json({
        success: false,
        error: "AuthenticationFailed",
        errorMessage: "Unable to authenticate. Please try again."
      });
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
      cert_check: null,
      analysis: null,
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

        // Meta device ban check (early exit)
        if (attestation.device_ban?.is_banned === true) {
          console.warn(`[META DEVICE BANNED] User:${metaId} | UniqueId:${attestation.unique_id || 'unknown'} | RemainingTime:${attestation.device_ban?.remaining_ban_time || 'unknown'}`);
          
          // ============================================================
          // TEMPORARY: Check if this is a fraudulent ban from the breach
          // ============================================================
          const masterPlayFabIdForRemediation = await getPlayFabIdFromCustomId(metaId, titleId, secretKey);
          if (masterPlayFabIdForRemediation && BREACH_REMEDIATION.enabled) {
            const blob = await loadSecurityBlob(titleId, secretKey, masterPlayFabIdForRemediation);
            if (blob) {
              const fraudBan = detectFraudulentBan(blob);
              if (fraudBan) {
                console.log(`[BREACH-REMEDIATE] Detected fraudulent ban for MetaId:${metaId} PlayFabId:${masterPlayFabIdForRemediation} BanId:${fraudBan.banId}`);
                
                const unbanResult = await remediateFraudulentBan(fraudBan.banId, oculusAccessToken);
                
                if (unbanResult.success) {
                  console.log(`[BREACH-REMEDIATE] Successfully unbanned MetaId:${metaId} PlayFabId:${masterPlayFabIdForRemediation}`);
                  
                  // Clear from blob and save
                  clearFraudulentBanFromBlob(blob, fraudBan);
                  await saveSecurityBlob(titleId, secretKey, masterPlayFabIdForRemediation, blob);
                  
                  // Log remediation event to PlayFab
                  try {
                    await fetch(`https://${titleId}.playfabapi.com/Server/WritePlayerEvent`, {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
                      body: JSON.stringify({
                        PlayFabId: masterPlayFabIdForRemediation,
                        EventName: "breach_auto_remediation",
                        Body: {
                          ts: new Date().toISOString(),
                          banId: fraudBan.banId,
                          reason: fraudBan.reason,
                          issuedAt: fraudBan.issuedAt,
                          source: "meta_device_ban_check"
                        }
                      })
                    });
                  } catch (e) {
                    console.warn("[BREACH-REMEDIATE] Failed to log event:", e.message);
                  }
                  
                  // Return special response telling user to retry
                  return res.status(200).json({
                    success: false,
                    error: "BanRemediated",
                    errorCode: 1099,
                    errorMessage: "Your account has been restored. Please restart the app to log in."
                  });
                } else {
                  console.error(`[BREACH-REMEDIATE] Failed to unban MetaId:${metaId}: ${unbanResult.error}`);
                  // Fall through to normal banned response
                }
              }
            }
          }
          // ============================================================
          // END TEMPORARY BREACH REMEDIATION
          // ============================================================
          
          const remainingDays = parseInt(attestation.device_ban.remaining_ban_time, 10) || 0;

          return res.status(403).json({
            success: false,
            error: "AccountBanned",
            errorCode: 1002,
            errorMessage: "This device is banned.",
            banInfo: { reason: "Device banned", expiry: (remainingDays >= 3650) ? "Indefinite" : attestation.device_ban.remaining_ban_time }
          });
        }

        // Consolidated attestation analysis (single source of truth)
        attestation.analysis = analyzeAttestationPayload(payload, nonce, attestation.cert_check);
        attestation.valid = attestation.analysis.isValid;
        attestation.reason = attestation.analysis.reasonString;

        if (!attestation.valid) {
          console.warn(`[ATTESTATION FAILED] User:${metaId} | Reasons:${attestation.reason}`);
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

        // ============================================================
        // TEMPORARY: Check if this is a fraudulent ban from the breach
        // ============================================================
        if (masterPlayFabId && BREACH_REMEDIATION.enabled) {
          const blob = await loadSecurityBlob(titleId, secretKey, masterPlayFabId);
          if (blob) {
            const fraudBan = detectFraudulentBan(blob);
            if (fraudBan) {
              console.log(`[BREACH-REMEDIATE] Detected fraudulent PlayFab ban for MetaId:${metaId} PlayFabId:${masterPlayFabId} BanId:${fraudBan.banId}`);
              
              // First, unban from Meta if they have a Meta ban
              let metaUnbanSuccess = true;
              if (fraudBan.banId) {
                const unbanResult = await remediateFraudulentBan(fraudBan.banId, oculusAccessToken);
                metaUnbanSuccess = unbanResult.success;
                if (!metaUnbanSuccess) {
                  console.error(`[BREACH-REMEDIATE] Failed to unban from Meta: ${unbanResult.error}`);
                }
              }
              
              // Revoke the PlayFab ban
              let playfabUnbanSuccess = false;
              try {
                // Get all bans for this user
                const getBansResp = await fetch(`https://${titleId}.playfabapi.com/Server/GetUserBans`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
                  body: JSON.stringify({ PlayFabId: masterPlayFabId })
                });
                
                if (getBansResp.ok) {
                  const bansData = await getBansResp.json();
                  const activeBans = bansData?.data?.BanData?.filter(b => b.Active) || [];
                  
                  // Find bans matching the fraudulent reason pattern
                  const fraudulentPlayFabBans = activeBans.filter(b => 
                    BREACH_REMEDIATION.fraudReasons.has(`PlayFab ban: ${b.Reason}`) ||
                    b.Reason === "Toxic behavior in game."
                  );
                  
                  if (fraudulentPlayFabBans.length > 0) {
                    // Revoke the fraudulent bans
                    const revokeResp = await fetch(`https://${titleId}.playfabapi.com/Server/RevokeAllBansForUser`, {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
                      body: JSON.stringify({ PlayFabId: masterPlayFabId })
                    });
                    playfabUnbanSuccess = revokeResp.ok;
                    
                    if (playfabUnbanSuccess) {
                      console.log(`[BREACH-REMEDIATE] Revoked PlayFab bans for PlayFabId:${masterPlayFabId}`);
                    }
                  }
                }
              } catch (e) {
                console.error(`[BREACH-REMEDIATE] Failed to revoke PlayFab ban: ${e.message}`);
              }
              
              // Clear from blob and save
              if (metaUnbanSuccess || playfabUnbanSuccess) {
                clearFraudulentBanFromBlob(blob, fraudBan);
                await saveSecurityBlob(titleId, secretKey, masterPlayFabId, blob);
                
                // Log remediation event
                try {
                  await fetch(`https://${titleId}.playfabapi.com/Server/WritePlayerEvent`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
                    body: JSON.stringify({
                      PlayFabId: masterPlayFabId,
                      EventName: "breach_auto_remediation",
                      Body: {
                        ts: new Date().toISOString(),
                        banId: fraudBan.banId,
                        reason: fraudBan.reason,
                        issuedAt: fraudBan.issuedAt,
                        metaUnban: metaUnbanSuccess,
                        playfabUnban: playfabUnbanSuccess,
                        source: "playfab_ban_check"
                      }
                    })
                  });
                } catch (e) {
                  console.warn("[BREACH-REMEDIATE] Failed to log event:", e.message);
                }
                
                // Return special response telling user to retry
                return res.status(200).json({
                  success: false,
                  error: "BanRemediated",
                  errorCode: 1099,
                  errorMessage: "Your account has been restored. Please restart the app to log in."
                });
              }
            }
          }
        }
        // ============================================================
        // END TEMPORARY BREACH REMEDIATION
        // ============================================================

        // Only issue Meta device ban if not already banned
        if (attestation.unique_id && masterPlayFabId && !attestation.device_ban?.is_banned) {
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
        error: "AuthenticationFailed",
        errorMessage: playfabData.errorMessage || "Unable to authenticate. Please try again."
      });
    }

    const masterPlayFabId = playfabData.data.PlayFabId;

    // === SECURITY BLOB (load once, save once at end) ===
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

    // === ENFORCEMENT ===
    if (ENFORCEMENT_CONFIG.enabled) {
      let _isDev;
      const checkIsDev = async () => {
        if (_isDev === undefined) {
          _isDev = await isDeveloper(masterPlayFabId, titleId, secretKey);
        }
        return _isDev;
      };

      // Handle missing attestation token
      if (!attestationToken) {
        const noTokenAction = getEnforcementAction("no_token");
        if (noTokenAction !== "allow") {
          if (await checkIsDev()) {
            console.log(`[DEV BYPASS] Allowing missing attestation token for developer: ${metaId}`);
          } else {
            console.warn(`[ATTESTATION BLOCKED] No token | MetaId:${metaId} | Action:${noTokenAction}`);
            return res.status(403).json({
              success: false,
              error: "AuthenticationFailed",
              errorMessage: "Unable to authenticate. Please try again."
            });
          }
        }
      }

      // Handle verification failures (Meta API couldn't verify)
      if (attestation.reason === "verification_failed" && !(await checkIsDev())) {
        const verifyAction = getEnforcementAction("verification_failed");
        if (verifyAction !== "allow") {
          console.warn(`[ATTESTATION BLOCKED] Verification failed | MetaId:${metaId} | Action:${verifyAction}`);
          return res.status(403).json({
            success: false,
            error: "AuthenticationFailed",
            errorMessage: "Unable to authenticate. Please try again."
          });
        }
      }

      // Handle attestation failures with tiered enforcement
      if (!attestation.valid && attestation.reason !== "verification_failed" && !(await checkIsDev())) {
        const action = getEnforcementAction(attestation.reason);

        if (action !== "allow") {
          console.warn(`[ATTESTATION ${action.toUpperCase()}] PlayFabId:${masterPlayFabId} | MetaId:${metaId} | App:${attestation.app_integrity} | Device:${attestation.device_integrity} | Reasons:${attestation.reason} | Action:${action}`);

          const blob = await ensureBlob();

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

            // Meta permanent hardware ban (only if not already banned)
            if (attestation.unique_id && !attestation.device_ban?.is_banned) {
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
          if (blob) {
            const now = new Date().toISOString();
            const di = blob.di || (blob.di = {});
            di.lastEnforce = now;
            di.lastAction = action;
            blob.lua = now;
            securityDirty = true;
          } else {
            console.error(`[SECURITY BLOB] Failed to load — cannot record lastEnforce. PlayFabId:${masterPlayFabId}`);
          }

          // Save blob before returning
          if (securityDirty && securityBlob) {
            try {
              await saveSecurityBlob(titleId, secretKey, masterPlayFabId, securityBlob);
            } catch (e) {
              console.error("[SECURITY BLOB SAVE FAILED]", e);
            }
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
              error: "AuthenticationFailed",
              errorMessage: "Unable to authenticate. Please try again."
            });
          }
        }
      }
    }

    // === FORENSIC LOGGING ===
    // Uses consolidated analysis from attestation.analysis (no duplicate calculations)
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

        // Use pre-computed reason mask from analysis (no duplicate calculation)
        di.rm = di.rm | (attestation.analysis?.reasonMask || 0);

        if (attestation.unique_id) di.uid = attestation.unique_id;
        if (attestation.cert_check?.clientHash) di.ch = attestation.cert_check.clientHash;
        if (attestation.cert_check?.reason === "cert_mismatch") {
          di.cmc = (di.cmc || 0) + 1;
          if (!di.fcm) di.fcm = now;
        }

        blob.lua = now;
        securityDirty = true;

        // Event logging
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
                rm: attestation.analysis?.reasonMask || 0,
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

    // Log verification failures in Security blob
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
      try {
        await saveSecurityBlob(titleId, secretKey, masterPlayFabId, securityBlob);
      } catch (e) {
        console.error("[SECURITY BLOB SAVE FAILED]", e);
      }
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