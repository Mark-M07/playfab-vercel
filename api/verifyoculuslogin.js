// api/verifyoculuslogin.js
import fetch from 'node-fetch';
import querystring from 'node:querystring';
import crypto from 'crypto';
import { lookup as dnsLookupCb } from 'node:dns';
import https from 'node:https';

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

// === VERSION GATE ===
// Minimum allowed bundleVersionCode (integer from Meta attestation payload).
// Set via env var. 0 or empty = disabled. When you ship a new build and want
// to cut off old versions, update this to the oldest versionCode you still allow.
// The value comes from Meta's signed attestation claims (app_state.version),
// so it cannot be spoofed by the client.
const MINIMUM_VERSION_CODE = parseInt(process.env.MINIMUM_VERSION_CODE || "0", 10) || 0;

// === ENFORCEMENT CONFIGURATION ===
// Action types: "allow" | "block" | "ban"
//   - allow: Let login proceed (monitoring only)
//   - block: Reject this login attempt but don't ban
//   - ban:   Reject login AND issue permanent PlayFab + Meta device ban
const ENFORCEMENT_CONFIG = {
  enabled: true, // Master switch - set to true to enable enforcement
  
  // Device integrity failures
  device_NotTrusted: "block",   // Block login, prompt factory reset
  device_Basic: "block",        // Block login, prompt factory reset
  
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

  // Game version too old (Meta-attested versionCode below minimum)
  version_outdated: "block",    // Block login, prompt update — never ban (could be legit stale install)
};

// ============================================================================
// SECURITY: SECURE PLAYFAB RESOLVER
// DNS-over-HTTPS resolution with IP range validation and connection pinning.
//
// Architecture:
//   1. Resolve PlayFab hostname via DoH (Cloudflare / Google) — immune to
//      local DNS poisoning since queries travel over HTTPS.
//   2. Validate every resolved IP against known PlayFab CIDR ranges — defence
//      in depth even against a compromised DoH provider.
//   3. Pin outbound PlayFab connections to validated IPs via a custom
//      https.Agent — Node's own DNS resolver is never used for PlayFab.
//
// ============================================================================

// --- PlayFab IP allowlist (CIDR notation, matching PlayFab's published list) ---
// Source: PlayFab dashboard → Settings → Static IP prefixes and addresses
// To update: edit this array and redeploy.
const PLAYFAB_CIDRS = [
  '20.120.128.144/28', '20.120.129.32/28', '20.120.129.96/28',
  '20.120.129.160/28', '20.120.129.240/28', '20.120.130.208/28',
  '20.120.131.0/28',   '20.120.131.240/28', '20.120.132.32/28',
  '20.120.132.208/28', '20.120.133.64/28',  '20.120.133.112/28',
  '20.252.116.240/28', '20.252.117.240/28', '20.252.118.0/28',
  '20.252.118.48/28',  '20.252.118.64/28',  '20.252.118.208/28',
  '20.252.119.16/28',  '20.252.119.176/28', '20.252.119.192/28',
  '20.252.119.240/28', '20.252.119.48/28',  '20.252.119.96/28',
  '20.42.182.0/23',
  '20.51.84.128/28',   '20.51.84.160/28',   '20.51.84.176/28',
  '20.51.84.240/28',   '20.51.85.32/28',    '20.51.85.64/28',
  '20.51.85.128/28',   '20.51.85.176/28',
  '20.72.226.112/28',  '20.72.226.160/28',
  '20.9.200.0/25',     '20.9.200.128/25',
  '48.210.5.64/26',    '48.210.5.128/26',   '48.210.6.0/23',
  '52.250.84.16/28',   '52.250.87.96/28',   '52.250.87.160/28',
  '52.250.87.192/28',
  '57.154.81.226/31',
  '34.213.208.16/32',  '34.216.170.167/32', '52.13.201.178/32',
];

// --- CIDR parsing and IP validation ---

function ipToNumber(ip) {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function parseCidr(cidr) {
  const trimmed = cidr.trim();
  // Support bare IPs (no /prefix) — treat as /32
  const slashIdx = trimmed.indexOf('/');
  const ip     = slashIdx >= 0 ? trimmed.slice(0, slashIdx) : trimmed;
  const prefix = slashIdx >= 0 ? parseInt(trimmed.slice(slashIdx + 1), 10) : 32;
  const ipNum  = ipToNumber(ip);
  const mask   = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return { cidr: trimmed, start: (ipNum & mask) >>> 0, end: ((ipNum & mask) | ~mask) >>> 0 };
}

// Parse CIDRs once at module load (warm instances reuse this)
const PLAYFAB_IP_RANGES = PLAYFAB_CIDRS.map(parseCidr);

// Startup log — printed once per cold start so you can confirm the ranges in Vercel logs
console.log(`[RESOLVER INIT] PlayFab IP allowlist loaded: ${PLAYFAB_IP_RANGES.length} CIDR ranges covering ${PLAYFAB_CIDRS.join(', ')}`);

function isValidPlayFabIP(ip) {
  const ipNum = ipToNumber(ip);
  for (const range of PLAYFAB_IP_RANGES) {
    if (ipNum >= range.start && ipNum <= range.end) return true;
  }
  return false;
}

// --- DoH providers (tried in order; both use standard DNS-over-HTTPS JSON) ---
const DOH_PROVIDERS = [
  { name: 'cloudflare', url: 'https://1.1.1.1/dns-query' },
  { name: 'google',     url: 'https://8.8.8.8/resolve'   },
];

// --- Resolver tuning ---
const RESOLVER_CONFIG = {
  dohTimeoutMs:    3_000,    // Per-provider DoH query timeout
  cacheFreshMs:    120_000,  // Consider cache "fresh" for 2 min (skip re-resolve)
  cacheStaleMs:    600_000,  // Accept stale cache for up to 10 min (emergency fallback)
};

// --- Slack alerting ---
const SLACK_SECURITY_WEBHOOK = process.env.SLACK_SECURITY_WEBHOOK_URL || '';
const SLACK_ALERT_COOLDOWN_MS = 60_000; // Min 60s between Slack messages of same type
let _slackLastSent = {};                // { eventType: timestamp }

async function sendSlackAlert(eventType, message, details = {}) {
  if (!SLACK_SECURITY_WEBHOOK) return;

  // Rate-limit per event type to prevent flooding during active attacks
  const now = Date.now();
  if (_slackLastSent[eventType] && (now - _slackLastSent[eventType]) < SLACK_ALERT_COOLDOWN_MS) return;
  _slackLastSent[eventType] = now;

  const blocks = [
    {
      type: 'section',
      text: { type: 'mrkdwn', text: message },
    },
  ];

  // Add detail fields if provided
  const fields = Object.entries(details)
    .filter(([, v]) => v !== undefined && v !== null)
    .map(([k, v]) => ({ type: 'mrkdwn', text: `*${k}:*\n${v}` }));
  if (fields.length > 0) {
    blocks.push({ type: 'section', fields: fields.slice(0, 10) }); // Slack max 10 fields
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5_000);
    await fetch(SLACK_SECURITY_WEBHOOK, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ blocks }),
      signal: controller.signal,
    });
    clearTimeout(timeout);
  } catch {
    // Slack delivery is best-effort — never block the login flow
  }
}

// --- Module-level state (persists across warm Vercel invocations) ---
const resolver = {
  ips:              [],     // Validated PlayFab IPs from DoH
  lastResolved:     0,      // Timestamp of last successful DoH resolution
  resolving:        false,  // Concurrency guard
};

// --- DNS-over-HTTPS resolution ---

async function resolveViaDoH(hostname) {
  for (const provider of DOH_PROVIDERS) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), RESOLVER_CONFIG.dohTimeoutMs);
      const resp = await fetch(`${provider.url}?name=${encodeURIComponent(hostname)}&type=A`, {
        headers: { Accept: 'application/dns-json' },
        signal: controller.signal,
      });
      clearTimeout(timeout);
      if (!resp.ok) continue;

      const data = await resp.json();
      const ips = (data.Answer || []).filter(a => a.type === 1).map(a => a.data);
      if (ips.length > 0) return { ips, provider: provider.name };
    } catch {
      // Provider unreachable — try next
    }
  }
  return { ips: [], provider: null };
}

// --- Resolver cache management ---

async function refreshResolverCache(titleId) {
  if (resolver.resolving) return; // Another concurrent invocation is already refreshing
  resolver.resolving = true;
  try {
    const hostname = `${titleId}.playfabapi.com`;
    const { ips, provider } = await resolveViaDoH(hostname);

    if (ips.length === 0) {
      console.warn('[RESOLVER] DoH returned no IPs from any provider — retaining existing cache');
      sendSlackAlert('doh_failure', ':warning: *DoH Resolution Failed*\nBoth Cloudflare (1.1.1.1) and Google (8.8.8.8) DoH returned no IPs. Using cached IPs for now.', {
        'Cached IPs': resolver.ips.length > 0 ? resolver.ips.join(', ') : 'NONE — logins will fail!',
        'Cache Age': resolver.lastResolved ? `${Math.round((Date.now() - resolver.lastResolved) / 1000)}s (usable up to ${Math.round(RESOLVER_CONFIG.cacheStaleMs / 1000)}s)` : 'never resolved',
        'Action Required': resolver.ips.length > 0
          ? 'Monitor only — cached IPs will sustain logins for up to 10 minutes. If this persists, check Vercel region connectivity and consider redeploying to a different region.'
          : 'URGENT — No cached IPs available. Player logins are failing. Check Vercel network status and redeploy immediately.',
      }).catch(() => {});
      return;
    }

    const validIps   = ips.filter(ip => isValidPlayFabIP(ip));
    const invalidIps = ips.filter(ip => !isValidPlayFabIP(ip));

    if (invalidIps.length > 0) {
      // Even DoH is returning unexpected IPs — extremely unlikely but handle it
      console.error(`[RESOLVER ALERT] DoH via ${provider} returned IPs outside PlayFab ranges: ${invalidIps.join(', ')} — DISCARDING, retaining cache`);
      sendSlackAlert('doh_invalid_ips', ':rotating_light: *DoH Returned Invalid PlayFab IPs*\nDoH resolved PlayFab to IPs outside the known CIDR ranges. Discarded — using cached IPs.', {
        Provider: provider,
        'Invalid IPs': invalidIps.join(', '),
        'Valid IPs': validIps.join(', ') || 'none',
        'Action Required': 'Check if PlayFab has published new IP ranges (Dashboard → Settings → Static IP prefixes). If so, update PLAYFAB_CIDRS in verifyoculuslogin.js and redeploy. If PlayFab ranges haven\'t changed, this may indicate a sophisticated DNS supply-chain attack — escalate immediately.',
      }).catch(() => {});
      return;
    }

    if (validIps.length > 0) {
      const wasEmpty = resolver.ips.length === 0;
      resolver.ips = validIps;
      resolver.lastResolved = Date.now();
      if (wasEmpty) {
        // First resolution (cold start) — log for operational confidence
        console.log(`[RESOLVER READY] DoH via ${provider} resolved PlayFab to ${validIps.length} IPs: ${validIps.join(', ')} | All validated against ${PLAYFAB_IP_RANGES.length} CIDR ranges`);
      }
    }
  } finally {
    resolver.resolving = false;
  }
}

function isCacheFresh() {
  return resolver.ips.length > 0 && (Date.now() - resolver.lastResolved) < RESOLVER_CONFIG.cacheFreshMs;
}

function isCacheUsable() {
  return resolver.ips.length > 0 && (Date.now() - resolver.lastResolved) < RESOLVER_CONFIG.cacheStaleMs;
}

// --- Pinned https.Agent (routes PlayFab connections through DoH-resolved IPs) ---

let _pinnedAgent = null;
let _pinnedTitleId = null;

function getPinnedAgent(titleId) {
  if (_pinnedAgent && _pinnedTitleId === titleId) return _pinnedAgent;

  const pfHost = `${titleId}.playfabapi.com`;
  _pinnedAgent = new https.Agent({
    keepAlive: true,
    maxSockets: 50,
    lookup: (hostname, options, callback) => {
      // Only pin PlayFab — everything else falls through to system DNS
      if (hostname === pfHost && resolver.ips.length > 0) {
        const ip = resolver.ips[Math.floor(Math.random() * resolver.ips.length)];
        return callback(null, ip, 4);
      }
      dnsLookupCb(hostname, options, callback);
    },
  });
  _pinnedTitleId = titleId;
  return _pinnedAgent;
}

// --- Public API: secure PlayFab fetch ---

// Set by handler on each invocation — used by pfFetch and getPinnedAgent
let _activeTitleId = null;

/**
 * Drop-in replacement for `fetch()` when calling PlayFab APIs.
 * Routes the connection through DoH-resolved, IP-validated endpoints
 * so that local DNS poisoning has zero effect on outbound traffic.
 *
 * Usage: replace `fetch(\`https://${titleId}.playfabapi.com/...\`, opts)`
 *   with `pfFetch(\`https://${titleId}.playfabapi.com/...\`, opts)`
 * No other changes needed — the titleId is read from module state.
 */
function pfFetch(url, options = {}) {
  return fetch(url, { ...options, agent: getPinnedAgent(_activeTitleId) });
}

/**
 * Call at the start of every handler invocation.
 * Ensures the DoH resolver cache is populated so pfFetch can pin connections
 * to validated PlayFab IPs.
 */
async function ensureResolver(titleId) {
  // Refresh DoH cache if stale
  if (!isCacheFresh()) {
    await refreshResolverCache(titleId);
  }

  // If cache is completely empty after refresh (first cold-start with no DoH
  // connectivity at all), we cannot safely route to PlayFab. Return false
  // so the handler can 503 gracefully — but this is a genuine connectivity
  // problem, not an attacker-triggerable condition.
  if (!isCacheUsable()) {
    console.error('[RESOLVER] No usable PlayFab IPs — DoH unreachable and no cached IPs. Genuine connectivity issue.');
    sendSlackAlert('resolver_down', ':x: *URGENT — Resolver Down, Player Logins Failing*\nCannot resolve PlayFab IPs via DoH and no cached IPs available. Players are seeing "Unable to connect" errors.', {
      'DoH Providers Tried': DOH_PROVIDERS.map(p => `${p.name} (${p.url})`).join(', '),
      'Cache Status': 'Empty — no fallback IPs available',
      'Player Impact': 'ALL logins failing with 503',
      'Action Required': '1) Check https://www.vercel-status.com for platform issues.\n2) Check https://status.playfab.com for PlayFab outages.\n3) Try redeploying to force a fresh cold start — this re-attempts DoH resolution.\n4) If DoH is blocked in the Vercel region, consider adding a third DoH provider or hardcoding fallback IPs temporarily.',
    }).catch(() => {});
    return false;
  }

  return true;
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
  VERSION_OUTDATED:    1 << 9,  // 512
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
  let resp;
  try {
    resp = await pfFetch(`https://${titleId}.playfabapi.com/Server/GetUserInternalData`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
      body: JSON.stringify({ PlayFabId: playFabId, Keys: ["Security"] })
    });
  } catch (e) {
    console.error(`[LOAD SECURITY] Network error for PlayFabId:${playFabId}: ${e.code || e.message}`);
    return null;
  }

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
    const resp = await pfFetch(`https://${titleId}.playfabapi.com/Server/UpdateUserInternalData`, {
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

// === DEVICE BAN REGISTRY ===
// Stores all UniqueId → account info mappings in a single Title Internal Data key
// Used to link alt accounts to the original banned account

const DEVICE_BAN_REGISTRY_KEY = "DeviceBanRegistry";

/**
 * Load the device ban registry from Title Internal Data
 * Returns an object mapping UniqueId → { playFabId, metaId }, or empty object if not found
 */
async function loadDeviceBanRegistry(titleId, secretKey) {
  try {
    const resp = await pfFetch(`https://${titleId}.playfabapi.com/Admin/GetTitleInternalData`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
      body: JSON.stringify({ Keys: [DEVICE_BAN_REGISTRY_KEY] })
    });
    
    if (!resp.ok) {
      console.warn(`[DEVICE BAN REGISTRY] Load failed: ${resp.status}`);
      return {};
    }
    
    const data = await resp.json().catch(() => null);
    const value = data?.data?.Data?.[DEVICE_BAN_REGISTRY_KEY];
    
    if (!value) return {};
    
    return JSON.parse(value);
  } catch (e) {
    console.warn(`[DEVICE BAN REGISTRY] Load exception:`, e.message);
    return {};
  }
}

/**
 * Save the device ban registry to Title Internal Data
 */
async function saveDeviceBanRegistry(titleId, secretKey, registry) {
  try {
    const resp = await pfFetch(`https://${titleId}.playfabapi.com/Admin/SetTitleInternalData`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
      body: JSON.stringify({ 
        Key: DEVICE_BAN_REGISTRY_KEY, 
        Value: JSON.stringify(registry) 
      })
    });
    
    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      console.error(`[DEVICE BAN REGISTRY] Save failed: ${resp.status} ${text.slice(0, 200)}`);
      return false;
    }
    return true;
  } catch (e) {
    console.error(`[DEVICE BAN REGISTRY] Save exception:`, e.message);
    return false;
  }
}

/**
 * Register a device ban in the registry for cross-account tracking
 */
async function registerDeviceBan(titleId, secretKey, uniqueId, playFabId, metaId, reason) {
  if (!uniqueId) return;
  
  const registry = await loadDeviceBanRegistry(titleId, secretKey);
  
  // Add or update entry
  registry[uniqueId] = {
    playFabId,
    metaId,
    reason
  };
  
  const saved = await saveDeviceBanRegistry(titleId, secretKey, registry);
  if (saved) {
    console.log(`[DEVICE BAN REGISTRY] Stored UniqueId:${uniqueId.slice(0, 16)}... → PlayFabId:${playFabId}`);
  }
}

/**
 * Look up original banned account by device UniqueId
 * Returns { playFabId, metaId } or null if not found
 */
async function lookupDeviceBan(titleId, secretKey, uniqueId) {
  if (!uniqueId) return null;
  
  const registry = await loadDeviceBanRegistry(titleId, secretKey);
  return registry[uniqueId] || null;
}

/**
 * Create a linked Security blob on an alt account by copying from the original banned account
 * Adds linkedAlt marker so admin knows this is a copy
 */
async function createLinkedBanBlob(titleId, secretKey, altPlayFabId, originalPlayFabId) {
  // Load the original account's Security blob
  const originalBlob = await loadSecurityBlob(titleId, secretKey, originalPlayFabId);
  
  if (!originalBlob) {
    console.warn(`[DEVICE BAN REGISTRY] Could not load original blob from PlayFabId:${originalPlayFabId}`);
    return false;
  }
  
  const now = new Date().toISOString();
  
  // Copy the blob and add alt account markers
  const altBlob = JSON.parse(JSON.stringify(originalBlob)); // Deep copy
  
  if (!altBlob.di) altBlob.di = {};
  altBlob.di.linkedAlt = true;
  altBlob.di.linkedTo = originalPlayFabId;
  altBlob.di.linkedAt = now;
  altBlob.lua = now;
  
  try {
    await saveSecurityBlob(titleId, secretKey, altPlayFabId, altBlob);
    console.log(`[DEVICE BAN REGISTRY] Copied blob to alt PlayFabId:${altPlayFabId} ← original:${originalPlayFabId}`);
    return true;
  } catch (e) {
    console.error(`[DEVICE BAN REGISTRY] Failed to create linked blob:`, e.message);
    return false;
  }
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
    const resp = await pfFetch(`https://${titleId}.playfabapi.com/Server/GetPlayFabIDsFromGenericIDs`, {
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
    const resp = await pfFetch(`https://${titleId}.playfabapi.com/Server/GetUserInternalData`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
      body: JSON.stringify({ PlayFabId: playFabId, Keys: ["IsDeveloper"] })
    });
    if (resp.ok) {
      const data = await readJson(resp, "IS DEVELOPER");
      if (!data) return false;
      return data.data?.Data?.IsDeveloper?.Value === "true";
    }
    console.error(`[isDeveloper] HTTP ${resp.status} for PlayFabId:${playFabId}`);
  } catch (e) {
    console.error(`[isDeveloper] Network error for PlayFabId:${playFabId}: ${e.code || e.message}`);
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

  // Make titleId available to pfFetch (module-level, safe in single-threaded Node)
  _activeTitleId = titleId;

  // ============================================================================
  // SECURITY: Initialise DoH-pinned resolver
  // Populates the IP cache via DNS-over-HTTPS (Cloudflare / Google) so that
  // all outbound PlayFab calls are routed to validated IPs. System DNS is
  // never used for PlayFab — local DNS poisoning has no effect.
  //
  // The only scenario where this returns 503 is a genuine connectivity
  // failure where DoH itself is unreachable AND no cached IPs exist —
  // an attacker cannot trigger this condition by poisoning DNS alone.
  // ============================================================================
  const resolverReady = await ensureResolver(titleId);
  if (!resolverReady) {
    return res.status(503).json({
      success: false,
      error: "Service temporarily unavailable",
      errorMessage: "Unable to connect. Please try again."
    });
  }
  // ============================================================================

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
          
          // Get PlayFab ID (needed for ban reason lookup)
          const playFabId = await getPlayFabIdFromCustomId(metaId, titleId, secretKey);

          // Check Security blob status and handle registry backfill / alt account detection
          if (playFabId && attestation.unique_id) {
            const existingBlob = await loadSecurityBlob(titleId, secretKey, playFabId);
            const hasBanEvidence = existingBlob?.mb?.r;
            
            if (hasBanEvidence) {
              // This account has ban evidence - it's the original banned account (or already linked)
              // Check if we need to backfill the registry
              const existingRegistry = await lookupDeviceBan(titleId, secretKey, attestation.unique_id);
              
              if (!existingRegistry) {
                // Backfill: add this account to the registry
                console.log(`[DEVICE BAN REGISTRY] Backfilling from existing ban: PlayFabId:${playFabId} Reason:${existingBlob.mb.r}`);
                await registerDeviceBan(
                  titleId, 
                  secretKey, 
                  attestation.unique_id, 
                  playFabId, 
                  metaId,
                  existingBlob.mb.r
                );
              }
            } else {
              // No ban evidence on this account - check if this is an alt account
              const originalBan = await lookupDeviceBan(titleId, secretKey, attestation.unique_id);
              
              if (originalBan) {
                // Found the original banned account - copy their Security blob to this alt
                console.log(`[DEVICE BAN REGISTRY] Alt account detected: MetaId:${metaId} PlayFabId:${playFabId} | Original: PlayFabId:${originalBan.playFabId}`);
                await createLinkedBanBlob(titleId, secretKey, playFabId, originalBan.playFabId);
              } else {
                // Not in registry - could be legacy ban or rotated UniqueId
                console.log(`[DEVICE BAN REGISTRY] No registry entry for UniqueId:${attestation.unique_id.slice(0, 16)}... | MetaId:${metaId} (legacy ban or rotated ID)`);
              }
            }
          }
          
          // Look up actual ban reason from PlayFab
          let banReason = "Device ban"; // Default for device-banned users with no PlayFab account
          if (playFabId) {
            try {
              const getBansResp = await pfFetch(`https://${titleId}.playfabapi.com/Server/GetUserBans`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
                body: JSON.stringify({ PlayFabId: playFabId })
              });
              
              if (getBansResp.ok) {
                const bansData = await getBansResp.json();
                const activeBan = bansData?.data?.BanData?.find(b => b.Active);
                if (activeBan?.Reason) {
                  banReason = activeBan.Reason;
                }
              }
            } catch (e) {
              console.warn("[GET BAN REASON] Failed to fetch from PlayFab:", e.message);
            }
          }

          const remainingDays = parseInt(attestation.device_ban.remaining_ban_time, 10) || 0;

          return res.status(403).json({
            success: false,
            error: "AccountBanned",
            errorCode: 1002,
            errorMessage: "Account is banned.",
            banInfo: { reason: banReason, expiry: (remainingDays >= 3650) ? "Indefinite" : attestation.device_ban.remaining_ban_time }
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
    const playfabLoginBody = JSON.stringify({
      CustomId: metaId,
      CreateAccount: true,
      InfoRequestParameters: {
        GetUserAccountInfo: true,
        GetPlayerProfile: true,
        GetUserData: true,
        GetEntityToken: true,
        ProfileConstraints: { ShowDisplayName: true }
      }
    });

    let playfabResp;
    let playfabData;
    const maxLoginRetries = 2;
    for (let attempt = 1; attempt <= maxLoginRetries; attempt++) {
      try {
        playfabResp = await pfFetch(`https://${titleId}.playfabapi.com/Server/LoginWithCustomID`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
          body: playfabLoginBody
        });
        break; // success — exit retry loop
      } catch (e) {
        console.error(`[PLAYFAB LOGIN] Network error (attempt ${attempt}/${maxLoginRetries}): ${e.code || e.message} | MetaId:${metaId}`);
        if (attempt < maxLoginRetries) {
          await new Promise(r => setTimeout(r, 500));
        } else {
          return res.status(503).json({
            success: false,
            error: "Service temporarily unavailable",
            errorMessage: "Unable to connect. Please try again."
          });
        }
      }
    }

    playfabData = await readJson(playfabResp, "PLAYFAB LOGIN");
    if (!playfabData) {
      return res.status(503).json({ success: false, error: "Service temporarily unavailable" });
    }

    if (!playfabResp.ok) {
      if (playfabData.errorCode === 1002) {
        // LoginWithCustomID claims user is banned.
        // MITM DEFENSE: Cross-verify with independent GetUserBans call before
        // issuing any irreversible Meta device ban. Attacker has previously
        // injected fake 1002 responses to weaponise our own ban cascade.
        const banInfo = extractBanInfo(playfabData);
        const masterPlayFabId = await getPlayFabIdFromCustomId(metaId, titleId, secretKey);

        // === CROSS-VERIFY: Confirm ban is real ===
        let confirmedBan = false;
        let verifiedReason = banInfo.reason;
        let verifiedExpiry = banInfo.expiry;

        if (masterPlayFabId) {
          try {
            const confirmResp = await pfFetch(`https://${titleId}.playfabapi.com/Server/GetUserBans`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'X-SecretKey': secretKey },
              body: JSON.stringify({ PlayFabId: masterPlayFabId })
            });

            if (confirmResp.ok) {
              const bansData = await confirmResp.json();
              const activeBan = bansData?.data?.BanData?.find(b => b.Active);
              if (activeBan) {
                confirmedBan = true;
                verifiedReason = activeBan.Reason || banInfo.reason;
                verifiedExpiry = activeBan.Expires || banInfo.expiry;
              }
            }
          } catch (e) {
            console.error(`[BAN VERIFY] GetUserBans failed for MetaId:${metaId} — ${e.message}`);
          }
        }

        if (!confirmedBan) {
          // LoginWithCustomID said banned, but GetUserBans disagrees — MITM detected
          console.error(`[MITM DEFENSE] Fake ban intercepted! MetaId:${metaId} | PlayFabId:${masterPlayFabId || 'unresolved'} | FakeReason:${banInfo.reason} | FakeExpiry:${banInfo.expiry}`);
          sendSlackAlert('mitm_fake_ban', ':rotating_light: *MITM Payload Injection — Fake Ban Intercepted*\nPlayFab LoginWithCustomID returned a ban response, but the independent GetUserBans cross-check confirms the player is NOT banned. The fake ban was blocked — the player will retry automatically.', {
            MetaId: metaId,
            PlayFabId: masterPlayFabId || 'unresolved',
            'Injected Reason': banInfo.reason,
            'Injected Expiry': banInfo.expiry,
            'Action Required': 'Both PlayFab calls route through DoH-pinned IPs, so this interception should not be possible under normal conditions. If this alert fires repeatedly, the attacker may be operating at the BGP/routing level rather than DNS. Monitor for repeated occurrences — if more than 5 players are affected within a few minutes, redeploy Vercel to force fresh connections and escalate to Vercel support.',
          }).catch(() => {});
          // Return 503 so client retries (next attempt routes through clean path)
          return res.status(503).json({
            success: false,
            error: "Service temporarily unavailable",
            errorMessage: "Unable to connect. Please try again."
          });
        }

        // Ban confirmed real — proceed with Meta device ban
        console.warn(`[BANNED USER LOGIN] MetaId:${metaId} | Reason:${verifiedReason} | Expiry:${verifiedExpiry} | Verified:true`);

        if (attestation.unique_id && masterPlayFabId && !attestation.device_ban?.is_banned) {
          const metaBan = await banDeviceAndRecord(attestation.unique_id, oculusAccessToken, banInfo.durationMinutes, {
            titleId,
            secretKey,
            playFabId: masterPlayFabId,
            banReason: `PlayFab ban: ${verifiedReason}`,
            metaId
          });
          // Register in device ban registry for cross-account lookups
          if (metaBan.success) {
            await registerDeviceBan(titleId, secretKey, attestation.unique_id, masterPlayFabId, metaId, `PlayFab ban: ${verifiedReason}`);
          }
        } else if (!masterPlayFabId) {
          console.error(`[CRITICAL] Failed to resolve MasterPlayFabId for banned MetaId:${metaId} — Meta ban NOT stored!`);
        }

        return res.status(403).json({
          success: false,
          error: "AccountBanned",
          errorCode: 1002,
          errorMessage: "Account is banned.",
          banInfo: { reason: verifiedReason, expiry: verifiedExpiry }
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
            console.warn(`[ATTESTATION BLOCKED] No token | PlayFabId:${masterPlayFabId} | MetaId:${metaId} | Action:${noTokenAction}`);

            // Record no-token attempt in security blob
            try {
              const blob = await ensureBlob();
              if (blob) {
                const now = new Date().toISOString();
                const di = blob.di || (blob.di = {});
                di.ntc = (di.ntc || 0) + 1;          // no-token count
                if (!di.ntf) di.ntf = now;           // first no-token time
                di.ntl = now;                        // last no-token time
                blob.lua = now;
                securityDirty = true;
              }
            } catch (e) {
              console.error(`[ATTESTATION BLOCKED] Failed to update security blob for PlayFabId:${masterPlayFabId}: ${e.message}`);
            }

            // Save blob before returning
            if (securityDirty && securityBlob) {
              try {
                await saveSecurityBlob(titleId, secretKey, masterPlayFabId, securityBlob);
              } catch (e) {
                console.error("[SECURITY BLOB SAVE FAILED]", e);
              }
            }

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

      // === VERSION GATE ===
      // Uses Meta-attested versionCode from the signed payload — cannot be spoofed.
      // Only applies when we have a valid attestation payload (payload != null)
      // and MINIMUM_VERSION_CODE is configured.
      if (MINIMUM_VERSION_CODE > 0 && payload?.app_state?.version) {
        const clientVersionCode = parseInt(payload.app_state.version, 10) || 0;

        if (clientVersionCode < MINIMUM_VERSION_CODE) {
          const versionAction = getEnforcementAction("version_outdated");
          if (versionAction !== "allow") {
            if (await checkIsDev()) {
              console.log(`[DEV BYPASS] Allowing outdated version for developer: ${metaId} | VersionCode:${clientVersionCode} | Min:${MINIMUM_VERSION_CODE}`);
            } else {
              console.warn(`[VERSION BLOCKED] PlayFabId:${masterPlayFabId} | MetaId:${metaId} | VersionCode:${clientVersionCode} | Min:${MINIMUM_VERSION_CODE} | App:${attestation.app_integrity} | Device:${attestation.device_integrity} | Action:${versionAction}`);

              // Record version-block attempt in security blob
              try {
                const blob = await ensureBlob();
                if (blob) {
                  const now = new Date().toISOString();
                  const di = blob.di || (blob.di = {});
                  di.vbc = (di.vbc || 0) + 1;          // version-block count
                  if (!di.vbf) di.vbf = now;           // first version-block time
                  di.vbl = now;                        // last version-block time
                  di.vbv = clientVersionCode;          // last blocked versionCode
                  blob.lua = now;
                  securityDirty = true;
                }
              } catch (e) {
                console.error(`[VERSION BLOCKED] Failed to update security blob for PlayFabId:${masterPlayFabId}: ${e.message}`);
              }

              // Save blob before returning
              if (securityDirty && securityBlob) {
                try {
                  await saveSecurityBlob(titleId, secretKey, masterPlayFabId, securityBlob);
                } catch (e) {
                  console.error("[SECURITY BLOB SAVE FAILED]", e);
                }
              }

              return res.status(403).json({
                success: false,
                error: "AuthenticationFailed",
                errorMessage: "Unable to authenticate. Please try again."
              });
            }
          }
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
              await pfFetch(`https://${titleId}.playfabapi.com/Server/BanUsers`, {
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
              if (metaBan.success && metaBan.recorded) {
                securityDirty = true;
                // Register in device ban registry for cross-account lookups
                await registerDeviceBan(titleId, secretKey, attestation.unique_id, masterPlayFabId, metaId, `Attestation: ${attestation.reason}`);
              }
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
            // Provide helpful message for device integrity issues
            const isDeviceIntegrityOnly = attestation.reason && 
              (attestation.reason === "device_NotTrusted" || 
               attestation.reason === "device_Basic" ||
               attestation.reason === "device_NotTrusted|device_Basic" ||
               attestation.reason === "device_Basic|device_NotTrusted");
            
            const errorMessage = isDeviceIntegrityOnly
              ? "Security check failed.\nA factory reset of your device is recommended."
              : "Unable to authenticate. Please try again.";
            
            return res.status(403).json({
              success: false,
              error: "AuthenticationFailed",
              errorMessage
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
        await pfFetch(`https://${titleId}.playfabapi.com/Server/AddGenericID`, {
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