import crypto from "crypto";
import fetch from "node-fetch";

/**
 * Meta webhook receiver for IAP order_status event.
 *    See -> https://developers.meta.com/horizon/documentation/unity/ps-webhooks-getting-started/ for more info.
 *
 * Required env vars:
 *    META_WEBHOOK_VERIFY_TOKEN   - must match the "Verify token" field on the dashboard-created webhook
 *                                - see -> https://developers.meta.com/horizon/manage/applications/8485526434899813/platform-services/webhooks/
 *
 * Phase 2 (registry) env vars:
 *    PLAYFAB_TITLE_ID            - required for buyer PlayFab lookup + writes
 *    PLAYFAB_DEV_SECRET_KEY      - required for buyer PlayFab lookup + writes
 *    META_IAP_REGISTRY_WRITE     - set to "1" to write to PlayFab, otherwise, it's a dry-run
 *
 * Optional env vars:
 *   OCULUS_APP_SECRET            - used to validate against the signed SHA256 Meta sends in their payload's X-Hub-Signature-256 header
 *                                - see -> https://developers.facebook.com/docs/graph-api/webhooks/getting-started#validate-requests
 *   META_WEBHOOK_SKIP_SIGNATURE  - set to "1" to log signature mismatches but still accept events (testing only)
 *
 * Vercel log filter tips:
 *    Search "[META_WEBHOOK]" for all webhook traffic
 *    Search "[META_WEBHOOK][order_status]" for purchase/refund events only
 *    Search "[META_WEBHOOK][verification]" for Meta dashboard setup / re-verification GETs
 *    Search "[META_WEBHOOK][playfab-lookup]" for Meta ID → PlayFab profile resolution
 *    Search "[META_WEBHOOK][registry-dry-run]" for Title Internal Data upserts that would occur
 *
 * @route GET|POST /api/webhookmetaorder
 */
export const config = {
  api: {
    bodyParser: false,
  },
};

const LOG_PREFIX = "[META_WEBHOOK]";
const REGISTRY_TITLE_INTERNAL_KEY = "MetaIapPurchaseRegistry";

/** Plain fetch to PlayFab — no DoH pinning (see rotatetoken.js). */
async function playFabApi(path, titleId, secretKey, body) {
  const resp = await fetch(`https://${titleId}.playfabapi.com${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-SecretKey": secretKey,
    },
    body: JSON.stringify(body),
  });
  const data = await resp.json().catch(() => null);
  return { ok: resp.ok, status: resp.status, data };
}

async function getPlayFabIdFromMetaId(metaId, titleId, secretKey) {
  const { ok, data } = await playFabApi(
    "/Server/GetPlayFabIDsFromGenericIDs",
    titleId,
    secretKey,
    {
      GenericIDs: [{ ServiceName: "CustomId", UserId: String(metaId) }],
    },
  );

  if (!ok) {
    return {
      playFabId: null,
      error: data?.errorMessage || data?.error || "lookup_failed",
    };
  }

  const playFabId = data?.data?.Data?.[0]?.PlayFabId ?? null;
  return { playFabId, error: playFabId ? null : "no_playfab_account" };
}

async function getPlayerProfileSummary(playFabId, titleId, secretKey) {
  const { ok, data } = await playFabApi(
    "/Server/GetPlayerProfile",
    titleId,
    secretKey,
    {
      PlayFabId: playFabId,
      ProfileConstraints: {
        ShowDisplayName: true,
        ShowCreated: true,
        ShowLastLogin: true,
      },
    },
  );

  if (!ok) {
    return {
      error: data?.errorMessage || data?.error || "profile_fetch_failed",
    };
  }

  const profile = data?.data?.PlayerProfile;
  return {
    displayName: profile?.DisplayName ?? null,
    created: profile?.Created ?? null,
    lastLogin: profile?.LastLogin ?? null,
  };
}

async function lookupBuyerPlayFabProfile(metaId, titleId, secretKey) {
  const lookup = await getPlayFabIdFromMetaId(metaId, titleId, secretKey);

  if (!lookup.playFabId) {
    return {
      metaId: String(metaId),
      playFabId: null,
      accountExists: false,
      lookupError: lookup.error,
      profile: null,
    };
  }

  const profile = await getPlayerProfileSummary(
    lookup.playFabId,
    titleId,
    secretKey,
  );

  return {
    metaId: String(metaId),
    playFabId: lookup.playFabId,
    accountExists: true,
    lookupError: profile.error ?? null,
    profile: profile.error
      ? null
      : {
          displayName: profile.displayName,
          created: profile.created,
          lastLogin: profile.lastLogin,
        },
  };
}

function normalizeDeveloperPayload(value) {
  if (value == null || value === "" || value === '""') return null;
  return value;
}

function buildRegistryEntry(event, ownerPlayFabId) {
  const status = event.notificationType || "UNKNOWN";
  return {
    ownerMetaId: event.userId ? String(event.userId) : null,
    ownerPlayFabId: ownerPlayFabId ?? null,
    sku: event.sku ?? null,
    purchasedAt: event.eventTime ? Number(event.eventTime) : null,
    status,
    notificationType: event.notificationType ?? null,
    developerPayload: normalizeDeveloperPayload(event.developerPayload),
    webhookReceivedAt: new Date().toISOString(),
    grantedToPlayFabId: null,
    grantedAt: null,
  };
}

async function processRegistryDryRun(event) {
  if (!event.reportingId) {
    log("warn", "registry-dry-run", "Skipping — event has no reportingId", {
      sku: event.sku,
      userId: event.userId,
    });
    return;
  }

  const titleId = process.env.PLAYFAB_TITLE_ID;
  const secretKey = process.env.PLAYFAB_DEV_SECRET_KEY;
  const writeEnabled = process.env.META_IAP_REGISTRY_WRITE === "1";

  let buyer = null;
  if (titleId && secretKey && event.userId) {
    try {
      buyer = await lookupBuyerPlayFabProfile(event.userId, titleId, secretKey);
      log("info", "playfab-lookup", "Buyer profile lookup", buyer);
    } catch (err) {
      log("error", "playfab-lookup", "Buyer profile lookup failed", {
        metaId: event.userId,
        error: err.message,
      });
    }
  } else if (event.userId) {
    log(
      "warn",
      "playfab-lookup",
      "Skipping lookup — PLAYFAB_TITLE_ID or PLAYFAB_DEV_SECRET_KEY not configured",
    );
  }

  const registryEntry = buildRegistryEntry(event, buyer?.playFabId ?? null);

  // Title Internal Data is title-wide (not per-player UserData). Keyed by reporting_id inside the blob.
  const wouldWrite = {
    dryRun: !writeEnabled,
    writeTarget: "TitleInternalData",
    api: "Admin/SetTitleInternalData",
    key: REGISTRY_TITLE_INTERNAL_KEY,
    upsert: {
      [event.reportingId]: registryEntry,
    },
  };

  log(
    "info",
    "registry-dry-run",
    "Would upsert IAP ownership registry entry",
    wouldWrite,
  );

  if (writeEnabled) {
    log(
      "warn",
      "registry-dry-run",
      "META_IAP_REGISTRY_WRITE=1 but persist is not implemented yet — no PlayFab write performed",
    );
  }
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

/** Avoid req.query — Vercel/Node may parse via deprecated url.parse(). */
function parseQueryParams(req) {
  const host = req.headers.host || "localhost";
  const url = new URL(req.url || "/", `https://${host}`);
  return url.searchParams;
}

function log(level, tag, message, details = undefined) {
  const prefix = tag ? `${LOG_PREFIX}[${tag}]` : LOG_PREFIX;
  const payload =
    details === undefined ? message : `${message} ${JSON.stringify(details)}`;
  if (level === "error") {
    console.error(`${prefix} ${payload}`);
  } else if (level === "warn") {
    console.warn(`${prefix} ${payload}`);
  } else {
    console.log(`${prefix} ${payload}`);
  }
}

function timingSafeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
  } catch {
    return false;
  }
}

function validateSignature(rawBodyBuffer, signatureHeader, appSecret) {
  if (!signatureHeader || !appSecret) {
    return { checked: false, valid: true, reason: "not_configured" };
  }

  const expectedHex = crypto
    .createHmac("sha256", appSecret)
    .update(rawBodyBuffer)
    .digest("hex");

  const receivedHex = signatureHeader.startsWith("sha256=")
    ? signatureHeader.slice(7)
    : signatureHeader;

  const valid = timingSafeEqualHex(expectedHex, receivedHex);
  return { checked: true, valid, reason: valid ? "ok" : "mismatch" };
}

function extractOrderStatusEvents(payload) {
  if (
    !payload ||
    payload.object !== "application" ||
    !Array.isArray(payload.entry)
  ) {
    return [];
  }

  const events = [];
  for (const entry of payload.entry) {
    const changes = Array.isArray(entry.changes) ? entry.changes : [];
    for (const change of changes) {
      if (change?.field !== "order_status") continue;

      const value = change.value || {};
      const productInfo = value.product_info || {};

      events.push({
        appId: entry.id,
        webhookTime: entry.time,
        eventTime: value.event_time,
        userId: value.user_id,
        notificationType: productInfo.notification_type,
        reportingId: productInfo.reporting_id,
        sku: productInfo.sku,
        developerPayload: productInfo.developer_payload,
        rawValue: value,
      });
    }
  }

  return events;
}

function summarizePayload(payload) {
  const fields = [];
  if (payload?.entry) {
    for (const entry of payload.entry) {
      for (const change of entry.changes || []) {
        if (change?.field) fields.push(change.field);
      }
    }
  }

  return {
    object: payload?.object ?? null,
    entryCount: Array.isArray(payload?.entry) ? payload.entry.length : 0,
    fields: [...new Set(fields)],
  };
}

async function handleVerification(req, res) {
  const verifyToken = process.env.META_WEBHOOK_VERIFY_TOKEN;
  const params = parseQueryParams(req);
  const mode = params.get("hub.mode");
  const challenge = params.get("hub.challenge");
  const token = params.get("hub.verify_token");

  log("info", "verification", "Incoming verification request", {
    mode,
    hasChallenge: Boolean(challenge),
    tokenMatches: Boolean(verifyToken && token === verifyToken),
  });

  if (!verifyToken) {
    log("error", "verification", "META_WEBHOOK_VERIFY_TOKEN is not configured");
    return res.status(500).send("Server misconfigured");
  }

  if (mode === "subscribe" && token === verifyToken && challenge) {
    log(
      "info",
      "verification",
      "Verification succeeded — echoing hub.challenge",
    );
    res.setHeader("Content-Type", "text/plain");
    return res.status(200).send(String(challenge));
  }

  log(
    "warn",
    "verification",
    "Verification failed — mode/token/challenge mismatch",
  );
  return res.status(403).send("Forbidden");
}

async function handleEventNotification(req, res) {
  const appSecret =
    process.env.OCULUS_APP_SECRET || process.env.META_APP_SECRET;
  const skipSignature = process.env.META_WEBHOOK_SKIP_SIGNATURE === "1";

  let rawBodyBuffer;
  try {
    rawBodyBuffer = await readRawBody(req);
  } catch (err) {
    log("error", "event", "Failed to read request body", {
      error: err.message,
    });
    return res.status(400).json({ success: false, error: "Invalid body" });
  }

  const signatureHeader = req.headers["x-hub-signature-256"];
  const signature = validateSignature(
    rawBodyBuffer,
    signatureHeader,
    appSecret,
  );

  if (signature.checked && !signature.valid) {
    log("warn", "event", "Signature mismatch", {
      skipSignature,
      hasAppSecret: Boolean(appSecret),
      bodyByteLength: rawBodyBuffer.length,
      receivedPrefix: String(signatureHeader || "").slice(0, 20),
    });
    if (!skipSignature) {
      return res
        .status(401)
        .json({ success: false, error: "Invalid signature" });
    }
  } else if (!signature.checked) {
    log(
      "warn",
      "event",
      "Signature not validated (missing app secret or header)",
    );
  }

  const rawBodyText = rawBodyBuffer.length
    ? rawBodyBuffer.toString("utf8")
    : "";
  let payload;
  try {
    payload = rawBodyText ? JSON.parse(rawBodyText) : null;
  } catch (err) {
    log("error", "event", "Body is not valid JSON", {
      error: err.message,
      preview: rawBodyText.slice(0, 400),
    });
    return res.status(400).json({ success: false, error: "Invalid JSON" });
  }

  const summary = summarizePayload(payload);
  log("info", "event", "Webhook POST received", summary);

  const orderEvents = extractOrderStatusEvents(payload);

  if (orderEvents.length === 0) {
    log(
      "info",
      "event",
      "No order_status changes in payload — logging full body for inspection",
      {
        payload,
      },
    );
  } else {
    for (const event of orderEvents) {
      log("info", "order_status", "Order event received", event);
      try {
        await processRegistryDryRun(event);
      } catch (err) {
        log(
          "error",
          "registry-dry-run",
          "Unexpected error during dry-run processing",
          {
            reportingId: event.reportingId,
            error: err.message,
          },
        );
      }
    }
  }

  // Meta expects a 200 response; otherwise it retries for up to 36 hours.
  return res.status(200).json({
    success: true,
    receivedAt: new Date().toISOString(),
    fields: summary.fields,
    orderStatusEventCount: orderEvents.length,
  });
}

export default async function handler(req, res) {
  if (req.method === "GET") {
    return handleVerification(req, res);
  }

  if (req.method === "POST") {
    return handleEventNotification(req, res);
  }

  log("warn", "event", `Unsupported method: ${req.method}`);
  return res.status(405).json({ success: false, error: "Method Not Allowed" });
}
