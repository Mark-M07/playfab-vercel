import crypto from "crypto";
import fetch from "node-fetch";

/**
 * Meta webhook receiver for IAP order_status event.
 *    See -> https://developers.meta.com/horizon/documentation/unity/ps-webhooks-getting-started/ for more info.
 *
 * Required env vars:
 *    META_WEBHOOK_VERIFY_TOKEN   - must match the "Verify token" field on the dashboard-created webhook
 *                                - see -> https://developers.meta.com/horizon/manage/applications/8485526434899813/platform-services/webhooks/
 *    META_WEBHOOK_BLOCK_WRITES   - set to "1" to block PlayFab writes but keep Vercel logging
 *    PLAYFAB_TITLE_ID            - required for buyer PlayFab lookup + writes
 *    PLAYFAB_DEV_SECRET_KEY      - required for buyer PlayFab lookup + writes
 *
 * Live writes are ON by default for all PURCHASED durable events (consumable Nugs SKUs excluded).
 *
 * Live write test whitelist (logging only — same write path as all players):
 *    28914815224829230 (Conehead91), 9062660193814011 (Ogethel)
 *
 * Meta dashboard test mode (no env var required):
 *    user_id 10149999707612630 → 28914815224829230 (Conehead91), item_sku_1 → random durable bundle SKU,
 *    always writes PlayerOrderStatusData to the target account for testing purposes
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
 *    Search "[META_WEBHOOK][dashboard-test]" for Meta dashboard test payload overrides
 *    Search "[META_WEBHOOK][live-write-test]" for whitelisted Meta IDs with live writes
 *    Search "[META_WEBHOOK][order-status-dry-run]" for would-write logs when META_WEBHOOK_BLOCK_WRITES != 1
 *    Search "[META_WEBHOOK][order-status-write]" for live Read Only Data writes
 *
 * @route GET|POST /api/webhookmetaorder
 */
export const config = {
  api: {
    bodyParser: false,
  },
};

const LOG_PREFIX = "[META_WEBHOOK]";
/** Read Only User Data key — separate from client-managed PlayerBundleData. */
const PLAYER_ORDER_STATUS_DATA_KEY = "PlayerOrderStatusData";
/** Consumable currency SKUs — durable ownership tracking not needed. */
const IGNORED_CONSUMABLE_SKUS = new Set([
  "Nugs_1000",
  "Nugs_2200",
  "Nugs_5000",
  "Nugs_11000",
]);
/** Meta dashboard "Send to My Server" sends this fake Meta ID — map to a real test account. */
const META_DASHBOARD_TEST_META_ID = "10149999707612630";
const META_DASHBOARD_TEST_TARGET_META_ID = "28914815224829230";
const META_DASHBOARD_TEST_SKU = "item_sku_1";
const DASHBOARD_TEST_DURABLE_SKUS = [
  "Bundle_HammerHug",
  "Bundle_WaveRider",
  "Bundle_XvP",
  "Bundle_Xenodon",
  "Bundle_Prugator",
];
/** Real Meta IDs that always write PlayerOrderStatusData (pre–full rollout testing). */
const LIVE_WRITE_TEST_META_IDS = new Set([
  "28914815224829230",
  "9062660193814011",
]);

function isIgnoredConsumableSku(sku) {
  return Boolean(sku && IGNORED_CONSUMABLE_SKUS.has(sku));
}

function isMetaDashboardTestUser(metaId) {
  return String(metaId) === META_DASHBOARD_TEST_META_ID;
}

function isLiveWriteTestUser(metaId) {
  return LIVE_WRITE_TEST_META_IDS.has(String(metaId));
}

function shouldWriteOrderStatus() {
  return process.env.META_WEBHOOK_BLOCK_WRITES !== "1";
}

function orderStatusLogTag(writeEnabled) {
  return writeEnabled ? "order-status-write" : "order-status-dry-run";
}

function pickRandomDashboardTestSku() {
  return DASHBOARD_TEST_DURABLE_SKUS[
    crypto.randomInt(0, DASHBOARD_TEST_DURABLE_SKUS.length)
  ];
}

/** Rewrite Meta dashboard test payloads to hit a real PlayFab account with varied durable SKUs. */
function applyDashboardTestOverrides(event) {
  if (!isMetaDashboardTestUser(event.userId)) {
    return event;
  }

  const original = {
    userId: event.userId,
    sku: event.sku,
    reportingId: event.reportingId,
  };

  const translated = {
    ...event,
    userId: META_DASHBOARD_TEST_TARGET_META_ID,
    isDashboardTest: true,
  };

  if (translated.sku === META_DASHBOARD_TEST_SKU) {
    translated.sku = pickRandomDashboardTestSku();
  }

  // Dashboard test reuses the same reporting_id every send — synthesize one per click.
  translated.reportingId = crypto.randomUUID();

  log("info", "dashboard-test", "Applied Meta dashboard test overrides", {
    original,
    translated: {
      userId: translated.userId,
      sku: translated.sku,
      reportingId: translated.reportingId,
    },
  });

  return translated;
}

function logLiveWriteTestUser(event) {
  if (!isLiveWriteTestUser(event.userId) || event.isDashboardTest) {
    return event;
  }

  log("info", "live-write-test", "Whitelisted Meta ID — will write PlayerOrderStatusData", {
    metaId: event.userId,
    sku: event.sku,
    reportingId: event.reportingId,
  });

  return { ...event, isLiveWriteTest: true };
}

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

async function getPlayerOrderStatusData(playFabId, titleId, secretKey) {
  const { ok, data } = await playFabApi(
    "/Server/GetUserReadOnlyData",
    titleId,
    secretKey,
    {
      PlayFabId: playFabId,
      Keys: [PLAYER_ORDER_STATUS_DATA_KEY],
    },
  );

  if (!ok) {
    return {
      error: data?.errorMessage || data?.error || "read_failed",
      value: null,
    };
  }

  const raw = data?.data?.Data?.[PLAYER_ORDER_STATUS_DATA_KEY]?.Value;
  if (!raw) {
    return { error: null, value: { order_statuses: [] } };
  }

  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed?.order_statuses)) {
      return { error: "invalid_shape", value: { order_statuses: [] }, raw };
    }
    return { error: null, value: parsed };
  } catch {
    return { error: "invalid_json", value: { order_statuses: [] }, raw };
  }
}

function buildOrderStatusEntry(event) {
  return {
    sku: event.sku ?? null,
    reporting_id: event.reportingId ?? null,
  };
}

function mergeOrderStatusData(current, entry) {
  const orderStatuses = [...(current?.order_statuses ?? [])];
  const duplicate = orderStatuses.some(
    (row) => row.reporting_id === entry.reporting_id,
  );

  if (duplicate) {
    return { merged: current, action: "skip_duplicate" };
  }

  orderStatuses.push(entry);
  return {
    merged: { order_statuses: orderStatuses },
    action: "append",
  };
}

async function writePlayerOrderStatusData(playFabId, value, titleId, secretKey) {
  const { ok, data } = await playFabApi(
    "/Server/UpdateUserReadOnlyData",
    titleId,
    secretKey,
    {
      PlayFabId: playFabId,
      Data: {
        [PLAYER_ORDER_STATUS_DATA_KEY]: JSON.stringify(value),
      },
    },
  );

  return {
    ok,
    error: ok ? null : data?.errorMessage || data?.error || "write_failed",
    data,
  };
}

async function processOrderStatusEvent(event) {
  if (isIgnoredConsumableSku(event.sku)) {
    log(
      "info",
      "order-status-dry-run",
      "Skipping consumable SKU — not tracked",
      {
        sku: event.sku,
        reportingId: event.reportingId,
      },
    );
    return;
  }

  if (!event.reportingId || !event.sku) {
    log(
      "warn",
      "order-status-dry-run",
      "Skipping — missing reportingId or sku",
      {
        reportingId: event.reportingId,
        sku: event.sku,
      },
    );
    return;
  }

  if (event.notificationType !== "PURCHASED") {
    log(
      "info",
      "order-status-dry-run",
      "Skipping — only PURCHASED handled for now",
      {
        notificationType: event.notificationType,
        reportingId: event.reportingId,
      },
    );
    return;
  }

  const titleId = process.env.PLAYFAB_TITLE_ID;
  const secretKey = process.env.PLAYFAB_DEV_SECRET_KEY;
  const writeEnabled = shouldWriteOrderStatus();

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
      return;
    }
  } else if (event.userId) {
    log(
      "warn",
      "playfab-lookup",
      "Skipping — PLAYFAB_TITLE_ID or PLAYFAB_DEV_SECRET_KEY not configured",
    );
    return;
  }

  if (!buyer?.playFabId) {
    log(
      "info",
      orderStatusLogTag(writeEnabled),
      writeEnabled
        ? "Deferred — no PlayFab account yet (will not write until buyer logs in)"
        : "Would write after first login — no PlayFab account yet",
      {
        metaId: event.userId,
        reportingId: event.reportingId,
        sku: event.sku,
        entry: buildOrderStatusEntry(event),
      },
    );
    return;
  }

  let currentRead = { value: { order_statuses: [] } };
  try {
    currentRead = await getPlayerOrderStatusData(
      buyer.playFabId,
      titleId,
      secretKey,
    );
    if (
      currentRead.error &&
      currentRead.error !== "invalid_shape" &&
      currentRead.error !== "invalid_json"
    ) {
      log(
        "error",
        "order-status-dry-run",
        "Failed to read existing Read Only Data",
        {
          playFabId: buyer.playFabId,
          error: currentRead.error,
        },
      );
      return;
    }
    if (
      currentRead.error === "invalid_shape" ||
      currentRead.error === "invalid_json"
    ) {
      log(
        "warn",
        "order-status-dry-run",
        "Existing key has unexpected shape — would reset list on write",
        {
          playFabId: buyer.playFabId,
          raw: currentRead.raw,
        },
      );
    }
  } catch (err) {
    log(
      "error",
      "order-status-dry-run",
      "Read existing PlayerOrderStatusData failed",
      {
        playFabId: buyer.playFabId,
        error: err.message,
      },
    );
    return;
  }

  const entry = buildOrderStatusEntry(event);
  const { merged, action } = mergeOrderStatusData(currentRead.value, entry);

  const wouldWrite = {
    dryRun: !writeEnabled,
    writeTarget: "UserReadOnlyData",
    api: "Server/UpdateUserReadOnlyData",
    playFabId: buyer.playFabId,
    displayName: buyer.profile?.displayName ?? null,
    key: PLAYER_ORDER_STATUS_DATA_KEY,
    action,
    currentValue: currentRead.value,
    mergedValue: merged,
    newEntry: entry,
  };

  log(
    "info",
    orderStatusLogTag(writeEnabled),
    writeEnabled
      ? "Updating player IAP order statuses"
      : "Would update player IAP order statuses",
    wouldWrite,
  );

  if (writeEnabled && action === "append") {
    try {
      const writeResult = await writePlayerOrderStatusData(
        buyer.playFabId,
        merged,
        titleId,
        secretKey,
      );

      if (writeResult.ok) {
        log("info", "order-status-write", "PlayerOrderStatusData write succeeded", {
          playFabId: buyer.playFabId,
          displayName: buyer.profile?.displayName ?? null,
          key: PLAYER_ORDER_STATUS_DATA_KEY,
          mergedValue: merged,
        });
      } else {
        log("error", "order-status-write", "PlayerOrderStatusData write failed", {
          playFabId: buyer.playFabId,
          error: writeResult.error,
          mergedValue: merged,
        });
      }
    } catch (err) {
      log("error", "order-status-write", "PlayerOrderStatusData write exception", {
        playFabId: buyer.playFabId,
        error: err.message,
      });
    }
  } else if (writeEnabled && action === "skip_duplicate") {
    log("info", "order-status-write", "Write skipped — duplicate reporting_id", {
      playFabId: buyer.playFabId,
      reportingId: entry.reporting_id,
    });
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
    for (const rawEvent of orderEvents) {
      log("info", "order_status", "Order event received", rawEvent);
      const event = logLiveWriteTestUser(applyDashboardTestOverrides(rawEvent));
      try {
        await processOrderStatusEvent(event);
      } catch (err) {
        log(
          "error",
          "order-status-dry-run",
          "Unexpected error during order status processing",
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
