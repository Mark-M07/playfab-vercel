import crypto from "crypto";
import fetch from "node-fetch";
import { ensurePlayerByOculusId } from "../lib/supabase/players.js";
import {
  parseMetaEventTime,
  recordOrderStatus,
} from "../lib/supabase/iap-order-status.js";
import { isSupabaseConfigured } from "../lib/supabase/client.js";

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
 *    (jk, right now we are skipping calls to playfab on this user so I can test orphaned-user calls to Supabase)
 *
 * Optional env vars:
 *   SUPABASE_URL                 - Supabase project URL
 *   SUPABASE_SERVICE_ROLE_KEY    - service role key (server only, never in client APK)
 *   OCULUS_APP_SECRET            - used to validate against the signed SHA256 Meta sends in their payload's X-Hub-Signature-256 header
 *                                - see -> https://developers.facebook.com/docs/graph-api/webhooks/getting-started#validate-requests
 *   META_WEBHOOK_SKIP_SIGNATURE  - set to "1" to log signature mismatches but still accept events (testing only)
 *
 * Vercel log filter tips:
 *    Search "[META_WEBHOOK]" for all webhook traffic
 *    Search "[META_WEBHOOK][order_status]" for purchase/refund events only
 *    Search "[META_WEBHOOK][verification]" for Meta dashboard setup / re-verification GETs
 *    Search "[META_WEBHOOK][playfab-lookup]" for successful Meta ID → PlayFab resolution
 *    Search "[META_WEBHOOK][orphan-purchaser]" for valid Meta ID, PlayFab OK, no linked account (pre-login store purchase)
 *    Search "[META_WEBHOOK][supabase-players]" for ug.players registry get/insert on orphan flow
 *    Search "[META_WEBHOOK][supabase-iap-order-status]" for ug.iap_order_status insert on orphan flow
 *    Search "[META_WEBHOOK][orphan-test]" for forced orphan QA path (skips PlayFab)
 *    Search "[META_WEBHOOK][lookup-invalid-meta-id]" for bad webhook user_id (e.g. "0")
 *    Search "[META_WEBHOOK][lookup-playfab-error]" for PlayFab API errors (non-transient)
 *    Search "[META_WEBHOOK][lookup-transient]" for retryable PlayFab failures (5xx/429)
 *    Search "[META_WEBHOOK][dashboard-test]" for Meta dashboard test payload overrides
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
/** TEMP: Skip PlayFab lookup and run orphan + Supabase path*/
const FORCED_ORPHAN_TEST_META_IDS = new Set([
  META_DASHBOARD_TEST_META_ID,
  META_DASHBOARD_TEST_TARGET_META_ID,
]);
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

function isForcedOrphanTestUser(metaId) {
  return FORCED_ORPHAN_TEST_META_IDS.has(String(metaId));
}

function buildForcedOrphanTestBuyer(metaId) {
  return {
    metaId: String(metaId),
    playFabId: null,
    accountExists: false,
    outcome: "pre_login_purchaser",
    logTag: "orphan-purchaser",
    detail: "Forced orphan test — PlayFab lookup skipped",
    lookupError: null,
    profile: null,
    httpStatus: null,
    playFabErrorCode: null,
    skippedApiCall: true,
    forcedOrphanTest: true,
  };
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

  log(
    "info",
    "live-write-test",
    "Whitelisted Meta ID — will write PlayerOrderStatusData",
    {
      metaId: event.userId,
      sku: event.sku,
      reportingId: event.reportingId,
    },
  );

  return { ...event, isLiveWriteTest: true };
}

/** PlayFab lookup failed with HTTP 429/5xx — retry may succeed on Meta webhook redelivery. */
const TRANSIENT_HTTP_STATUSES = new Set([429, 500, 502, 503, 504]);

function isValidMetaUserId(metaId) {
  const s = String(metaId ?? "").trim();
  if (!s || s === "0") return false;
  // Meta Quest app-scoped user IDs are numeric strings (typically ~10–17 digits).
  return /^\d{5,20}$/.test(s);
}

function describeInvalidMetaUserId(metaId) {
  const s = String(metaId ?? "").trim();
  if (!s) return "user_id is empty";
  if (s === "0") {
    return 'user_id is "0" (Meta placeholder — not a real profile; cannot map to PlayFab)';
  }
  if (!/^\d+$/.test(s)) return "user_id is not numeric";
  if (s.length < 5) return "user_id is too short for a Meta app-scoped ID";
  if (s.length > 20) return "user_id is too long for a Meta app-scoped ID";
  return "user_id failed validation";
}

function classifyPlayFabLookup(metaId, lookup) {
  if (!isValidMetaUserId(metaId)) {
    return {
      outcome: "invalid_meta_id",
      logTag: "lookup-invalid-meta-id",
      message: describeInvalidMetaUserId(metaId),
    };
  }

  if (!lookup.apiOk) {
    const msg = lookup.errorMessage || "lookup_failed";
    if (TRANSIENT_HTTP_STATUSES.has(lookup.httpStatus)) {
      return {
        outcome: "transient_error",
        logTag: "lookup-transient",
        message: `PlayFab transient error (HTTP ${lookup.httpStatus}): ${msg}`,
      };
    }
    const lower = msg.toLowerCase();
    if (lower.includes("invalid input")) {
      return {
        outcome: "invalid_meta_id",
        logTag: "lookup-invalid-meta-id",
        message: `PlayFab rejected user_id lookup: ${msg}`,
      };
    }
    return {
      outcome: "playfab_api_error",
      logTag: "lookup-playfab-error",
      message: `PlayFab API error (HTTP ${lookup.httpStatus ?? "?"}): ${msg}`,
    };
  }

  if (!lookup.playFabId) {
    return {
      outcome: "pre_login_purchaser",
      logTag: "orphan-purchaser",
      message:
        "PlayFab OK — CustomId not linked (buyer purchased before first login / account auto-create)",
    };
  }

  return {
    outcome: "success",
    logTag: "playfab-lookup",
    message: "PlayFab account resolved",
  };
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
  if (!isValidMetaUserId(metaId)) {
    return {
      playFabId: null,
      apiOk: false,
      httpStatus: null,
      errorMessage: describeInvalidMetaUserId(metaId),
      errorCode: null,
      skippedApiCall: true,
    };
  }

  const { ok, status, data } = await playFabApi(
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
      apiOk: false,
      httpStatus: status,
      errorMessage: data?.errorMessage || data?.error || "lookup_failed",
      errorCode: data?.errorCode ?? null,
      skippedApiCall: false,
    };
  }

  const playFabId = data?.data?.Data?.[0]?.PlayFabId ?? null;
  return {
    playFabId,
    apiOk: true,
    httpStatus: status,
    errorMessage: playFabId ? null : "no_playfab_account",
    errorCode: null,
    skippedApiCall: false,
  };
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
  const classification = classifyPlayFabLookup(metaId, lookup);

  const base = {
    metaId: String(metaId),
    playFabId: lookup.playFabId,
    outcome: classification.outcome,
    logTag: classification.logTag,
    detail: classification.message,
    httpStatus: lookup.httpStatus,
    playFabErrorCode: lookup.errorCode,
    skippedApiCall: lookup.skippedApiCall ?? false,
  };

  if (!lookup.playFabId) {
    return {
      ...base,
      accountExists: false,
      lookupError: lookup.errorMessage,
      profile: null,
    };
  }

  const profile = await getPlayerProfileSummary(
    lookup.playFabId,
    titleId,
    secretKey,
  );

  return {
    ...base,
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

function logUnresolvedLookup(event, buyer, writeEnabled) {
  if (!buyer) {
    log("error", "lookup-playfab-error", "Lookup result missing", {
      metaId: event.userId,
      sku: event.sku,
      reportingId: event.reportingId,
    });
    return;
  }

  const level =
    buyer.outcome === "transient_error"
      ? "warn"
      : buyer.outcome === "pre_login_purchaser"
        ? "info"
        : "error";

  const payload = {
    outcome: buyer.outcome,
    metaId: event.userId,
    sku: event.sku,
    reportingId: event.reportingId,
    httpStatus: buyer.httpStatus,
    playFabErrorCode: buyer.playFabErrorCode,
    lookupError: buyer.lookupError,
    skippedApiCall: buyer.skippedApiCall,
    entry: buildOrderStatusEntry(event),
    writesBlocked: !writeEnabled,
  };

  if (buyer.outcome === "pre_login_purchaser") {
    log(
      level,
      "orphan-purchaser",
      "Pre-login purchaser — no PlayFab CustomId yet; Supabase ug.players + ug.iap_order_status steps run next",
      payload,
    );
    return;
  }

  log(level, buyer.logTag, buyer.detail, payload);
}

async function recordOrphanOrderStatusInSupabase(event, player) {
  if (!isSupabaseConfigured()) {
    log(
      "warn",
      "supabase-iap-order-status",
      "Supabase env not configured - skipping ug.iap_order_status",
      {
        metaId: event.userId,
        reportingId: event.reportingId,
        sku: event.sku,
        supabasePlayerId: player.id,
      },
    );
    return null;
  }

  try {
    const result = await recordOrderStatus({
      reportingId: event.reportingId,
      sku: event.sku,
      oculusId: event.userId,
      playerId: player.id,
      notificationType: event.notificationType,
      purchasedAt: parseMetaEventTime(event.eventTime),
    });

    if (!result.ok || !result.orderStatus) {
      log(
        "error",
        "supabase-iap-order-status",
        "Failed to record order in ug.iap_order_status",
        {
          metaId: event.userId,
          reportingId: event.reportingId,
          sku: event.sku,
          supabasePlayerId: player.id,
          error: result.error,
          code: result.code,
          action: result.action,
        },
      );
      return null;
    }

    const message =
      result.action === "skip_duplicate"
        ? "Order already recorded in ug.iap_order_status"
        : result.created
          ? "Inserted new row in ug.iap_order_status"
          : "Recorded order in ug.iap_order_status";

    log("info", "supabase-iap-order-status", message, {
      metaId: event.userId,
      reportingId: event.reportingId,
      sku: event.sku,
      supabasePlayerId: player.id,
      supabaseOrderStatusId: result.orderStatus.id,
      notificationType: event.notificationType,
      purchasedAt: result.orderStatus.purchased_at,
      created: result.created,
      action: result.action,
    });

    return result.orderStatus;
  } catch (err) {
    log(
      "error",
      "supabase-iap-order-status",
      "Unexpected error recording ug.iap_order_status row",
      {
        metaId: event.userId,
        reportingId: event.reportingId,
        sku: event.sku,
        supabasePlayerId: player.id,
        error: err.message,
      },
    );
    return null;
  }
}

async function ensureOrphanPlayerInSupabase(event) {
  if (!isSupabaseConfigured()) {
    log(
      "warn",
      "supabase-players",
      "Supabase env not configured - skipping ug.players",
      {
        metaId: event.userId,
        reportingId: event.reportingId,
        sku: event.sku,
      },
    );
    return null;
  }

  try {
    const result = await ensurePlayerByOculusId(event.userId);

    if (!result.ok || !result.player) {
      log(
        "error",
        "supabase-players",
        "Failed to ensure player in ug.players",
        {
          metaId: event.userId,
          reportingId: event.reportingId,
          sku: event.sku,
          error: result.error,
          code: result.code,
        },
      );
      return null;
    }

    log(
      "info",
      "supabase-players",
      result.created
        ? "Inserted new row in ug.players"
        : "Player already exists in ug.players",
      {
        metaId: event.userId,
        supabasePlayerId: result.player.id,
        created: result.created,
        reportingId: event.reportingId,
        sku: event.sku,
      },
    );

    await recordOrphanOrderStatusInSupabase(event, result.player);

    return result.player;
  } catch (err) {
    log(
      "error",
      "supabase-players",
      "Unexpected error ensuring ug.players row",
      {
        metaId: event.userId,
        reportingId: event.reportingId,
        error: err.message,
      },
    );
    return null;
  }
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

async function writePlayerOrderStatusData(
  playFabId,
  value,
  titleId,
  secretKey,
) {
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

  if (!isValidMetaUserId(event.userId)) {
    log(
      "error",
      "lookup-invalid-meta-id",
      describeInvalidMetaUserId(event.userId),
      {
        metaId: event.userId,
        sku: event.sku,
        reportingId: event.reportingId,
        appId: event.appId,
      },
    );
    return;
  }

  const titleId = process.env.PLAYFAB_TITLE_ID;
  const secretKey = process.env.PLAYFAB_DEV_SECRET_KEY;
  const writeEnabled = shouldWriteOrderStatus();

  if (isForcedOrphanTestUser(event.userId)) {
    log(
      "info",
      "orphan-test",
      "Forcing pre-login orphan path — skipping PlayFab lookup",
      {
        metaId: event.userId,
        sku: event.sku,
        reportingId: event.reportingId,
      },
    );
    await ensureOrphanPlayerInSupabase(event);
    logUnresolvedLookup(
      event,
      buildForcedOrphanTestBuyer(event.userId),
      writeEnabled,
    );
    return;
  }

  let buyer = null;
  if (titleId && secretKey && event.userId) {
    try {
      buyer = await lookupBuyerPlayFabProfile(event.userId, titleId, secretKey);
      if (buyer.playFabId) {
        log("info", "playfab-lookup", "Buyer profile lookup succeeded", buyer);
      }
    } catch (err) {
      log("error", "lookup-playfab-error", "Buyer profile lookup threw", {
        metaId: event.userId,
        sku: event.sku,
        reportingId: event.reportingId,
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
    if (buyer?.outcome === "pre_login_purchaser") {
      await ensureOrphanPlayerInSupabase(event);
    }
    logUnresolvedLookup(event, buyer, writeEnabled);
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
        log(
          "info",
          "order-status-write",
          "PlayerOrderStatusData write succeeded",
          {
            playFabId: buyer.playFabId,
            displayName: buyer.profile?.displayName ?? null,
            key: PLAYER_ORDER_STATUS_DATA_KEY,
            mergedValue: merged,
          },
        );
      } else {
        log(
          "error",
          "order-status-write",
          "PlayerOrderStatusData write failed",
          {
            playFabId: buyer.playFabId,
            error: writeResult.error,
            mergedValue: merged,
          },
        );
      }
    } catch (err) {
      log(
        "error",
        "order-status-write",
        "PlayerOrderStatusData write exception",
        {
          playFabId: buyer.playFabId,
          error: err.message,
        },
      );
    }
  } else if (writeEnabled && action === "skip_duplicate") {
    log(
      "info",
      "order-status-write",
      "Write skipped — duplicate reporting_id",
      {
        playFabId: buyer.playFabId,
        reportingId: entry.reporting_id,
      },
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
