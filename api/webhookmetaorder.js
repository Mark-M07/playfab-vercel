import crypto from "crypto";

/**
 * Meta webhook receiver for IAP order_status event.
 *    See -> https://developers.meta.com/horizon/documentation/unity/ps-webhooks-getting-started/ for more info.
 *
 * Required env vars:
 *    META_WEBHOOK_VERIFY_TOKEN   - must match the "Verify token" field on the dashboard-created webhook
 *                                - see -> https://developers.meta.com/horizon/manage/applications/8485526434899813/platform-services/webhooks/
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
 *
 * @route GET|POST /api/webhookmetaorder
 */

export const config = {
  api: {
    bodyParser: false,
  },
};

const LOG_PREFIX = "[META_WEBHOOK]";

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
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

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const aBuf = Buffer.from(a, "utf8");
  const bBuf = Buffer.from(b, "utf8");
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function validateSignature(rawBody, signatureHeader, appSecret) {
  if (!signatureHeader || !appSecret) {
    return { checked: false, valid: true, reason: "not_configured" };
  }

  const expected = `sha256=${crypto
    .createHmac("sha256", appSecret)
    .update(rawBody, "utf8")
    .digest("hex")}`;

  const valid = timingSafeEqual(expected, signatureHeader);
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
  const mode = req.query["hub.mode"];
  const challenge = req.query["hub.challenge"];
  const token = req.query["hub.verify_token"];

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

  let rawBody = "";
  try {
    rawBody = await readRawBody(req);
  } catch (err) {
    log("error", "event", "Failed to read request body", {
      error: err.message,
    });
    return res.status(400).json({ success: false, error: "Invalid body" });
  }

  const signatureHeader = req.headers["x-hub-signature-256"];
  const signature = validateSignature(rawBody, signatureHeader, appSecret);

  if (signature.checked && !signature.valid) {
    log("warn", "event", "Signature mismatch", {
      skipSignature,
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

  let payload;
  try {
    payload = rawBody ? JSON.parse(rawBody) : null;
  } catch (err) {
    log("error", "event", "Body is not valid JSON", {
      error: err.message,
      preview: rawBody.slice(0, 400),
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
