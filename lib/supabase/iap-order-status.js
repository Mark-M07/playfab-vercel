import {
  getSupabaseServiceClient,
  isSupabaseConfigured,
  ugTable,
} from "./client.js";

const ORDER_STATUS_COLUMNS =
  "id, reporting_id, sku, oculus_id, player_id, notification_type, purchased_at, webhook_received_at, created_at, updated_at";

/**
 * Meta sends event_time as a Unix seconds string (see docs/meta-webhook-sample-payload.json).
 */
export function parseMetaEventTime(eventTime) {
  if (eventTime == null || eventTime === "") {
    return null;
  }

  const seconds = Number(eventTime);
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return null;
  }

  return new Date(seconds * 1000).toISOString();
}

/**
 * Insert an IAP ownership row into ug.iap_order_status.
 * Idempotent on reporting_id — duplicate webhook deliveries return the existing row.
 */
export async function recordOrderStatus({
  reportingId,
  sku,
  oculusId,
  playerId,
  notificationType = "PURCHASED",
  purchasedAt = null,
}) {
  const client = getSupabaseServiceClient();
  if (!client) {
    return {
      ok: false,
      orderStatus: null,
      created: false,
      action: "supabase_not_configured",
      error: "supabase_not_configured",
    };
  }

  if (!isSupabaseConfigured()) {
    return {
      ok: false,
      orderStatus: null,
      created: false,
      action: "supabase_not_configured",
      error: "supabase_not_configured",
    };
  }

  const row = {
    reporting_id: reportingId,
    sku: String(sku),
    oculus_id: String(oculusId),
    player_id: playerId,
    notification_type: notificationType,
  };

  if (purchasedAt) {
    row.purchased_at = purchasedAt;
  }

  const { data, error } = await ugTable(client, "iap_order_status")
    .insert(row)
    .select(ORDER_STATUS_COLUMNS)
    .single();

  if (error) {
    if (error.code === "23505") {
      const existing = await getOrderStatusByReportingId(reportingId);
      if (existing.ok && existing.orderStatus) {
        return {
          ok: true,
          orderStatus: existing.orderStatus,
          created: false,
          action: "skip_duplicate",
          error: null,
        };
      }
    }

    return {
      ok: false,
      orderStatus: null,
      created: false,
      action: "insert_failed",
      error: error.message,
      code: error.code,
    };
  }

  return {
    ok: true,
    orderStatus: data,
    created: true,
    action: "insert",
    error: null,
  };
}

export async function getOrderStatusByReportingId(reportingId) {
  const client = getSupabaseServiceClient();
  if (!client) {
    return {
      ok: false,
      orderStatus: null,
      error: "supabase_not_configured",
    };
  }

  const { data, error } = await ugTable(client, "iap_order_status")
    .select(ORDER_STATUS_COLUMNS)
    .eq("reporting_id", reportingId)
    .maybeSingle();

  if (error) {
    return {
      ok: false,
      orderStatus: null,
      error: error.message,
      code: error.code,
    };
  }

  return { ok: true, orderStatus: data, error: null };
}
