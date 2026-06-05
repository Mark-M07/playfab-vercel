import {
  getSupabaseServiceClient,
  isSupabaseConfigured,
  ugTable,
} from "./client.js";

const PLAYER_COLUMNS =
  "id, oculus_id, playfab_id_master, playfab_id_title, display_name, created_at, updated_at";

/**
 * Fetch a player row by Meta / Oculus app-scoped ID (webhook user_id).
 */
export async function getPlayerByOculusId(oculusId) {
  const client = getSupabaseServiceClient();
  if (!client) {
    return {
      ok: false,
      player: null,
      error: "supabase_not_configured",
    };
  }

  const { data, error } = await ugTable(client, "players")
    .select(PLAYER_COLUMNS)
    .eq("oculus_id", String(oculusId))
    .maybeSingle();

  if (error) {
    return { ok: false, player: null, error: error.message, code: error.code };
  }

  return { ok: true, player: data, error: null };
}

/**
 * Insert a minimal player row (oculus_id only). PlayFab fields filled later.
 */
export async function createPlayerByOculusId(oculusId) {
  const client = getSupabaseServiceClient();
  if (!client) {
    return {
      ok: false,
      player: null,
      created: false,
      error: "supabase_not_configured",
    };
  }

  const { data, error } = await ugTable(client, "players")
    .insert({ oculus_id: String(oculusId) })
    .select(PLAYER_COLUMNS)
    .single();

  if (error) {
    if (error.code === "23505") {
      return getPlayerByOculusId(oculusId).then((existing) => ({
        ...existing,
        created: false,
      }));
    }
    return {
      ok: false,
      player: null,
      created: false,
      error: error.message,
      code: error.code,
    };
  }

  return { ok: true, player: data, created: true, error: null };
}

/**
 * Ensure ug.players has a row for this Meta ID — select first, insert if missing.
 */
export async function ensurePlayerByOculusId(oculusId) {
  if (!isSupabaseConfigured()) {
    return {
      ok: false,
      player: null,
      created: false,
      error: "supabase_not_configured",
    };
  }

  const existing = await getPlayerByOculusId(oculusId);
  if (!existing.ok) {
    return { ...existing, created: false };
  }

  if (existing.player) {
    return { ok: true, player: existing.player, created: false, error: null };
  }

  return createPlayerByOculusId(oculusId);
}
