import { createClient } from "@supabase/supabase-js";

/** @type {import("@supabase/supabase-js").SupabaseClient | null} */
let serviceClient = null;

export const UG_SCHEMA = "ug";

export function isSupabaseConfigured() {
  return Boolean(
    process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY,
  );
}

/**
 * Server-side Supabase client (service role — bypasses RLS).
 * Returns null when SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY are not set.
 */
export function getSupabaseServiceClient() {
  const url = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !serviceRoleKey) {
    return null;
  }

  if (!serviceClient) {
    serviceClient = createClient(url, serviceRoleKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      },
    });
  }

  return serviceClient;
}

/** Query builder scoped to the Ug game schema. */
export function ugTable(client, tableName) {
  return client.schema(UG_SCHEMA).from(tableName);
}
