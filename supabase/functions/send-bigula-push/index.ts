// Supabase Edge Function: send BIGULA push notifications via Firebase Cloud Messaging HTTP v1.
// Required Supabase Edge Function secrets:
//   FIREBASE_SERVICE_ACCOUNT_JSON  full Firebase service-account JSON (never expose client-side)
//   SUPABASE_URL                    https://vfteiggdhthvrrlndtbs.supabase.co
//   SUPABASE_SERVICE_ROLE_KEY       Supabase service-role key (server-side only)
//   BIGULA_PUSH_WEBHOOK_SECRET      random secret shared with the Database Webhook
//
// Configure Database Webhook: public.notifications, INSERT, POST to this function.
// Add header: x-bigula-webhook-secret: <same BIGULA_PUSH_WEBHOOK_SECRET>
// The notification row's user_id selects recipients from public.user_push_tokens.

import { createClient } from "npm:@supabase/supabase-js@2";
import { SignJWT, importPKCS8 } from "npm:jose@5";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://afrixx-app.github.io",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-bigula-webhook-secret",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

async function getGoogleAccessToken(serviceAccount: { client_email: string; private_key: string; token_uri?: string }) {
  const now = Math.floor(Date.now() / 1000);
  const key = await importPKCS8(serviceAccount.private_key, "RS256");
  const assertion = await new SignJWT({
    scope: "https://www.googleapis.com/auth/firebase.messaging",
  })
    .setProtectedHeader({ alg: "RS256", typ: "JWT" })
    .setIssuer(serviceAccount.client_email)
    .setAudience(serviceAccount.token_uri || "https://oauth2.googleapis.com/token")
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .sign(key);

  const response = await fetch(serviceAccount.token_uri || "https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion,
    }),
  });
  const body = await response.json();
  if (!response.ok || !body.access_token) {
    throw new Error(`Google OAuth token request failed (${response.status}): ${JSON.stringify(body)}`);
  }
  return body.access_token as string;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  const expectedSecret = Deno.env.get("BIGULA_PUSH_WEBHOOK_SECRET");
  const providedSecret = req.headers.get("x-bigula-webhook-secret");
  if (!expectedSecret || !providedSecret || providedSecret !== expectedSecret) {
    return json({ error: "Unauthorized webhook" }, 401);
  }

  try {
    const payload = await req.json();
    const record = payload?.record;
    if (payload?.type !== "INSERT" || payload?.table !== "notifications" ||
        payload?.schema !== "public" || !record?.user_id) {
      return json({ ignored: true, reason: "Not a supported notification insert" });
    }

    const serviceAccountRaw = Deno.env.get("FIREBASE_SERVICE_ACCOUNT_JSON");
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!serviceAccountRaw || !supabaseUrl || !serviceRoleKey) {
      throw new Error("Missing required server secrets");
    }

    const serviceAccount = JSON.parse(serviceAccountRaw);
    const projectId = serviceAccount.project_id;
    if (!projectId || !serviceAccount.client_email || !serviceAccount.private_key) {
      throw new Error("Firebase service-account JSON is missing required fields");
    }

    const supabase = createClient(supabaseUrl, serviceRoleKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: devices, error: tokenError } = await supabase
      .from("user_push_tokens")
      .select("id, token")
      .eq("user_id", record.user_id);

    if (tokenError) throw tokenError;
    if (!devices?.length) return json({ ok: true, sent: 0, reason: "No registered devices" });

    const accessToken = await getGoogleAccessToken(serviceAccount);
    const title = String(record.title || "BIGULA notification").slice(0, 120);
    const body = String(record.message || "You have a new notification on BIGULA.").slice(0, 500);
    const results = await Promise.all(devices.map(async (device: { id: string; token: string }) => {
      const response = await fetch(
        `https://fcm.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/messages:send`,
        {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${accessToken}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            message: {
              token: device.token,
              notification: { title, body },
              data: {
                notification_id: String(record.id || ""),
                type: String(record.type || ""),
                related_video_id: String(record.related_video_id || ""),
                related_user_id: String(record.related_user_id || ""),
              },
              android: { priority: "HIGH", notification: { channel_id: "default" } },
            },
          }),
        },
      );
      const result = await response.json().catch(() => ({}));
      if (!response.ok) {
        const errorCode = result?.error?.details?.find((x: { errorCode?: string }) => x.errorCode)?.errorCode;
        if (response.status === 404 || errorCode === "UNREGISTERED") {
          await supabase.from("user_push_tokens").delete().eq("id", device.id);
        }
        return { ok: false, status: response.status, error: result?.error?.message || "FCM send failed" };
      }
      return { ok: true };
    }));

    return json({
      ok: results.every((r) => r.ok),
      sent: results.filter((r) => r.ok).length,
      failed: results.filter((r) => !r.ok).length,
    });
  } catch (error) {
    console.error("BIGULA push sender error:", error);
    return json({ error: "Push delivery failed. Check Edge Function logs." }, 500);
  }
});
