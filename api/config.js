// GET /config.js — only what the login screen needs to reach Supabase (safe to show in a browser:
// the publishable key opens nothing without an account, RLS guards every table).
// The App Client key and the item-list URL are NOT here: the page gets them from public.client_config() after login.
export default function handler(req, res) {
  const cfg = {
    supabaseUrl: process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || "",
    supabaseKey: process.env.SUPABASE_PUBLISHABLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_ANON_KEY || "",
    loginDomain: process.env.LOGIN_DOMAIN || "tosm.local",
  };
  res.setHeader("Content-Type", "application/javascript; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.send(`window.TOSM_CONFIG = ${JSON.stringify(cfg)};`);
}
