// GET /config.js — public settings the page needs to reach Supabase (all safe to show in a browser).
export default function handler(req, res) {
  const cfg = {
    supabaseUrl: process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || "",
    supabaseKey: process.env.SUPABASE_PUBLISHABLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_ANON_KEY || "",
    appClientKey: process.env.APP_CLIENT_KEY || "",
    loginDomain: process.env.LOGIN_DOMAIN || "tosm.local",
  };
  res.setHeader("Content-Type", "application/javascript; charset=utf-8");
  res.setHeader("Cache-Control", "public, max-age=60");
  res.send(`window.TOSM_CONFIG = ${JSON.stringify(cfg)};`);
}
