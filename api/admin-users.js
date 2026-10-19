// POST /api/admin-users — admin-only account management.
// Runs on Vercel with the service role key from the environment; the key never reaches the browser.
// Body: { action: "create", username, display_name, role }   → { ok, username, password }
//       { action: "reset", id }                               → { ok, password }
//       { action: "update", id, role?, active?, display_name? } → { ok }
import { createClient } from "@supabase/supabase-js";
import { randomInt } from "node:crypto";

const SUPABASE_URL = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL;
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY;
const DOMAIN = process.env.LOGIN_DOMAIN || "tosm.local";
const ROLES = ["admin", "editor", "viewer"];
const CHARS = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";   // no 0/O, 1/l/I
const newPassword = (n = 12) => Array.from({ length: n }, () => CHARS[randomInt(CHARS.length)]).join("");

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ error: "ใช้ได้เฉพาะ POST" });
  if (!SUPABASE_URL || !SERVICE_KEY) return res.status(500).json({ error: "ยังไม่ได้ตั้ง SUPABASE_URL และ SUPABASE_SERVICE_ROLE_KEY ใน Vercel" });
  const db = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });

  // who is calling? must be a signed-in, active admin
  const token = String(req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!token) return res.status(401).json({ error: "กรุณาเข้าสู่ระบบ" });
  const { data: who, error: whoErr } = await db.auth.getUser(token);
  if (whoErr || !who?.user) return res.status(401).json({ error: "เซสชันหมดอายุ · เข้าสู่ระบบใหม่" });
  const { data: me } = await db.from("profiles").select("id, role, active").eq("id", who.user.id).maybeSingle();
  if (!me?.active || me.role !== "admin") return res.status(403).json({ error: "เฉพาะผู้ดูแล (admin) เท่านั้น" });

  let b = req.body || {};
  if (typeof b === "string") { try { b = JSON.parse(b); } catch { b = {}; } }
  const name = v => String(v ?? "").trim().slice(0, 40);

  try {
    if (b.action === "create") {
      const username = String(b.username || "").trim().toLowerCase();
      if (!/^[a-z0-9._-]{2,32}$/.test(username)) return res.status(400).json({ error: "ชื่อผู้ใช้ใช้ได้เฉพาะ a-z 0-9 . _ - ยาว 2–32 ตัว" });
      const role = ROLES.includes(b.role) ? b.role : "editor";
      const password = newPassword();
      const { data, error } = await db.auth.admin.createUser({
        email: `${username}@${DOMAIN}`, password, email_confirm: true, user_metadata: { display_name: name(b.display_name) } });
      if (error) return res.status(400).json({ error: /already|exists|registered/i.test(error.message) ? "ชื่อผู้ใช้นี้มีอยู่แล้ว" : error.message });
      const { error: pe } = await db.from("profiles").upsert({ id: data.user.id, username, display_name: name(b.display_name) || username, role, active: true });
      if (pe) throw pe;
      return res.json({ ok: true, username, password });
    }

    const { data: target } = await db.from("profiles").select("id, username").eq("id", String(b.id || "")).maybeSingle();
    if (!target) return res.status(404).json({ error: "ไม่พบผู้ใช้นี้" });

    if (b.action === "reset") {
      const password = newPassword();
      const { error } = await db.auth.admin.updateUserById(target.id, { password });
      if (error) throw error;
      return res.json({ ok: true, password });
    }

    if (b.action === "update") {
      const patch = {};
      if ("display_name" in b) patch.display_name = name(b.display_name) || target.username;
      if ("role" in b) { if (!ROLES.includes(b.role)) return res.status(400).json({ error: "สิทธิ์ไม่ถูกต้อง" }); patch.role = b.role; }
      if ("active" in b) patch.active = !!b.active;
      if (target.id === me.id && ((patch.role && patch.role !== "admin") || patch.active === false))
        return res.status(400).json({ error: "ลดสิทธิ์หรือปิดบัญชีของตัวเองไม่ได้" });
      const { error } = await db.from("profiles").update(patch).eq("id", target.id);
      if (error) throw error;
      if ("active" in patch) {
        // a switched-off account can no longer sign in or refresh its session; its edit locks are freed
        await db.auth.admin.updateUserById(target.id, { ban_duration: patch.active ? "none" : "876000h" });
        if (!patch.active) await db.from("edit_locks").delete().eq("user_id", target.id);
      }
      return res.json({ ok: true });
    }

    return res.status(400).json({ error: "ไม่รู้จักคำสั่งนี้" });
  } catch (e) {
    return res.status(500).json({ error: e?.message || String(e) });
  }
}
