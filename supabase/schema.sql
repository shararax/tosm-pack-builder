-- =====================================================================
-- TOSM Pack Builder — Supabase schema, RLS guardrails, edit locks
-- Run once in Supabase → SQL Editor (safe to re-run: everything is idempotent).
-- =====================================================================

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------
-- private schema: things the browser must never read directly
-- ---------------------------------------------------------------------
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

-- App client key: every write from the web app must send this value in the
-- `x-app-client` header. Change it with:  update private.app_config set value = '…' where key = 'app_client_key';
create table if not exists private.app_config (key text primary key, value text not null);
insert into private.app_config (key, value) values ('app_client_key', encode(gen_random_bytes(18), 'hex'))
  on conflict (key) do nothing;
insert into private.app_config (key, value) values ('login_domain', 'tosm.local')
  on conflict (key) do nothing;

-- ---------------------------------------------------------------------
-- Tables
-- ---------------------------------------------------------------------
create table if not exists public.profiles (
  id            uuid primary key references auth.users(id) on delete cascade,
  username      text unique not null check (username ~ '^[a-z0-9._-]{2,32}$'),
  display_name  text not null default '',
  role          text not null default 'viewer' check (role in ('admin','editor','viewer')),
  active        boolean not null default false,          -- only accounts made by an admin are switched on
  created_at    timestamptz not null default now()
);

create table if not exists public.folders (
  id          text primary key,
  name        text not null default 'โปรโมชันใหม่',
  color       text not null default '',
  pack_order  text[] not null default '{}',
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  updated_by  uuid references auth.users(id) on delete set null
);

create table if not exists public.packs (
  id                text primary key,
  folder_id         text not null references public.folders(id) on delete cascade,
  name              text not null default '',
  mode              text not null default 'fixed' check (mode in ('fixed','random')),
  price             numeric,                              -- THB
  display_pos       integer not null default 0,           -- higher = shown first
  buy_limit         integer check (buy_limit >= 0),        -- 0 = unlimited (the page warns above 99)
  start_date        date,
  start_time        text not null default '00:01',
  end_date          date,
  end_time          text not null default '23:59',
  reset_on          boolean not null default false,
  reset_every       integer,
  reset_first_date  date,
  reset_first_time  text not null default '23:59',
  az_category       text not null default '',
  types             text[] not null default '{}',
  bonus             boolean not null default true,        -- gets Golden Seed Point + Player EXP
  idea              text not null default '',
  image_url         text not null default '',
  sold_count        integer check (sold_count >= 0),       -- real sales, typed in after the promotion
  extra             jsonb not null default '{}',          -- anything the app keeps that has no column yet
  updated_at        timestamptz not null default now(),
  updated_by        uuid references auth.users(id) on delete set null
);
create index if not exists packs_folder_idx on public.packs(folder_id);

create table if not exists public.pack_items (
  pack_id    text not null references public.packs(id) on delete cascade,
  uid        text not null,
  position   integer not null default 0,
  item_id    text not null default '',
  name       text not null default '',
  amt        numeric,
  tp         numeric,
  tp_game    numeric,
  chance     numeric check (chance is null or chance >= 0),
  is_fixed   boolean not null default false,
  is_custom  boolean not null default false,
  extra      jsonb not null default '{}',
  primary key (pack_id, uid)
);

create table if not exists public.item_values (           -- TP remembered per item
  item_id    text primary key,
  tp         numeric,
  tp_game    numeric,
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users(id) on delete set null
);

create table if not exists public.app_settings (
  id           integer primary key default 1 check (id = 1),
  tp_rate      numeric not null default 2,
  seed_per_thb numeric not null default 10,
  az_map       jsonb not null default '{}',
  custom_cats  text[] not null default '{}',
  updated_at   timestamptz not null default now(),
  updated_by   uuid references auth.users(id) on delete set null
);
insert into public.app_settings (id) values (1) on conflict do nothing;

create table if not exists public.edit_locks (
  resource     text primary key,                        -- e.g. 'pack:abc123'
  user_id      uuid not null references auth.users(id) on delete cascade,
  user_name    text not null default '',
  acquired_at  timestamptz not null default now(),
  expires_at   timestamptz not null
);

create table if not exists public.change_log (
  id         bigserial primary key,
  at         timestamptz not null default now(),
  user_id    uuid,
  user_name  text not null default '',
  entity     text not null,
  entity_id  text not null,
  action     text not null,
  summary    jsonb not null default '{}'
);
create index if not exists change_log_entity_idx on public.change_log(entity, entity_id, at desc);

-- ---------------------------------------------------------------------
-- Helpers used by every policy
-- ---------------------------------------------------------------------
create or replace function public.is_member() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and active);
$$;

create or replace function public.app_client_ok() returns boolean
language sql stable security definer set search_path = public, private as $$
  select coalesce(
    (current_setting('request.headers', true)::jsonb ->> 'x-app-client')
      = (select value from private.app_config where key = 'app_client_key'), false);
$$;

create or replace function public.can_edit() returns boolean
language sql stable security definer set search_path = public as $$
  select public.app_client_ok() and exists (
    select 1 from public.profiles where id = auth.uid() and active and role in ('admin','editor'));
$$;

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and active and role = 'admin');
$$;

create or replace function public.my_name() returns text
language sql stable security definer set search_path = public as $$
  select coalesce(nullif(display_name, ''), username, '') from public.profiles where id = auth.uid();
$$;

-- a new auth user gets an inactive viewer profile; only the admin API switches it on
create or replace function private.on_auth_user_created() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, username, display_name)
  values (new.id,
          lower(split_part(coalesce(new.email, new.id::text), '@', 1)),
          coalesce(new.raw_user_meta_data ->> 'display_name', ''))
  on conflict (id) do nothing;
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function private.on_auth_user_created();

-- ---------------------------------------------------------------------
-- Grants: anon gets NOTHING; authenticated gets table access that RLS then narrows
-- ---------------------------------------------------------------------
revoke all on all tables    in schema public from anon;
revoke all on all sequences in schema public from anon;
revoke all on all functions in schema public from anon, public;
alter default privileges in schema public revoke all on tables    from anon;
alter default privileges in schema public revoke all on sequences from anon;
alter default privileges in schema public revoke all on functions from anon, public;

revoke all on all tables    in schema public from authenticated;
revoke all on all functions in schema public from authenticated;
grant usage on schema public to authenticated;
grant select, insert, update, delete on public.folders, public.packs, public.pack_items, public.item_values to authenticated;
grant select, update on public.app_settings to authenticated;
grant select on public.profiles, public.edit_locks, public.change_log to authenticated;
grant execute on function public.is_member(), public.can_edit(), public.is_admin(), public.my_name(), public.app_client_ok() to authenticated;

-- ---------------------------------------------------------------------
-- Row Level Security — on for every table, policies per role
-- ---------------------------------------------------------------------
alter table public.profiles     enable row level security;
alter table public.folders      enable row level security;
alter table public.packs        enable row level security;
alter table public.pack_items   enable row level security;
alter table public.item_values  enable row level security;
alter table public.app_settings enable row level security;
alter table public.edit_locks   enable row level security;
alter table public.change_log   enable row level security;

do $$ declare t text; begin
  foreach t in array array['folders','packs','pack_items','item_values'] loop
    execute format('drop policy if exists %1$s_read on public.%1$s', t);
    execute format('drop policy if exists %1$s_insert on public.%1$s', t);
    execute format('drop policy if exists %1$s_update on public.%1$s', t);
    execute format('drop policy if exists %1$s_delete on public.%1$s', t);
    execute format('create policy %1$s_read   on public.%1$s for select to authenticated using (public.is_member())', t);
    execute format('create policy %1$s_insert on public.%1$s for insert to authenticated with check (public.can_edit())', t);
    execute format('create policy %1$s_update on public.%1$s for update to authenticated using (public.can_edit()) with check (public.can_edit())', t);
    execute format('create policy %1$s_delete on public.%1$s for delete to authenticated using (public.can_edit())', t);
  end loop;
end $$;

drop policy if exists app_settings_read on public.app_settings;
drop policy if exists app_settings_update on public.app_settings;
create policy app_settings_read   on public.app_settings for select to authenticated using (public.is_member());
create policy app_settings_update on public.app_settings for update to authenticated using (public.can_edit()) with check (public.can_edit());

drop policy if exists profiles_read on public.profiles;
create policy profiles_read on public.profiles for select to authenticated
  using (id = auth.uid() or public.is_member());          -- members see names; changes go through the admin API only

drop policy if exists edit_locks_read on public.edit_locks;
create policy edit_locks_read on public.edit_locks for select to authenticated using (public.is_member());
-- no insert/update/delete policies: locks change only through acquire_lock / release_lock

drop policy if exists change_log_read on public.change_log;
create policy change_log_read on public.change_log for select to authenticated using (public.is_member());

-- ---------------------------------------------------------------------
-- Edit locks: the first person to open a pack holds it; others see who
-- ---------------------------------------------------------------------
create or replace function public.acquire_lock(p_resource text, p_ttl_seconds integer default 60)
returns table (resource text, user_id uuid, user_name text, expires_at timestamptz, mine boolean)
language plpgsql security definer set search_path = public as $$
#variable_conflict use_column
declare v_name text := public.my_name();
begin
  if not public.can_edit() then raise exception 'not_allowed' using errcode = '42501'; end if;
  insert into public.edit_locks as l (resource, user_id, user_name, acquired_at, expires_at)
  values (p_resource, auth.uid(), v_name, now(), now() + make_interval(secs => greatest(15, least(p_ttl_seconds, 300))))
  on conflict (resource) do update
    set user_id = excluded.user_id, user_name = excluded.user_name, expires_at = excluded.expires_at,
        acquired_at = case when l.user_id = excluded.user_id then l.acquired_at else now() end
    where l.user_id = excluded.user_id or l.expires_at < now();          -- free, expired, or already mine
  return query select l.resource, l.user_id, l.user_name, l.expires_at, l.user_id = auth.uid()
    from public.edit_locks l where l.resource = p_resource;
end $$;

create or replace function public.release_lock(p_resource text) returns void
language sql security definer set search_path = public as $$
  delete from public.edit_locks where resource = p_resource and user_id = auth.uid();
$$;

create or replace function public.release_my_locks() returns void
language sql security definer set search_path = public as $$
  delete from public.edit_locks where user_id = auth.uid();
$$;

create or replace function private.locked_by_other(p_resource text) returns text
language sql stable security definer set search_path = public as $$
  select user_name from public.edit_locks
   where resource = p_resource and user_id <> auth.uid() and expires_at > now();
$$;

create or replace function private.log(p_entity text, p_id text, p_action text, p_summary jsonb) returns void
language sql security definer set search_path = public as $$
  insert into public.change_log (user_id, user_name, entity, entity_id, action, summary)
  values (auth.uid(), coalesce(public.my_name(), ''), p_entity, p_id, p_action, coalesce(p_summary, '{}'));
$$;

-- ---------------------------------------------------------------------
-- save_pack: one transaction writes the pack row and its items, refuses
-- when someone else holds the pack's lock, and logs the change
-- ---------------------------------------------------------------------
create or replace function public.save_pack(p jsonb, items jsonb) returns timestamptz
language plpgsql security invoker set search_path = public as $$
declare v_id text := p ->> 'id'; v_holder text; v_at timestamptz := now(); v_new boolean;
begin
  if not public.can_edit() then raise exception 'not_allowed' using errcode = '42501'; end if;
  v_holder := private.locked_by_other('pack:' || v_id);
  if v_holder is not null then raise exception 'locked_by_other:%', v_holder using errcode = 'P0001'; end if;
  v_new := not exists (select 1 from public.packs where id = v_id);
  insert into public.packs as t (id, folder_id, name, mode, price, display_pos, buy_limit, start_date, start_time, end_date, end_time,
      reset_on, reset_every, reset_first_date, reset_first_time, az_category, types, bonus, idea, image_url, sold_count, extra, updated_at, updated_by)
  values (v_id, p->>'folder_id', coalesce(p->>'name',''), coalesce(p->>'mode','fixed'), (p->>'price')::numeric, coalesce((p->>'display_pos')::int, 0),
      (p->>'buy_limit')::int, (p->>'start_date')::date, coalesce(p->>'start_time','00:01'), (p->>'end_date')::date, coalesce(p->>'end_time','23:59'),
      coalesce((p->>'reset_on')::boolean, false), (p->>'reset_every')::int, (p->>'reset_first_date')::date, coalesce(p->>'reset_first_time','23:59'),
      coalesce(p->>'az_category',''), coalesce(array(select jsonb_array_elements_text(p->'types')), '{}'), coalesce((p->>'bonus')::boolean, true),
      coalesce(p->>'idea',''), coalesce(p->>'image_url',''), (p->>'sold_count')::int, coalesce(p->'extra','{}'), v_at, auth.uid())
  on conflict (id) do update set folder_id = excluded.folder_id, name = excluded.name, mode = excluded.mode, price = excluded.price,
      display_pos = excluded.display_pos, buy_limit = excluded.buy_limit, start_date = excluded.start_date, start_time = excluded.start_time,
      end_date = excluded.end_date, end_time = excluded.end_time, reset_on = excluded.reset_on, reset_every = excluded.reset_every,
      reset_first_date = excluded.reset_first_date, reset_first_time = excluded.reset_first_time, az_category = excluded.az_category,
      types = excluded.types, bonus = excluded.bonus, idea = excluded.idea, image_url = excluded.image_url, sold_count = excluded.sold_count,
      extra = excluded.extra, updated_at = v_at, updated_by = auth.uid();
  delete from public.pack_items where pack_id = v_id
    and uid not in (select e->>'uid' from jsonb_array_elements(coalesce(items,'[]')) e);
  insert into public.pack_items as t (pack_id, uid, position, item_id, name, amt, tp, tp_game, chance, is_fixed, is_custom, extra)
  select v_id, e->>'uid', (ord - 1)::int, coalesce(e->>'item_id',''), coalesce(e->>'name',''), (e->>'amt')::numeric, (e->>'tp')::numeric,
         (e->>'tp_game')::numeric, (e->>'chance')::numeric, coalesce((e->>'is_fixed')::boolean,false), coalesce((e->>'is_custom')::boolean,false), coalesce(e->'extra','{}')
    from jsonb_array_elements(coalesce(items,'[]')) with ordinality as x(e, ord)
  on conflict (pack_id, uid) do update set position = excluded.position, item_id = excluded.item_id, name = excluded.name, amt = excluded.amt,
      tp = excluded.tp, tp_game = excluded.tp_game, chance = excluded.chance, is_fixed = excluded.is_fixed, is_custom = excluded.is_custom, extra = excluded.extra;
  perform private.log('pack', v_id, case when v_new then 'create' else 'update' end,
    jsonb_build_object('name', p->>'name', 'folder_id', p->>'folder_id', 'items', jsonb_array_length(coalesce(items,'[]'))));
  return v_at;
end $$;

create or replace function public.delete_pack(p_id text) returns void
language plpgsql security invoker set search_path = public as $$
declare v_holder text; v_name text;
begin
  if not public.can_edit() then raise exception 'not_allowed' using errcode = '42501'; end if;
  v_holder := private.locked_by_other('pack:' || p_id);
  if v_holder is not null then raise exception 'locked_by_other:%', v_holder using errcode = 'P0001'; end if;
  select name into v_name from public.packs where id = p_id;
  delete from public.packs where id = p_id;
  perform private.log('pack', p_id, 'delete', jsonb_build_object('name', v_name));
end $$;


-- lock guard: no route (direct update, folder delete cascade, …) can change a pack someone else holds
create or replace function private.pack_lock_guard() returns trigger
language plpgsql security definer set search_path = public as $$
declare r jsonb; v_id text; v_holder text;
begin
  if auth.uid() is null then return coalesce(new, old); end if;        -- service role / SQL editor
  r := case when tg_op = 'DELETE' then to_jsonb(old) else to_jsonb(new) end;
  v_id := coalesce(r ->> 'pack_id', r ->> 'id');
  v_holder := private.locked_by_other('pack:' || v_id);
  if v_holder is not null then raise exception 'locked_by_other:%', v_holder using errcode = 'P0001'; end if;
  return coalesce(new, old);
end $$;
drop trigger if exists packs_lock_guard on public.packs;
create trigger packs_lock_guard before update or delete on public.packs for each row execute function private.pack_lock_guard();
drop trigger if exists pack_items_lock_guard on public.pack_items;
create trigger pack_items_lock_guard before insert or update or delete on public.pack_items for each row execute function private.pack_lock_guard();

-- folders: log every change through a trigger
create or replace function private.log_folder() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'DELETE' then perform private.log('folder', old.id, 'delete', jsonb_build_object('name', old.name)); return old; end if;
  new.updated_at := now(); new.updated_by := auth.uid();
  perform private.log('folder', new.id, lower(tg_op), jsonb_build_object('name', new.name));
  return new;
end $$;
drop trigger if exists folders_log on public.folders;
create trigger folders_log before insert or update or delete on public.folders for each row execute function private.log_folder();

create or replace function private.touch() returns trigger
language plpgsql security definer set search_path = public as $$
begin new.updated_at := now(); new.updated_by := auth.uid(); return new; end $$;
drop trigger if exists app_settings_touch on public.app_settings;
create trigger app_settings_touch before update on public.app_settings for each row execute function private.touch();
drop trigger if exists item_values_touch on public.item_values;
create trigger item_values_touch before insert or update on public.item_values for each row execute function private.touch();

grant execute on function public.acquire_lock(text, integer), public.release_lock(text), public.release_my_locks(),
  public.save_pack(jsonb, jsonb), public.delete_pack(text) to authenticated;
-- the helpers in private run only inside the functions above
grant usage on schema private to authenticated;
revoke all on all tables in schema private from authenticated;
grant execute on function private.locked_by_other(text), private.log(text, text, text, jsonb) to authenticated;

-- ---------------------------------------------------------------------
-- Guardrail 1: any table created later in public gets RLS switched on
-- (Supabase allows event triggers for the postgres role; if your project
--  refuses this block, the audit below still catches a forgotten table)
-- ---------------------------------------------------------------------
create or replace function private.rls_on_new_table() returns event_trigger
language plpgsql security definer set search_path = public as $$
declare r record;
begin
  for r in select * from pg_event_trigger_ddl_commands() where command_tag = 'CREATE TABLE' and schema_name = 'public' loop
    execute format('alter table %s enable row level security', r.object_identity);
    execute format('revoke all on %s from anon', r.object_identity);
  end loop;
end $$;
do $$ begin
  if exists (select 1 from pg_event_trigger where evtname = 'tosm_rls_on_new_table') then drop event trigger tosm_rls_on_new_table; end if;
  create event trigger tosm_rls_on_new_table on ddl_command_end when tag in ('CREATE TABLE') execute function private.rls_on_new_table();
exception when insufficient_privilege then raise notice 'event trigger not allowed here; rely on public.rls_audit()';
end $$;

-- ---------------------------------------------------------------------
-- Guardrail 2: audit — run  select * from public.rls_audit();  it must return 0 rows
-- ---------------------------------------------------------------------
create or replace function public.rls_audit()
returns table (table_name text, problem text)
language sql stable security definer set search_path = public as $$
  select c.relname::text, 'RLS is off' from pg_class c join pg_namespace n on n.oid = c.relnamespace
   where n.nspname = 'public' and c.relkind = 'r' and not c.relrowsecurity
  union all
  select c.relname::text, 'RLS on but no policy (nobody can use it — add one or drop the table)'
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
   where n.nspname = 'public' and c.relkind = 'r' and c.relrowsecurity
     and not exists (select 1 from pg_policies p where p.schemaname = 'public' and p.tablename = c.relname)
  union all
  select table_name::text, 'anon has ' || string_agg(privilege_type, ', ')
    from information_schema.role_table_grants
   where table_schema = 'public' and grantee = 'anon' group by table_name
  union all
  select p.tablename::text, 'policy "' || p.policyname || '" is open to anon / public'
    from pg_policies p where p.schemaname = 'public' and (p.roles && array['anon','public']::name[]);
$$;
revoke all on function public.rls_audit() from public, anon, authenticated;   -- run it from the SQL editor

-- ---------------------------------------------------------------------
-- Realtime: everyone's changes reach every open page
-- ---------------------------------------------------------------------
do $$ declare t text; begin
  if not exists (select 1 from pg_publication where pubname = 'supabase_realtime') then create publication supabase_realtime; end if;
  foreach t in array array['folders','packs','item_values','app_settings','edit_locks'] loop
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = t) then
      execute format('alter publication supabase_realtime add table public.%I', t);
    end if;
  end loop;
end $$;
alter table public.packs replica identity full;
alter table public.edit_locks replica identity full;
alter table public.folders replica identity full;
