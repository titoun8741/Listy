-- Liste de courses avec comptes et listes privées.
-- À coller UNE SEULE FOIS dans Supabase > SQL Editor > New query > Run.
-- Peut être exécuté même si vous aviez déjà lancé l'ancienne version du script.
--
-- Principe : personne n'accède directement aux tables. Tout passe par des fonctions
-- qui exigent d'être connecté ET d'être membre de la liste concernée.

create table if not exists public.lists (
  code text primary key,
  name text not null default '',
  created_at timestamptz not null default now()
);
create table if not exists public.items (
  list_code text not null, id text not null, ts bigint not null default 0, data jsonb not null,
  primary key (list_code, id)
);
create table if not exists public.habits (
  list_code text not null, id text not null, data jsonb not null,
  primary key (list_code, id)
);
create table if not exists public.list_members (
  list_code text not null references public.lists(code) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  joined_at timestamptz not null default now(),
  primary key (list_code, user_id)
);
create table if not exists public.profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  name text not null default ''
);

alter table public.lists        enable row level security;
alter table public.items        enable row level security;
alter table public.habits       enable row level security;
alter table public.list_members enable row level security;
alter table public.profiles     enable row level security;
revoke all on public.lists, public.items, public.habits, public.list_members, public.profiles
  from anon, authenticated;

-- Ancienne fonction de suppression pour tous : retirée.
drop function if exists public.list_delete(text);

-- Fonction interne : l'utilisateur connecté est-il membre de la liste ?
create or replace function public._is_member(p_code text) returns boolean
language sql security definer stable set search_path = public as $$
  select exists (
    select 1 from public.list_members where list_code = p_code and user_id = auth.uid()
  );
$$;

create or replace function public.list_get(p_code text) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or p_code is null or p_code !~ '^[a-z0-9-]{3,24}$'
     or not public._is_member(p_code) then
    raise exception 'accès refusé' using errcode = '42501';
  end if;
  return jsonb_build_object(
    'exists',  true,
    'name',    (select name from public.lists where code = p_code),
    'items',   coalesce((select jsonb_agg(data order by ts, id) from public.items  where list_code = p_code), '[]'::jsonb),
    'habits',  coalesce((select jsonb_agg(data)                 from public.habits where list_code = p_code), '[]'::jsonb),
    'members', coalesce((select jsonb_object_agg(m.user_id::text, coalesce(p.name, ''))
                         from public.list_members m
                         left join public.profiles p on p.user_id = m.user_id
                         where m.list_code = p_code), '{}'::jsonb)
  );
end $$;

create or replace function public.my_lists() returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'accès refusé' using errcode = '42501'; end if;
  return coalesce((
    select jsonb_agg(jsonb_build_object('code', l.code, 'name', l.name) order by m.joined_at, l.code)
    from public.list_members m join public.lists l on l.code = m.list_code
    where m.user_id = auth.uid()
  ), '[]'::jsonb);
end $$;

create or replace function public.list_create(p_name text) returns text
language plpgsql security definer set search_path = public as $$
declare v_code text;
begin
  if auth.uid() is null then raise exception 'accès refusé' using errcode = '42501'; end if;
  if (select count(*) from public.list_members where user_id = auth.uid()) >= 50 then
    raise exception 'trop de listes';
  end if;
  loop
    v_code := left(replace(gen_random_uuid()::text, '-', ''), 10);
    exit when not exists (select 1 from public.lists where code = v_code);
  end loop;
  insert into public.lists(code, name) values (v_code, left(coalesce(p_name, ''), 30));
  insert into public.list_members(list_code, user_id) values (v_code, auth.uid());
  return v_code;
end $$;

create or replace function public.list_join(p_code text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_name text;
begin
  if auth.uid() is null then raise exception 'accès refusé' using errcode = '42501'; end if;
  if p_code is null or p_code !~ '^[a-z0-9-]{3,24}$' then raise exception 'code invalide'; end if;
  select name into v_name from public.lists where code = p_code;
  if not found then raise exception 'liste introuvable'; end if;
  if not public._is_member(p_code) then
    if (select count(*) from public.list_members where user_id = auth.uid()) >= 50 then
      raise exception 'trop de listes';
    end if;
    if (select count(*) from public.list_members where list_code = p_code) >= 20 then
      raise exception 'liste complète';
    end if;
    insert into public.list_members(list_code, user_id) values (p_code, auth.uid());
  end if;
  return jsonb_build_object('code', p_code, 'name', v_name);
end $$;

-- Quitter une liste : retire uniquement VOTRE accès. Les autres membres et les produits ne sont pas touchés.
create or replace function public.list_leave(p_code text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'accès refusé' using errcode = '42501'; end if;
  delete from public.list_members where list_code = p_code and user_id = auth.uid();
end $$;

create or replace function public.list_set_name(p_code text, p_name text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or p_code is null or p_code !~ '^[a-z0-9-]{3,24}$'
     or not public._is_member(p_code) then
    raise exception 'accès refusé' using errcode = '42501';
  end if;
  update public.lists set name = left(coalesce(p_name, ''), 30) where code = p_code;
end $$;

create or replace function public.item_put(p_code text, p_item jsonb) returns void
language plpgsql security definer set search_path = public as $$
declare v_by text; v_item jsonb;
begin
  if auth.uid() is null or p_code is null or p_code !~ '^[a-z0-9-]{3,24}$'
     or not public._is_member(p_code) then
    raise exception 'accès refusé' using errcode = '42501';
  end if;
  if p_item is null or jsonb_typeof(p_item) <> 'object'
     or coalesce(p_item->>'id', '') = '' or length(p_item::text) > 2000 then
    raise exception 'produit invalide';
  end if;
  -- L'auteur d'un produit est fixé par le serveur : on ne peut pas se faire passer pour quelqu'un d'autre.
  select data->>'by' into v_by from public.items where list_code = p_code and id = p_item->>'id';
  if not found then
    if (select count(*) from public.items where list_code = p_code) >= 500 then
      raise exception 'liste pleine';
    end if;
    v_by := auth.uid()::text;
  end if;
  v_item := jsonb_set(p_item, '{by}', to_jsonb(coalesce(v_by, '')));
  insert into public.items(list_code, id, ts, data)
  values (p_code, p_item->>'id', coalesce((p_item->>'ts')::bigint, 0), v_item)
  on conflict (list_code, id) do update set data = excluded.data, ts = excluded.ts;
end $$;

create or replace function public.item_delete(p_code text, p_id text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or p_code is null or p_code !~ '^[a-z0-9-]{3,24}$'
     or not public._is_member(p_code) then
    raise exception 'accès refusé' using errcode = '42501';
  end if;
  delete from public.items where list_code = p_code and id = p_id;
end $$;

create or replace function public.habit_put(p_code text, p_habit jsonb) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or p_code is null or p_code !~ '^[a-z0-9-]{3,24}$'
     or not public._is_member(p_code) then
    raise exception 'accès refusé' using errcode = '42501';
  end if;
  if p_habit is null or jsonb_typeof(p_habit) <> 'object'
     or coalesce(p_habit->>'id', '') = '' or length(p_habit::text) > 1000 then
    raise exception 'habitude invalide';
  end if;
  if not exists (select 1 from public.habits where list_code = p_code and id = p_habit->>'id')
     and (select count(*) from public.habits where list_code = p_code) >= 300 then
    return;
  end if;
  insert into public.habits(list_code, id, data) values (p_code, p_habit->>'id', p_habit)
  on conflict (list_code, id) do update set data = excluded.data;
end $$;

create or replace function public.profile_get() returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'accès refusé' using errcode = '42501'; end if;
  return jsonb_build_object('name', coalesce((select name from public.profiles where user_id = auth.uid()), ''));
end $$;

create or replace function public.profile_set(p_name text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'accès refusé' using errcode = '42501'; end if;
  insert into public.profiles(user_id, name) values (auth.uid(), left(trim(coalesce(p_name, '')), 20))
  on conflict (user_id) do update set name = excluded.name;
end $$;

-- Droits : réservés aux personnes connectées (jamais aux visiteurs anonymes).
revoke all on function
  public._is_member(text), public.list_get(text), public.my_lists(), public.list_create(text),
  public.list_join(text), public.list_leave(text), public.list_set_name(text, text),
  public.item_put(text, jsonb), public.item_delete(text, text), public.habit_put(text, jsonb),
  public.profile_get(), public.profile_set(text)
  from public, anon, authenticated;

grant execute on function
  public.list_get(text), public.my_lists(), public.list_create(text),
  public.list_join(text), public.list_leave(text), public.list_set_name(text, text),
  public.item_put(text, jsonb), public.item_delete(text, text), public.habit_put(text, jsonb),
  public.profile_get(), public.profile_set(text)
  to authenticated;

notify pgrst, 'reload schema';
