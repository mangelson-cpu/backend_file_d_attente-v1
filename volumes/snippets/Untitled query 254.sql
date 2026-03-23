create or replace function public.create_user_with_role(
    p_email text,
    p_nom text,
    p_password text, 
    p_role text,
    p_agence_id uuid
)
returns void
language plpgsql
security definer
as $$
declare
    current_role text;
begin
    select role into current_role
    from public.users
    where id = auth.uid();

    if current_role is null then
        raise exception 'Utilisateur non trouvé';
    end if;

    if current_role = 'super_admin' then
        null;
    elsif current_role = 'admin' then
        if p_role != 'user' then
            raise exception 'Un admin peut seulement créer un user';
        end if;
        if p_agence_id != (select agence_id from public.users where id = auth.uid()) then
            raise exception 'Un admin ne peut créer que dans sa propre agence';
        end if;
    else
        raise exception 'Permission refusée';
    end if;

    insert into public.users (id, email, nom_user, role, agence_id)
    values (gen_random_uuid(), p_email, p_nom, p_role, p_agence_id);
end;
$$;

grant execute on function public.create_user_with_role to authenticated;

create or replace function public.create_user_with_role(
    p_user_id uuid,          -- ID de l'utilisateur déjà créé dans auth.users
    p_email text,
    p_nom text,
    p_role text,
    p_agence_id uuid
)
returns void
language plpgsql
security definer
as $$
declare
    current_role text;
begin
    -- Récupérer le rôle de l'utilisateur connecté (celui qui appelle la fonction)
    select role into current_role
    from public.users
    where id = auth.uid();

    if current_role is null then
        raise exception 'Utilisateur non trouvé';
    end if;

    -- Vérifier la logique des droits
    if current_role = 'super_admin' then
        -- super_admin peut créer admin et user
        null;
    elsif current_role = 'admin' then
        -- admin ne peut créer que des users
        if p_role != 'user' then
            raise exception 'Un admin peut seulement créer un user';
        end if;
        -- admin ne peut créer que dans sa propre agence
        if p_agence_id != (select agence_id from public.users where id = auth.uid()) then
            raise exception 'Un admin ne peut créer que dans sa propre agence';
        end if;
    else
        raise exception 'Permission refusée';
    end if;

    -- Insérer dans public.users en utilisant l'ID fourni par Supabase Auth
    insert into public.users (id, email, nom_user, role, agence_id)
    values (p_user_id, p_email, p_nom, p_role, p_agence_id);

end;
$$;

select role into current_role
select auth.uid() as current_user_id;


create or replace function public.create_user_simple(
    p_user_id uuid,
    p_email text,
    p_nom text,
    p_role text,
    p_agence_id uuid
)
returns void
language plpgsql
as $$
begin
    insert into public.users (id, email, nom_user, role, agence_id)
    values (p_user_id, p_email, p_nom, p_role, p_agence_id);
end;
$$;

grant execute on function public.create_user_simple to authenticated;

create_user_simple

create or replace function public.create_user_simple (
    p_email text,
    p_nom text,
    p_role text,
    p_agence_id uuid,
    p_password text
)
returns void
language plpgsql
security definer
as $$
declare
    current_role text;
begin
    select role into current_role
    from public.users
    where id = auth.uid();


    if current_role is null then
        raise exception 'Utilisateur non connecté';
    end if;

    if current_role != 'super_admin' then
        raise exception 'Rôle actuel de l''utilisateur : %', current_role;
    end if;


    insert into public.users (id, email, nom_user, role, agence_id)
    values (gen_random_uuid(), p_email, p_nom, p_role, p_agence_id);
end;
$$;

grant execute on function public.create_user_simple(text, text, text, uuid, text) to authenticated;

create or replace function public.create_user_simple(
    p_email text,
    p_nom text,
    p_role text,
    p_agence_id uuid,
    p_password text
)
returns void
language plpgsql
security definer
as $$
declare
    -- On ne se base plus sur auth.uid() pour éviter supabase_admin
    new_user_id uuid;
begin
    -- Vérifie que le rôle fourni est valide
    if p_role not in ('user', 'admin') then
        raise exception 'Rôle invalide : %', p_role;
    end if;

    -- 🔹 IMPORTANT : créer l'utilisateur dans auth.users via Service Role
    -- Ici on ne peut pas le faire directement depuis PL/pgSQL,
    -- donc on suppose que l'utilisateur est déjà créé côté Auth (frontend signUp)
    -- et que son ID est généré. On récupère l'ID via la clé frontend.
    
    -- Génère un nouvel UUID pour public.users
    new_user_id := gen_random_uuid();

    -- Créer l’utilisateur dans public.users
    insert into public.users (id, email, nom_user, role, agence_id)
    values (new_user_id, p_email, p_nom, p_role, p_agence_id);
end;
$$;

-- ⚠️ Grant sur la signature exacte
grant execute on function public.create_user_simple(text, text, text, uuid, text) to authenticated;

create table public.users (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  nom_user text not null,
  role text not null check (role in ('super_admin','admin','user')),
  agence_id uuid null references public.agence(id),
  created_at timestamptz default now()
);

create or replace function public.handle_new_auth_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.users (
    id,
    email,
    nom_user,
    role
  )
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'nom_user', 'Nouveau utilisateur'),
    'user' -- rôle par défaut
  );

  return new;
end;
$$;

create trigger on_auth_user_created
after insert on auth.users
for each row
execute procedure public.handle_new_auth_user();

alter table public.users enable row level security;

SELECT role AS current_user_role
FROM public.users
WHERE id = auth.uid();

raise exception 'Rôle actuel de l''utilisateur : %', current_user_role;

create or replace function public.get_current_user_id_role()
returns text
language plpgsql
security definer
as $$
declare
    user_id text;
    role_user text;
begin
    select id::text, role into user_id, role_user
    from public.users
    where id = auth.uid();

    if user_id is null then
        return 'Aucun utilisateur connecté';
    end if;

    return 'Utilisateur ID: ' || user_id || ', Rôle: ' || role_user;
end;
$$;

create or replace function public.get_current_user_role()
returns text
language plpgsql
security definer
as $$
declare
    role_user text;
begin
    select id,role into role_user
    from public.users
    where id = auth.uid();

    if role_user is null then
        return 'Aucun utilisateur connecté';
    end if;

    return role_user;
end;
$$; 

create or replace function public.get_current_user_role()
returns text
language plpgsql
security definer
as $$
declare
    user_info text;
begin
    select 'ID: ' || id::text || ', Role: ' || role
    into user_info
    from public.users
    where id = auth.uid();

    if user_info is null then
        return 'Aucun utilisateur connecté';
    end if;

    return user_info;
end;
$$;

create or replace function public.create_user_secure(
    p_email text,
    p_password text,
    p_nom_user text,
    p_role text,
    p_agence_id uuid
)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
    current_role text;
    new_user_id uuid;
begin

    -- 1️⃣ Vérifier utilisateur connecté
    if auth.uid() is null then
        return 'Utilisateur non connecté';
    end if;

    -- 2️⃣ Récupérer rôle du créateur
    select role into current_role
    from public.users
    where id = auth.uid();

    if current_role is null then
        return 'Rôle introuvable';
    end if;

    -------------------------------------------------
    -- 🔐 LOGIQUE D'AUTORISATION
    -------------------------------------------------

    if current_role = 'user' then
        return 'Accès refusé';
    end if;

    if current_role = 'admin' and p_role <> 'user' then
        return 'Un admin peut créer uniquement un user';
    end if;

    -------------------------------------------------
    -- 3️⃣ Création dans auth.users (service role requis)
    -------------------------------------------------

    new_user_id := gen_random_uuid();

    insert into auth.users (
        id,
        email,
        encrypted_password,
        email_confirmed_at,
        raw_user_meta_data
    )
    values (
        new_user_id,
        p_email,
        crypt(p_password, gen_salt('bf')),
        now(),
        jsonb_build_object('nom_user', p_nom_user)
    );

    -------------------------------------------------
    -- 4️⃣ Création dans public.users
    -------------------------------------------------

    insert into public.users (
        id,
        email,
        nom_user,
        role,
        agence_id
    )
    values (
        new_user_id,
        p_email,
        p_nom_user,
        p_role,
        p_agence_id
    );

    return 'Utilisateur créé avec succès';

end;
$$;
drop function assign_role_secure() cascade;


create or replace function public.create_user_secure(
    p_email text,
    p_password text,
    p_nom_user text,
    p_role text,
    p_agence_id uuid
)
returns text
language plpgsql
security definer
as $$
declare
    current_role text;
    new_user_id uuid;
begin
  
    select role into current_role
    from public.users
    where id = auth.uid();

    if current_role is null then
        return 'Utilisateur non connecté';
    end if;

    if current_role = 'user' then
        return 'Accès refusé';
    end if;

    if current_role = 'admin' and p_role <> 'user' then
        return 'Admin ne peut créer que user';
    end if;

    -- Création sécurisée
    new_user_id := gen_random_uuid();

    insert into auth.users (
        id, email, encrypted_password, email_confirmed_at, raw_user_meta_data
    )
    values (
        new_user_id, p_email, crypt(p_password, gen_salt('bf')), now(),
        jsonb_build_object('nom_user', p_nom_user)
    );

    insert into public.users (
        id, email, nom_user, role, agence_id
    )
    values (
        new_user_id, p_email, p_nom_user, p_role, p_agence_id
    );

    return 'Utilisateur créé avec succès';
end;
$$;

create or replace function public.assign_role_secure(
    p_new_user_id uuid,
    p_email text,
    p_nom_user text,
    p_role text,
    p_agence_id uuid
)
returns text
language plpgsql
security definer
as $$
declare
    current_role text;
begin
    -- 1️⃣ Récupérer le rôle de l'utilisateur connecté
    select role into current_role
    from public.users
    where id = auth.uid();

    if current_role is null then
        return 'Utilisateur non connecté';
    end if;

    -- 2️⃣ Vérifier les droits
    if current_role = 'user' then
        return 'Accès refusé : vous ne pouvez créer aucun utilisateur';
    elsif current_role = 'admin' and p_role <> 'user' then
        return 'Accès refusé : un admin ne peut créer que des users';
    end if;

    -- 3️⃣ Insérer dans public.users
    insert into public.users (
        id,
        email,
        nom_user,
        role,
        agence_id,
        created_at
    )
    values (
        p_new_user_id,
        p_email,
        p_nom_user,
        p_role,
        p_agence_id,
        now()
    );

    return 'Utilisateur créé avec succès';
end;
$$;

-- Fonction pour récupérer le rôle de l'utilisateur connecté
create or replace function public.get_current_user_role()
returns text
language plpgsql
security definer
as $$
declare
    current_role text;
begin
    select role into current_role
    from public.users
    where id = auth.uid();

    if current_role is null then
        return 'Utilisateur non connecté';
    end if;

    return current_role;
end;
$$;

create or replace function public.check_create_user_rights(p_role text)
returns text
language plpgsql
security definer
as $$
declare
    current_role text;
begin
    -- Récupérer le rôle de l'utilisateur connecté
    select role into current_role
    from public.users
    where id = auth.uid();

    if current_role is null then
        return 'Utilisateur non connecté';
    end if;

    -- Vérification des droits
    if current_role = 'user' then
        return 'Accès refusé : vous ne pouvez créer aucun utilisateur';
    elsif current_role = 'admin' and p_role <> 'user' then
        return 'Accès refusé : un admin ne peut créer que des users';
    end if;

    return 'ok';
end;
$$;

grant execute on function public.check_create_user_rights(text) to authenticated;