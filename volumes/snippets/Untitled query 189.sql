create or replace function public.get_current_user_role()
returns text
language plpgsql
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

-- Permissions pour Supabase
grant execute on function public.get_current_user_role() to authenticated;

create or replace function public.assign_role_secure(
    p_new_user_id uuid,
    p_email text,
    p_nom_user text,
    p_role text,
    p_agence_id uuid
)
returns text
language plpgsql
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

    -- Insertion sécurisée dans public.users
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

grant execute on function public.assign_role_secure(uuid, text, text, text, uuid) to authenticated;

create or replace function public.check_create_user_rights(p_role text)
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

    if current_role = 'user' then
        return 'Accès refusé : vous ne pouvez créer aucun utilisateur';
    elsif current_role = 'admin' and p_role <> 'user' then
        return 'Accès refusé : un admin ne peut créer que des users';
    end if;

    return 'ok';
end;
$$;

grant execute on function public.check_create_user_rights(text) to authenticated;

select public.check_create_user_rights('user');