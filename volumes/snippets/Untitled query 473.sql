create or replace function public.create_user_with_role(
    p_current_user_id uuid,
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
    new_user_id uuid;
begin
    select role into current_role
    from public.users
    where id = p_current_user_id;

    if current_role is null then
        raise exception 'Utilisateur non trouvé';
    end if;

    if current_role = 'super_admin' then
        null;
    elsif current_role = 'admin' then
        if p_role != 'user' then
            raise exception 'Un admin peut seulement créer un user';
        end if;
        if p_agence_id != (
            select agence_id from public.users where id = p_current_user_id
        ) then
            raise exception 'Un admin ne peut créer que dans sa propre agence';
        end if;
    else
        raise exception 'Permission refusée';
    end if;

    new_user_id := gen_random_uuid();

    -- INSERT dans public.users
    insert into public.users (id, email, nom_user, role, agence_id)
    values (new_user_id, p_email, p_nom, p_role, p_agence_id);
end;
$$;