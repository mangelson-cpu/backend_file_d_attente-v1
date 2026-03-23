
DO $$
DECLARE
    new_user_id uuid := gen_random_uuid();
    admin_email text := 'max@gmail.com';
    admin_password text := '123456';
    admin_name text := 'RAKOTO Max';
BEGIN
    -- Insérer dans auth.users
    INSERT INTO auth.users (
        id, instance_id, email, encrypted_password, email_confirmed_at,
        aud, role, raw_app_meta_data, raw_user_meta_data, is_super_admin,
        is_sso_user, created_at, updated_at
    ) VALUES (
        new_user_id,
        '00000000-0000-0000-0000-000000000000',
        admin_email,
        extensions.crypt(admin_password, extensions.gen_salt('bf')),
        NOW(),
        'authenticated',
        'authenticated',
        '{"provider": "email", "providers": ["email"]}'::jsonb,
        json_build_object('nom_user', admin_name)::jsonb,
        false,
        false,
        NOW(),
        NOW()
    );

    -- Insérer l'identité pour permettre la connexion GoTrue
    INSERT INTO auth.identities (
        id, user_id, provider_id, identity_data, provider, last_sign_in_at, created_at, updated_at
    ) VALUES (
        new_user_id,
        new_user_id,
        admin_email,
        json_build_object('sub', new_user_id::text, 'email', admin_email, 'email_verified', true, 'provider', 'email')::jsonb,
        'email',
        NOW(),
        NOW(),
        NOW()
    );

    -- Insérer dans la table public.users avec le rôle super_admin
    INSERT INTO public.users (
        id, email, nom_user, role, agence_id, created_at
    ) VALUES (
        new_user_id,
        admin_email,
        admin_name,
        'super_admin',
        null, 
        NOW()
    );
END
$$;
