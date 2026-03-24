-- Créer la table auth.identities si elle n'existe pas encore
CREATE TABLE IF NOT EXISTS auth.identities (
    id text NOT NULL,
    user_id uuid NOT NULL,
    identity_data jsonb NOT NULL,
    provider text NOT NULL,
    last_sign_in_at timestamptz NULL,
    created_at timestamptz NULL,
    updated_at timestamptz NULL,
    provider_id text NULL,
    CONSTRAINT identities_pkey PRIMARY KEY (provider, id),
    CONSTRAINT identities_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE
);

-- Garantir les droits pour l'insertion
ALTER TABLE auth.identities OWNER TO supabase_auth_admin;

-- Définir une variable fixe pour l'ID de l'admin
\set new_id 'd9b9b9b9-b9b9-b9b9-b9b9-b9b9b9b9b9b9'

-- On force le search_path pour éviter les ambiguïtés entre auth.users et public.users
SET search_path = auth, public, extensions;

-- 1. Insérer dans auth.users
-- On utilise le nom de table qualifié pour être 100% sûr
INSERT INTO auth.users (
    id, instance_id, email, encrypted_password, email_confirmed_at,
    aud, role, raw_app_meta_data, raw_user_meta_data, is_super_admin,
    confirmation_token, recovery_token, email_change_token_new, email_change,
    is_sso_user, is_anonymous, created_at, updated_at
) VALUES (
    'd9b9b9b9-b9b9-b9b9-b9b9-b9b9b9b9b9b9',
    '00000000-0000-0000-0000-000000000000',
    'max@gmail.com',
    extensions.crypt('123456', extensions.gen_salt('bf')),
    NOW(),
    'authenticated',
    'authenticated',
    '{"provider": "email", "providers": ["email"]}'::jsonb,
    '{"nom_user": "RAKOTO Max"}'::jsonb,
    false,
    '', '', '', '', 
    false, false, NOW(), NOW()
) ON CONFLICT (id) DO NOTHING;

-- 2. Insérer l'identité
INSERT INTO auth.identities (
    id, user_id, provider_id, identity_data, provider, last_sign_in_at, created_at, updated_at
) VALUES (
    'd9b9b9b9-b9b9-b9b9-b9b9-b9b9b9b9b9b9',
    'd9b9b9b9-b9b9-b9b9-b9b9-b9b9b9b9b9b9',
    'max@gmail.com',
    '{"sub": "d9b9b9b9-b9b9-b9b9-b9b9-b9b9b9b9b9b9", "email": "max@gmail.com", "email_verified": true, "provider": "email"}'::jsonb,
    'email',
    NOW(),
    NOW(),
    NOW()
) ON CONFLICT (provider, id) DO NOTHING;

-- 3. Insérer dans public.users (explicitement via public.users)
INSERT INTO public.users (
    id, email, nom_user, role, agence_id, created_at
) VALUES (
    'd9b9b9b9-b9b9-b9b9-b9b9-b9b9b9b9b9b9',
    'max@gmail.com',
    'RAKOTO Max',
    'super_admin',
    null,
    NOW()
) ON CONFLICT (id) DO NOTHING;
