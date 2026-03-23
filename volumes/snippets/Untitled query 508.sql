-- ============================================================
-- Fonction RPC sécurisée : create_user_secure
-- À exécuter dans le SQL Editor de Supabase (ou via migration)
-- ============================================================

-- 1. Activer l'extension pgcrypto si pas déjà fait
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 2. Supprimer l'ancienne fonction si elle existe
DROP FUNCTION IF EXISTS public.create_user_secure(TEXT, TEXT, TEXT, TEXT, UUID);

-- 3. Créer la fonction
CREATE OR REPLACE FUNCTION public.create_user_secure(
  p_email TEXT,
  p_password TEXT,
  p_nom_user TEXT,
  p_role TEXT,
  p_agence_id UUID DEFAULT NULL
)
RETURNS JSON
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth, extensions
AS $$
DECLARE
  v_caller_id UUID;
  v_caller_role TEXT;
  v_new_user_id UUID;
BEGIN
  -- 1. Vérifier que l'appelant est authentifié
  v_caller_id := auth.uid();
  IF v_caller_id IS NULL THEN
    RETURN json_build_object('success', false, 'message', 'Non authentifié');
  END IF;

  -- 2. Récupérer le rôle de l'appelant depuis public.users
  SELECT role INTO v_caller_role
  FROM public.users
  WHERE id = v_caller_id;

  IF v_caller_role IS NULL THEN
    RETURN json_build_object('success', false, 'message', 'Profil appelant introuvable');
  END IF;

  -- 3. Appliquer les règles métier de création
  --    user          → ne peut rien créer
  --    admin         → peut créer uniquement des "user"
  --    super_admin   → peut créer des "admin" et des "user"
  IF v_caller_role = 'user' THEN
    RETURN json_build_object('success', false, 'message', 'Les utilisateurs simples ne peuvent pas créer de comptes');
  END IF;

  IF v_caller_role = 'admin' AND p_role <> 'user' THEN
    RETURN json_build_object('success', false, 'message', 'Un admin ne peut créer que des utilisateurs de type "user"');
  END IF;

  IF v_caller_role = 'super_admin' AND p_role NOT IN ('admin', 'user') THEN
    RETURN json_build_object('success', false, 'message', 'Un super_admin ne peut créer que des admin ou des user');
  END IF;

  -- 4. Vérifier que l'email n'existe pas déjà
  IF EXISTS (SELECT 1 FROM auth.users WHERE email = p_email) THEN
    RETURN json_build_object('success', false, 'message', 'Cet email est déjà utilisé');
  END IF;

  -- 5. Valider le mot de passe (minimum 6 caractères)
  IF LENGTH(p_password) < 6 THEN
    RETURN json_build_object('success', false, 'message', 'Le mot de passe doit contenir au moins 6 caractères');
  END IF;

  -- 6. Générer un UUID pour le nouvel utilisateur
  v_new_user_id := gen_random_uuid();

  -- 7. Insérer dans auth.users (avec TOUS les champs requis par GoTrue)
  INSERT INTO auth.users (
    id,
    instance_id,
    email,
    encrypted_password,
    email_confirmed_at,
    confirmation_sent_at,
    confirmation_token,
    recovery_token,
    email_change_token_new,
    email_change,
    aud,
    role,
    raw_app_meta_data,
    raw_user_meta_data,
    is_super_admin,
    is_sso_user,
    created_at,
    updated_at
  ) VALUES (
    v_new_user_id,
    '00000000-0000-0000-0000-000000000000',
    p_email,
    crypt(p_password, gen_salt('bf')),
    NOW(),
    NOW(),
    '',        -- confirmation_token (vide car déjà confirmé)
    '',        -- recovery_token
    '',        -- email_change_token_new
    '',        -- email_change
    'authenticated',
    'authenticated',
    json_build_object(
      'provider', 'email',
      'providers', ARRAY['email']
    )::jsonb,
    json_build_object('nom_user', p_nom_user)::jsonb,
    false,     -- is_super_admin (géré par public.users)
    false,     -- is_sso_user
    NOW(),
    NOW()
  );

  -- 8. Créer l'identité email dans auth.identities
  --    (nécessaire pour que l'utilisateur puisse se connecter)
  INSERT INTO auth.identities (
    id,
    user_id,
    provider_id,
    identity_data,
    provider,
    last_sign_in_at,
    created_at,
    updated_at
  ) VALUES (
    v_new_user_id,
    v_new_user_id,
    p_email,
    json_build_object(
      'sub', v_new_user_id::text,
      'email', p_email,
      'email_verified', true,
      'provider', 'email'
    )::jsonb,
    'email',
    NOW(),
    NOW(),
    NOW()
  );

  -- 9. Insérer dans public.users
  INSERT INTO public.users (id, email, nom_user, role, agence_id, created_at)
  VALUES (v_new_user_id, p_email, p_nom_user, p_role, p_agence_id, NOW());

  -- 10. Retourner le succès
  RETURN json_build_object(
    'success', true,
    'message', 'Utilisateur créé avec succès',
    'user_id', v_new_user_id
  );

EXCEPTION WHEN OTHERS THEN
  RETURN json_build_object('success', false, 'message', 'Erreur serveur: ' || SQLERRM);
END;
$$;

-- 4. Sécuriser les permissions d'exécution
--    Seuls les utilisateurs authentifiés peuvent appeler cette fonction
REVOKE ALL ON FUNCTION public.create_user_secure(TEXT, TEXT, TEXT, TEXT, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.create_user_secure(TEXT, TEXT, TEXT, TEXT, UUID) FROM anon;
GRANT EXECUTE ON FUNCTION public.create_user_secure(TEXT, TEXT, TEXT, TEXT, UUID) TO authenticated;

-- 5. Recharger le cache de schéma PostgREST
--    (indispensable pour que la nouvelle fonction soit accessible via l'API)
NOTIFY pgrst, 'reload schema';
