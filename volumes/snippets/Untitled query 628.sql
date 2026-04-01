-- ============================================================================
-- MIGRATION: Kiosk Login Feature
-- Veuillez exécuter ce script dans la console SQL de votre instance Supabase.
-- ============================================================================

-- 1. Création de la table de configuration spécifique aux agences
CREATE TABLE IF NOT EXISTS public.agence_settings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agence_id uuid NOT NULL UNIQUE,
    kiosk_password text, -- Sera stocké sous forme cryptée
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT agence_settings_pkey PRIMARY KEY (id),
    CONSTRAINT agence_settings_agence_id_fkey FOREIGN KEY (agence_id) REFERENCES public.agence(id) ON DELETE CASCADE
);

-- 2. Configuration RLS (Row Level Security)
ALTER TABLE public.agence_settings ENABLE ROW LEVEL SECURITY;

-- 2a. Lecture: Admin peut lire les configs de son agence, SuperAdmin peut lire tout
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies 
        WHERE tablename = 'agence_settings' AND policyname = 'agence_settings_select_policy'
    ) THEN
        CREATE POLICY agence_settings_select_policy ON public.agence_settings 
        FOR SELECT USING (
            ((( SELECT users.role FROM public.users WHERE (users.id = auth.uid())) = 'super_admin'::text) 
            OR (agence_id = ( SELECT users.agence_id FROM public.users WHERE (users.id = auth.uid()))))
        );
    END IF;
END $$;

-- 2b. Écriture directe interdite au niveau table, on passe par les RPC
-- (Les fonctions RPC ci-dessous fonctionnent en SECURITY DEFINER, elles contournent cela pour écrire les configurations, garantissant la sécurité).


-- 3. Fonction: update_kiosk_password
-- Permet à l'administrateur d'agence ou super-admin de mettre à jour le mot de passe
CREATE OR REPLACE FUNCTION public.update_kiosk_password(p_password TEXT, p_agence_id UUID DEFAULT NULL)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, auth
AS $$
DECLARE
    v_target_agence_id UUID;
    v_caller_role TEXT;
    v_caller_agence_id UUID;
BEGIN
    -- 1. Identifier l'appelant
    SELECT role, agence_id INTO v_caller_role, v_caller_agence_id
    FROM public.users WHERE id = auth.uid();

    IF v_caller_role IS NULL THEN
        RAISE EXCEPTION 'Utilisateur non autorisé';
    END IF;

    -- 2. Déterminer l'agence cible
    IF v_caller_role = 'super_admin' THEN
        -- Le super_admin peut spécifier l'agence
        v_target_agence_id := COALESCE(p_agence_id, v_caller_agence_id);
    ELSIF v_caller_role = 'admin' THEN
        -- L'admin modifie de force son agence
        IF p_agence_id IS NOT NULL AND p_agence_id != v_caller_agence_id THEN
            RAISE EXCEPTION 'Non autorisé: Vous ne pouvez modifier que votre agence.';
        END IF;
        v_target_agence_id := v_caller_agence_id;
    ELSE
         RAISE EXCEPTION 'Non autorisé: Niveau de privilège insuffisant';
    END IF;

    IF v_target_agence_id IS NULL THEN
         RAISE EXCEPTION 'Agence non spécifiée ou introuvable';
    END IF;

    -- 3. Insérer ou mettre à jour les settings
    INSERT INTO public.agence_settings (agence_id, kiosk_password, updated_at)
    VALUES (
        v_target_agence_id,
        CASE WHEN p_password IS NULL OR p_password = '' THEN NULL ELSE crypt(p_password, gen_salt('bf')) END,
        NOW()
    )
    ON CONFLICT (agence_id) DO UPDATE SET
        kiosk_password = CASE WHEN p_password IS NULL OR p_password = '' THEN NULL ELSE crypt(p_password, gen_salt('bf')) END,
        updated_at = NOW();

    RETURN TRUE;
END;
$$;


-- 4. Fonction: verify_kiosk_password
-- Invoquée par la borne pour valider l'accès
CREATE OR REPLACE FUNCTION public.verify_kiosk_password(p_agence_id UUID, p_password TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, auth
AS $$
DECLARE
    v_stored_hash TEXT;
BEGIN
    SELECT kiosk_password INTO v_stored_hash
    FROM public.agence_settings
    WHERE agence_id = p_agence_id;

    -- S'il n'y a pas de mot de passe configuré, la borne est accessible (comportement par défaut)
    IF v_stored_hash IS NULL THEN
        RETURN TRUE;
    END IF;

    -- Si la borne requiert un mot de passe et on n'en passe pas, erreur
    IF p_password IS NULL OR p_password = '' THEN
        RETURN FALSE;
    END IF;

    -- Comparaison du hash
    RETURN v_stored_hash = crypt(p_password, v_stored_hash);
END;
$$;

-- Note : Accordez l'exécution (GRANT) à tous les rôles pour la vérification
GRANT EXECUTE ON FUNCTION public.verify_kiosk_password(UUID, TEXT) TO public;
GRANT EXECUTE ON FUNCTION public.verify_kiosk_password(UUID, TEXT) TO anon;
GRANT EXECUTE ON FUNCTION public.verify_kiosk_password(UUID, TEXT) TO authenticated;

GRANT EXECUTE ON FUNCTION public.update_kiosk_password(TEXT, UUID) TO authenticated;

-- Forcer le rafraîchissement du cache des fonctions pour PostgREST
NOTIFY pgrst, 'reload schema';
