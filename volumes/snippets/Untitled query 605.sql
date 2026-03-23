-- ==========================================
-- ENDPOINTS API POUR TABLETTE SATISFACTION
-- ==========================================
-- 1. Table des évaluations (Une seule note finale par ticket)
-- ==========================================

-- Pour garantir qu'il n'y ait qu'un SEUL et UNIQUE vote par ticket,
-- on supprime l'ancienne table si besoin, ou on s'assure que ticket_numero est UNIQUE.
CREATE TABLE IF NOT EXISTS public.evaluations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id VARCHAR NOT NULL,
    ticket_numero VARCHAR NOT NULL UNIQUE,  -- UNIQUE empêche les doublons pour le même ticket
    score INT NOT NULL CHECK (score IN (1, 2, 3)),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now())
);

-- Activer RLS pour protéger les données
ALTER TABLE public.evaluations ENABLE ROW LEVEL SECURITY;

-- Autoriser la tablette (qui utilisera l'anon key de Supabase) à insérer les notes
CREATE POLICY "Allow tablet to insert evaluations" 
ON public.evaluations 
FOR INSERT TO public 
WITH CHECK (true);

-- Permettre aux admins de lire les résultats
CREATE POLICY "Allow admins to read evaluations" 
ON public.evaluations 
FOR SELECT TO authenticated 
USING (true);

-- ==========================================
-- ACTIVER LE TEMPS RÉEL (Réactions Live)
-- ==========================================
-- Indispensable pour que React reçoive les notifications d'animation
ALTER PUBLICATION supabase_realtime ADD TABLE public.evaluations;


-- ==========================================
-- 2. Endpoint UNIQUE "Tout-en-un" (Récupère le ticket ET vote en une seule requête)
-- 
-- URL de la tablette: POST https://[PROJECT_ID].supabase.co/rest/v1/rpc/vote_satisfaction
-- Body: { "p_agence_id": "UUID", "p_nom_guichet": "Guichet X", "p_score": 1, "p_device_id": "VRAI_ID_DE_LA_TABLETTE" }
-- ==========================================
CREATE OR REPLACE FUNCTION vote_satisfaction(p_agence_id UUID, p_nom_guichet VARCHAR, p_score INT, p_device_id VARCHAR)
RETURNS JSON
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_ticket_numero VARCHAR;
BEGIN
    -- ÉTAPE A : Le backend cherche tout seul s'il y a un ticket en cours à ce guichet
    SELECT numero_ticket INTO v_ticket_numero
    FROM public.ticket
    WHERE agence_id = p_agence_id 
      AND nom_guichet = p_nom_guichet
      AND status = 'called' -- Statut du ticket actif
    ORDER BY created_at DESC
    LIMIT 1;

    -- Si le guichet est vide (aucun client sélectionné), on bloque le vote pour éviter les faux-positifs
    IF v_ticket_numero IS NULL THEN
        RETURN json_build_object('success', false, 'error', 'Aucun ticket n''est actuellement "En cours" ("called") sur ce guichet.');
    END IF;

    -- ÉTAPE B : Si un ticket a été trouvé, on enregistre ou met à jour le vote dans 'evaluations' (UPSERT)
    INSERT INTO public.evaluations (ticket_numero, device_id, score)
    VALUES (v_ticket_numero, p_device_id, p_score)
    ON CONFLICT (ticket_numero) 
    DO UPDATE SET 
        score = EXCLUDED.score,
        device_id = EXCLUDED.device_id,
        created_at = timezone('utc'::text, now());

    -- On renvoie un succès de la tablette, avec le numéro du ticket évalué pour info
    RETURN json_build_object('success', true, 'ticket_numero', v_ticket_numero, 'message', 'Vote pris en compte ou mis à jour avec succès.');
EXCEPTION WHEN OTHERS THEN
    -- En cas d'erreur serveur inattendue
    RETURN json_build_object('success', false, 'error', SQLERRM);
END;
$$;
