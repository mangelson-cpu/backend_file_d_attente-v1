-- ============================================================
-- TABLE : active_guichets
-- Suit en temps réel quels guichets sont occupés par quels agents
-- ============================================================

CREATE TABLE IF NOT EXISTS public.active_guichets (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  nom_guichet TEXT NOT NULL,
  agence_id UUID NOT NULL REFERENCES public.agence(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  session_start TIMESTAMPTZ DEFAULT now(),
  
  -- Un guichet ne peut être occupé que par une seule personne à la fois
  UNIQUE(nom_guichet, agence_id),
  -- Un agent ne peut occuper qu'un seul guichet à la fois
  UNIQUE(user_id)
);

-- Activation RLS
ALTER TABLE public.active_guichets ENABLE ROW LEVEL SECURITY;

-- Politiques RLS
-- 1. SELECT : Tous les authentifiés peuvent voir (pour savoir ce qui est pris)
CREATE POLICY "active_guichets_select_policy"
  ON public.active_guichets
  FOR SELECT
  USING (true);

-- 2. INSERT : Un agent peut s'enregistrer sur un guichet
CREATE POLICY "active_guichets_insert_policy"
  ON public.active_guichets
  FOR INSERT
  WITH CHECK (auth.uid() = user_id);

-- 3. DELETE : Un agent peut libérer son guichet
CREATE POLICY "active_guichets_delete_policy"
  ON public.active_guichets
  FOR DELETE
  USING (auth.uid() = user_id OR (SELECT role FROM public.users WHERE id = auth.uid()) IN ('admin', 'super_admin'));

-- Activer Realtime pour surveiller les prises/libérations
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables 
        WHERE pubname = 'supabase_realtime' 
        AND schemaname = 'public' 
        AND tablename = 'active_guichets'
    ) THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.active_guichets;
    END IF;
END $$;
