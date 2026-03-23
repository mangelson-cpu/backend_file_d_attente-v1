-- ============================================================
-- TABLE : guichet_service
-- Mappe les guichets physiques aux services disponibles
-- ============================================================

CREATE TABLE IF NOT EXISTS public.guichet_service (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  nom_guichet TEXT NOT NULL, -- "Guichet 1", "Caisse 2", etc.
  service_id UUID NOT NULL REFERENCES public.service(id) ON DELETE CASCADE,
  agence_id UUID NOT NULL REFERENCES public.agence(id) ON DELETE CASCADE,
  user_id UUID REFERENCES public.users(id) ON DELETE SET NULL, -- L'agent assigné au guichet pour ce service
  created_at TIMESTAMPTZ DEFAULT now(),
  
  -- S'assurer qu'un même service avec le même agent n'est pas assigné deux fois au même guichet
  UNIQUE(nom_guichet, service_id, agence_id, user_id)
);

-- Activation RLS
ALTER TABLE public.guichet_service ENABLE ROW LEVEL SECURITY;

-- Politiques RLS
-- 1. SELECT : Tous les authentifiés de l'agence peuvent voir
CREATE POLICY "guichet_service_select_policy"
  ON public.guichet_service
  FOR SELECT
  USING (
    (SELECT role FROM public.users WHERE id = auth.uid()) = 'super_admin'
    OR agence_id = (SELECT agence_id FROM public.users WHERE id = auth.uid())
  );

-- 2. INSERT/DELETE : Réservé aux admins de l'agence et super_admin
CREATE POLICY "guichet_service_modify_policy"
  ON public.guichet_service
  FOR ALL
  USING (
    (SELECT role FROM public.users WHERE id = auth.uid()) = 'super_admin'
    OR (
      (SELECT role FROM public.users WHERE id = auth.uid()) = 'admin'
      AND agence_id = (SELECT agence_id FROM public.users WHERE id = auth.uid())
    )
  );
