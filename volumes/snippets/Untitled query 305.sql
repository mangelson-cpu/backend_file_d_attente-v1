-- ============================================================
-- FIX : Accès Public pour le Kiosque
-- Autorise la lecture des services et affectations sans connexion
-- ============================================================

-- 1. Autoriser SELECT sur guichet_service pour tout le monde (anon)
DROP POLICY IF EXISTS "guichet_service_select_public_policy" ON public.guichet_service;
CREATE POLICY "guichet_service_select_public_policy"
  ON public.guichet_service
  FOR SELECT
  TO public
  USING (true);

-- 2. Autoriser SELECT sur service pour tout le monde (anon)
-- (On vérifie si la RLS est activée sur service)
ALTER TABLE public.service ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_select_public_policy" ON public.service;
CREATE POLICY "service_select_public_policy"
  ON public.service
  FOR SELECT
  TO public
  USING (true);

-- 3. Autoriser SELECT sur agence pour tout le monde (anon)
-- (Déjà potentiellement configuré, mais on s'assure pour le kiosque)
ALTER TABLE public.agence ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "agence_select_public_policy" ON public.agence;
CREATE POLICY "agence_select_public_policy"
  ON public.agence
  FOR SELECT
  TO public
  USING (true);
