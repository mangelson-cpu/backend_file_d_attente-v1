-- ============================================================
-- TABLE : sous_service
-- Gère les sous-services associés à un service principal
-- ============================================================

CREATE TABLE IF NOT EXISTS public.sous_service (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  nom_sous_service TEXT NOT NULL,
  service_id UUID NOT NULL REFERENCES public.service(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Activation RLS
ALTER TABLE public.sous_service ENABLE ROW LEVEL SECURITY;

-- 1. SELECT : super_admin, admin, et les agents peuvent lire
CREATE POLICY "sous_service_select_policy"
  ON public.sous_service
  FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM public.users
      WHERE users.id = auth.uid()
      AND users.role IN ('super_admin', 'admin', 'agent')
    )
    OR true -- Pour autoriser la lecture public si besoin (kiosque)
  );

-- 2. INSERT : super_admin uniquement
CREATE POLICY "sous_service_insert_policy"
  ON public.sous_service
  FOR INSERT
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.users
      WHERE users.id = auth.uid()
      AND users.role = 'super_admin'
    )
  );

-- 3. UPDATE : super_admin uniquement
CREATE POLICY "sous_service_update_policy"
  ON public.sous_service
  FOR UPDATE
  USING (
    EXISTS (
      SELECT 1 FROM public.users
      WHERE users.id = auth.uid()
      AND users.role = 'super_admin'
    )
  );

-- 4. DELETE : super_admin uniquement
CREATE POLICY "sous_service_delete_policy"
  ON public.sous_service
  FOR DELETE
  USING (
    EXISTS (
      SELECT 1 FROM public.users
      WHERE users.id = auth.uid()
      AND users.role = 'super_admin'
    )
  );

-- ============================================================
-- MODIFICATION TABLE : ticket
-- Ajout de la référence sous_service_id
-- ============================================================

ALTER TABLE public.ticket 
ADD COLUMN IF NOT EXISTS sous_service_id UUID REFERENCES public.sous_service(id) ON DELETE SET NULL;
