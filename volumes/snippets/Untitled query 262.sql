-- ============================================================
-- FIX : Autoriser le kiosque (public) à lire les configurations
-- ============================================================

-- 1. Autoriser la lecture publique des affectations de guichets
-- Nécessaire pour que le kiosque puisse assigner un guichet au ticket
DROP POLICY IF EXISTS "guichet_service_select_public_policy" ON public.guichet_service;
CREATE POLICY "guichet_service_select_public_policy"
  ON public.guichet_service
  FOR SELECT
  TO public
  USING (true);

-- 2. S'assurer que les tickets peuvent être créés anonymement
DROP POLICY IF EXISTS "ticket_insert_public_policy" ON public.ticket;
CREATE POLICY "ticket_insert_public_policy"
  ON public.ticket
  FOR INSERT
  TO public
  WITH CHECK (true);

-- 3. S'assurer que les tickets peuvent être lus anonymement (pour le compteur de tickets du jour)
DROP POLICY IF EXISTS "ticket_select_public_policy" ON public.ticket;
CREATE POLICY "ticket_select_public_policy"
  ON public.ticket
  FOR SELECT
  TO public
  USING (true);

-- 4. Autoriser la lecture publique des services
DROP POLICY IF EXISTS "service_select_public_policy" ON public.service;
CREATE POLICY "service_select_public_policy"
  ON public.service
  FOR SELECT
  TO public
  USING (true);

-- 5. Vérifier que la colonne 'niveau' existe bien
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='ticket' AND column_name='niveau') THEN
        ALTER TABLE public.ticket RENAME COLUMN priority TO niveau;
    END IF;
EXCEPTION
    WHEN undefined_column THEN
        -- Si 'priority' n'existe pas non plus, on ajoute 'niveau'
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='ticket' AND column_name='niveau') THEN
            ALTER TABLE public.ticket ADD COLUMN niveau TEXT DEFAULT 'normal';
        END IF;
END $$;
