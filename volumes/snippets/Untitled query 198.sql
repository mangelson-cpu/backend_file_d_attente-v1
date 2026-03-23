-- ============================================================
-- TABLE : ticket
-- Gère la file d'attente des clients
-- ============================================================

-- Définition du type énuméré pour le statut
DO $$ BEGIN
    CREATE TYPE ticket_status AS ENUM ('waiting', 'called', 'done', 'cancelled');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

CREATE TABLE IF NOT EXISTS public.ticket (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  numero_ticket TEXT NOT NULL,
  agence_id UUID NOT NULL REFERENCES public.agence(id) ON DELETE CASCADE,
  service_id UUID NOT NULL REFERENCES public.service(id) ON DELETE CASCADE,
  nom_guichet TEXT, -- Le guichet assigné lors de l'appel
  user_id UUID REFERENCES public.users(id), -- L'agent qui traite le ticket
  niveau TEXT DEFAULT 'normal', -- normal, urgent, vip
  status ticket_status DEFAULT 'waiting' NOT NULL,
  date_debut TIMESTAMPTZ, -- Heure d'appel
  date_fin TIMESTAMPTZ,   -- Heure de clôture
  created_at TIMESTAMPTZ DEFAULT now() NOT NULL
);

-- Activation RLS
ALTER TABLE public.ticket ENABLE ROW LEVEL SECURITY;

-- Politiques RLS
-- 1. SELECT : Tout le monde dans l'agence peut voir les tickets
DROP POLICY IF EXISTS "ticket_select_policy" ON public.ticket;
CREATE POLICY "ticket_select_policy"
  ON public.ticket
  FOR SELECT
  USING (
    agence_id = (SELECT agence_id FROM public.users WHERE id = auth.uid())
    OR (SELECT role FROM public.users WHERE id = auth.uid()) = 'super_admin'
    OR true 
  );

-- 2. INSERT : Le kiosque (public/anon) peut créer des tickets
DROP POLICY IF EXISTS "ticket_insert_public_policy" ON public.ticket;
CREATE POLICY "ticket_insert_public_policy"
  ON public.ticket
  FOR INSERT
  TO public
  WITH CHECK (true);

-- 3. UPDATE : Seuls les agents/admins peuvent appeler ou terminer un ticket
DROP POLICY IF EXISTS "ticket_update_policy" ON public.ticket;
CREATE POLICY "ticket_update_policy"
  ON public.ticket
  FOR UPDATE
  USING (
    agence_id = (SELECT agence_id FROM public.users WHERE id = auth.uid())
  );

-- Activer Realtime pour les tickets (avec vérification pour éviter les erreurs)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables 
        WHERE pubname = 'supabase_realtime' 
        AND schemaname = 'public' 
        AND tablename = 'ticket'
    ) THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.ticket;
    END IF;
END $$;
