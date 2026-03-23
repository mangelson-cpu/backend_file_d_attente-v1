CREATE TABLE IF NOT EXISTS public.guichet (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  nom_guichet TEXT NOT NULL,
  appellation TEXT,
  agence_id UUID NOT NULL REFERENCES public.agence(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (nom_guichet, agence_id)
);

-- Si besoin, n'oubliez pas d'activer les politiques RLS (Row Level Security) 
-- pour permettre aux utilisateurs de lire/écrire sur cette table.
ALTER TABLE public.guichet ENABLE ROW LEVEL SECURITY;

-- Autoriser la lecture aux authentifiés
CREATE POLICY "Enable read access for authenticated users" ON public.guichet
AS PERMISSIVE FOR SELECT
TO authenticated
USING (true);

-- Autoriser l'insertion/modification aux admins
CREATE POLICY "Enable insert/update for authenticated users" ON public.guichet
AS PERMISSIVE FOR ALL
TO authenticated
USING (true)
WITH CHECK (true);
