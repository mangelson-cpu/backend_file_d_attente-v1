-- Ajouter la colonne slug à la table agence
ALTER TABLE agence ADD COLUMN IF NOT EXISTS slug TEXT UNIQUE;

-- Mettre à jour les agences existantes avec un slug généré à partir de leur nom
-- (en minuscules, en remplaçant les espaces par des tirets)
UPDATE agence 
SET slug = LOWER(REPLACE(REPLACE(nom, ' ', '-'), '''', '')) 
WHERE slug IS NULL;

-- ============================================================
-- DROITS D'ACCÈS PUBLICS (RLS)
-- ============================================================

-- 1. Autoriser la lecture publique de la table agence (pour trouver l'ID via le slug)
DROP POLICY IF EXISTS "agence_public_select_policy" ON public.agence;
CREATE POLICY "agence_public_select_policy" ON public.agence
FOR SELECT TO public
USING (true);

-- 2. Autoriser la lecture publique des guichets/services (pour afficher les services sur la borne)
DROP POLICY IF EXISTS "guichet_service_public_select_policy" ON public.guichet_service;
CREATE POLICY "guichet_service_public_select_policy" ON public.guichet_service
FOR SELECT TO public
USING (true);

-- 3. S'assurer que les services eux-mêmes sont lisibles
ALTER TABLE public.service ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_public_select_policy" ON public.service;
CREATE POLICY "service_public_select_policy" ON public.service
FOR SELECT TO public
USING (true);
