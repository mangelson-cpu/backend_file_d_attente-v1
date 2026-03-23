-- ============================================================
-- SCRIPT DE CORRECTION DES DROITS (RLS) SUR LA TABLE AGENCE
-- Permet aux admins et users de voir leur propre agence
-- ============================================================

-- 1. Activer RLS si ce n'est pas déjà fait
ALTER TABLE public.agence ENABLE ROW LEVEL SECURITY;

-- 2. Supprimer l'ancienne politique restrictive
DROP POLICY IF EXISTS "agence_select_policy" ON public.agence;

-- 3. Nouvelle politique SELECT :
-- - super_admin voit TOUTES les agences
-- - admin et user voient uniquement LEUR agence
CREATE POLICY "agence_select_policy"
ON public.agence
FOR SELECT
USING (
  (SELECT role FROM public.users WHERE id = auth.uid()) = 'super_admin'
  OR 
  id = (SELECT agence_id FROM public.users WHERE id = auth.uid())
);

-- NOTE : Les politiques INSERT, UPDATE, DELETE restent réservées au super_admin
-- comme défini précédemment dans crud_agences.db
